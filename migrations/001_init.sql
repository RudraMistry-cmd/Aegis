-- Aegis PostgreSQL schema, migration 001: tables, constraints and integrity triggers.
-- Implements the persistence contracts of spec/storage/interfaces.md for the PostgreSQL adapter.
--
-- Conventions
--   * Every instant is stored as epoch milliseconds UTC in a BIGINT column named *_at_ms.
--     The domain passes `now` from its injected Clock (spec/auth/principal.md §0, INV-TIME-01), so
--     no query ever calls now(); BIGINT keeps that value exact, with no float or time-zone rounding
--     at the expiry boundaries the conformance suite tests to the millisecond.
--   * Ids follow the Id grammar of spec/auth/principal.md §0 and are compared byte-wise.
--   * Every invariant that can be stated declaratively is a constraint or a trigger, so a defect in
--     application code fails loudly instead of silently corrupting security state.
--   * Custom error codes raised by the triggers use the class 'AE' and are mapped to INTERNAL by the
--     adapter (they indicate an attempted invariant breach, i.e. a bug).

CREATE SCHEMA IF NOT EXISTS aegis;

-- ---------------------------------------------------------------- domains

CREATE DOMAIN aegis.ident AS text
  CHECK (VALUE ~ '^[A-Za-z0-9_.:~-]{1,128}$');

CREATE DOMAIN aegis.epoch_ms AS bigint
  CHECK (VALUE >= 0);

-- ---------------------------------------------------------------- users (spec §2)

-- Every id ever issued, never deleted: a deleted user's id can never be reissued (INV-ID-01).
CREATE TABLE aegis.user_id_registry (
  id               aegis.ident PRIMARY KEY,
  registered_at_ms aegis.epoch_ms NOT NULL
);

CREATE TABLE aegis.users (
  id               aegis.ident    PRIMARY KEY REFERENCES aegis.user_id_registry (id),
  status           text           NOT NULL CHECK (status ~ '^[a-z][a-z0-9_]{0,31}$'),
  version          integer        NOT NULL DEFAULT 0 CHECK (version >= 0),
  security_version integer        NOT NULL DEFAULT 0 CHECK (security_version >= 0),
  created_at_ms    aegis.epoch_ms NOT NULL,
  updated_at_ms    aegis.epoch_ms NOT NULL,
  metadata         jsonb          NOT NULL DEFAULT '{}'::jsonb
                   CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE FUNCTION aegis.users_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id <> OLD.id OR NEW.created_at_ms <> OLD.created_at_ms THEN
    RAISE EXCEPTION 'aegis: user id and creation time are immutable' USING ERRCODE = 'AE010';
  END IF;
  -- securityVersion is monotonic (principal.md §3.2); version increments on every mutation (§3.1).
  IF NEW.security_version < OLD.security_version OR NEW.version < OLD.version THEN
    RAISE EXCEPTION 'aegis: user versions never decrease' USING ERRCODE = 'AE011';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER users_guard BEFORE UPDATE ON aegis.users
  FOR EACH ROW EXECUTE FUNCTION aegis.users_guard();

-- ---------------------------------------------------------------- identifiers (spec §3)

CREATE TABLE aegis.identifiers (
  id            aegis.ident    PRIMARY KEY,
  user_id       aegis.ident    NOT NULL REFERENCES aegis.users (id) ON DELETE CASCADE,
  type          text           NOT NULL CHECK (type ~ '^[a-z][a-z0-9_-]{0,31}$'),
  value         text           NOT NULL CHECK (char_length(value) BETWEEN 1 AND 320),
  normalized    text           NOT NULL CHECK (char_length(normalized) BETWEEN 1 AND 320),
  verified      boolean        NOT NULL,
  created_at_ms aegis.epoch_ms NOT NULL,
  -- §3.1 / INV-ID-02: enforced by the store, never by check-then-insert. Deterministic collations
  -- compare byte-wise for equality, so uniqueness is exact; normalization is the core's job.
  CONSTRAINT identifiers_type_normalized_key UNIQUE (type, normalized)
);

-- ---------------------------------------------------------------- credentials (spec §4)

CREATE TABLE aegis.credentials (
  id              aegis.ident    PRIMARY KEY,
  user_id         aegis.ident    NOT NULL REFERENCES aegis.users (id) ON DELETE CASCADE,
  type            text           NOT NULL CHECK (type ~ '^[a-z][a-z0-9_-]{0,31}$'),
  payload         text           NOT NULL,
  created_at_ms   aegis.epoch_ms NOT NULL,
  last_used_at_ms aegis.epoch_ms,
  -- §4.1 / INV-CRED-03: at most one credential per type; `put` is an atomic upsert on this key.
  CONSTRAINT credentials_user_type_key UNIQUE (user_id, type)
);

-- ---------------------------------------------------------------- sessions (spec §5, session.md)

CREATE TABLE aegis.sessions (
  id                        aegis.ident    PRIMARY KEY,
  user_id                   aegis.ident    NOT NULL REFERENCES aegis.users (id) ON DELETE CASCADE,
  subject_type              text           NOT NULL CHECK (subject_type ~ '^[a-z][a-z0-9_-]{0,31}$'),
  auth_method               text           NOT NULL CHECK (char_length(auth_method) BETWEEN 1 AND 64),
  amr                       text[]         NOT NULL,
  authenticated_at_ms       aegis.epoch_ms NOT NULL,
  created_at_ms             aegis.epoch_ms NOT NULL,
  last_seen_at_ms           aegis.epoch_ms NOT NULL,
  idle_expires_at_ms        aegis.epoch_ms NOT NULL,
  absolute_expires_at_ms    aegis.epoch_ms NOT NULL,
  revoked_at_ms             aegis.epoch_ms,
  revoked_reason            text,
  device                    jsonb CHECK (device IS NULL OR jsonb_typeof(device) = 'object'),
  security_version_at_issue integer        NOT NULL CHECK (security_version_at_issue >= 0),
  -- session.md §2.2.4: revokedAt and revokedReason are set together or not at all.
  CONSTRAINT sessions_revocation_pair CHECK ((revoked_at_ms IS NULL) = (revoked_reason IS NULL)),
  -- session.md §2.2.3: createdAt < idleExpiresAt <= absoluteExpiresAt.
  CONSTRAINT sessions_expiry_order CHECK (
    created_at_ms < idle_expires_at_ms AND idle_expires_at_ms <= absolute_expires_at_ms
  ),
  CONSTRAINT sessions_revoked_reason CHECK (revoked_reason IS NULL OR revoked_reason IN (
    'logout', 'logout_all', 'admin', 'password_changed', 'password_reset', 'account_state',
    'credentials_invalidated', 'refresh_reuse_detected', 'evicted', 'expired_cleanup'
  ))
);

CREATE FUNCTION aegis.sessions_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- INV-SESS-02: a revoked session is terminal. Nothing about it may change again: not its
  -- revocation (first reason wins), not its expiry, not its last-seen time.
  IF OLD.revoked_at_ms IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'aegis: revoked session % is terminal', OLD.id USING ERRCODE = 'AE001';
  END IF;
  -- INV-SESS-04: fields written once at creation.
  IF NEW.id <> OLD.id OR NEW.user_id <> OLD.user_id OR NEW.subject_type <> OLD.subject_type
     OR NEW.auth_method <> OLD.auth_method OR NEW.amr <> OLD.amr
     OR NEW.authenticated_at_ms <> OLD.authenticated_at_ms
     OR NEW.created_at_ms <> OLD.created_at_ms
     OR NEW.absolute_expires_at_ms <> OLD.absolute_expires_at_ms
     OR NEW.security_version_at_issue <> OLD.security_version_at_issue THEN
    RAISE EXCEPTION 'aegis: immutable session field changed on %', OLD.id USING ERRCODE = 'AE002';
  END IF;
  -- session.md §5.4: a touch never shortens the idle expiry.
  IF NEW.idle_expires_at_ms < OLD.idle_expires_at_ms THEN
    RAISE EXCEPTION 'aegis: idle expiry may not shrink on %', OLD.id USING ERRCODE = 'AE003';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER sessions_guard BEFORE UPDATE ON aegis.sessions
  FOR EACH ROW EXECUTE FUNCTION aegis.sessions_guard();

-- ---------------------------------------------------------------- refresh tokens (spec §6, tokens.md §3)

CREATE TABLE aegis.refresh_tokens (
  id             aegis.ident    PRIMARY KEY,
  -- tokens.md §1.5: only the SHA-256 digest of the secret is stored. Unique: the lookup key.
  hash           text           NOT NULL UNIQUE CHECK (hash ~ '^[0-9a-f]{64}$'),
  session_id     aegis.ident    NOT NULL REFERENCES aegis.sessions (id) ON DELETE CASCADE,
  user_id        aegis.ident    NOT NULL REFERENCES aegis.users (id) ON DELETE CASCADE,
  -- Lineage pointers within one family. Deliberately not foreign keys: a family is always deleted
  -- together (with its session), and a SET NULL cascade would have to update frozen revoked rows.
  parent_id      aegis.ident,
  successor_id   aegis.ident,
  status         text           NOT NULL CHECK (status IN ('active', 'used', 'revoked')),
  revoked_reason text CHECK (revoked_reason IS NULL OR revoked_reason IN (
    'family_revoked', 'superseded', 'session_revoked', 'reuse_detected', 'expired_cleanup'
  )),
  created_at_ms  aegis.epoch_ms NOT NULL,
  expires_at_ms  aegis.epoch_ms NOT NULL,
  used_at_ms     aegis.epoch_ms,
  CONSTRAINT refresh_tokens_used_has_time CHECK (status <> 'used' OR used_at_ms IS NOT NULL),
  CONSTRAINT refresh_tokens_revoked_has_reason CHECK (status <> 'revoked' OR revoked_reason IS NOT NULL),
  CONSTRAINT refresh_tokens_active_has_no_successor CHECK (status <> 'active' OR successor_id IS NULL)
);

-- tokens.md §3.2.2: at most one ACTIVE token per family at any instant. This is the database's own
-- guarantee that a single refresh can never fork a family into two live chains (INV-TOK-02).
CREATE UNIQUE INDEX refresh_tokens_one_active_per_family
  ON aegis.refresh_tokens (session_id) WHERE status = 'active';

CREATE FUNCTION aegis.refresh_tokens_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id <> OLD.id OR NEW.hash <> OLD.hash OR NEW.session_id <> OLD.session_id
     OR NEW.user_id <> OLD.user_id OR NEW.created_at_ms <> OLD.created_at_ms
     OR NEW.expires_at_ms <> OLD.expires_at_ms
     OR NEW.parent_id IS DISTINCT FROM OLD.parent_id THEN
    RAISE EXCEPTION 'aegis: immutable refresh-token field changed on %', OLD.id USING ERRCODE = 'AE004';
  END IF;
  -- tokens.md §3.2.1: active -> used, active -> revoked, used -> revoked. Nothing returns to active,
  -- and a revoked record is frozen.
  IF OLD.status = 'revoked' AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'aegis: revoked refresh token % is terminal', OLD.id USING ERRCODE = 'AE005';
  END IF;
  IF NEW.status = 'active' AND OLD.status <> 'active' THEN
    RAISE EXCEPTION 'aegis: refresh token % cannot return to active', OLD.id USING ERRCODE = 'AE006';
  END IF;
  IF OLD.used_at_ms IS NOT NULL AND NEW.used_at_ms IS DISTINCT FROM OLD.used_at_ms THEN
    RAISE EXCEPTION 'aegis: usedAt is write-once on %', OLD.id USING ERRCODE = 'AE007';
  END IF;
  -- The successor link only moves on a used parent (rotate sets it; the grace replacement of
  -- tokens.md §3.5 re-points it).
  IF NEW.successor_id IS DISTINCT FROM OLD.successor_id AND NEW.status <> 'used' THEN
    RAISE EXCEPTION 'aegis: successor may only be set on a used token (%)', OLD.id USING ERRCODE = 'AE008';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER refresh_tokens_guard BEFORE UPDATE ON aegis.refresh_tokens
  FOR EACH ROW EXECUTE FUNCTION aegis.refresh_tokens_guard();

-- ---------------------------------------------------------------- role catalog mirror (spec §8.1)

-- A mirror for referential integrity and administration only. The engine evaluates the immutable
-- in-code catalog and never reads these tables (roles.md §3.3), so there is deliberately no
-- foreign key from assignments to roles: an assignment may outlive its role, in which case it
-- contributes nothing (roles.md §5.2).
CREATE TABLE aegis.catalog_state (
  singleton        boolean        PRIMARY KEY DEFAULT true CHECK (singleton),
  version          text           NOT NULL,
  synced_at_ms     aegis.epoch_ms NOT NULL
);

CREATE TABLE aegis.roles (
  name text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9_-]{0,63}$')
);

CREATE TABLE aegis.permissions (
  name text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9_-]{0,47}:[a-z][a-z0-9_-]{0,47}$')
);

-- ---------------------------------------------------------------- role assignments (spec §8.2)

CREATE TABLE aegis.role_assignments (
  subject_id    aegis.ident    NOT NULL,
  role_name     text           NOT NULL CHECK (role_name ~ '^[a-z][a-z0-9_-]{0,63}$'),
  -- assignments.md §3: the empty string encodes "global". A real scope type must match the
  -- Segment grammar, so it can never be empty, and primary-key columns cannot be NULL.
  scope_type    text           NOT NULL DEFAULT '',
  scope_id      text           NOT NULL DEFAULT '',
  expires_at_ms aegis.epoch_ms,
  granted_by    text           NOT NULL CHECK (char_length(granted_by) BETWEEN 1 AND 128),
  granted_at_ms aegis.epoch_ms NOT NULL,
  -- §8.2.1: identity is (subject, role, scope); concurrent identical assigns collapse onto it.
  PRIMARY KEY (subject_id, role_name, scope_type, scope_id),
  CONSTRAINT role_assignments_scope_pair CHECK ((scope_type = '') = (scope_id = '')),
  CONSTRAINT role_assignments_scope_type CHECK (scope_type = '' OR scope_type ~ '^[a-z][a-z0-9_-]{0,31}$')
);

-- ---------------------------------------------------------------- audit (spec §10)

CREATE TABLE aegis.audit_events (
  seq           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  id            text           NOT NULL UNIQUE,
  type          text           NOT NULL,
  at_ms         aegis.epoch_ms NOT NULL,
  severity      text           NOT NULL CHECK (severity IN ('info', 'notice', 'warning', 'high')),
  outcome       text           NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
  reason        text,
  actor_id      text,
  actor_type    text,
  actor_session text,
  target_type   text,
  target_id     text,
  context       jsonb          NOT NULL DEFAULT '{}'::jsonb,
  details       jsonb          NOT NULL DEFAULT '{}'::jsonb
);

-- §10.1 / INV-AUD-02: append-only. The core has no operation to alter or delete an event; these
-- triggers make the table itself refuse it, whatever the caller.
CREATE FUNCTION aegis.audit_events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'aegis: audit events are append-only' USING ERRCODE = 'AE020';
END $$;

CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON aegis.audit_events
  FOR EACH ROW EXECUTE FUNCTION aegis.audit_events_append_only();

CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON aegis.audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION aegis.audit_events_append_only();
