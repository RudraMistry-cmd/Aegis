-- Aegis PostgreSQL schema, migration 002: secondary indexes.
--
-- Every hot query in src/storage/postgres/ is listed next to the index that serves it. Unique and
-- primary-key constraints from 001 already index: users(id), identifiers(type, normalized),
-- credentials(user_id, type), sessions(id), refresh_tokens(id), refresh_tokens(hash),
-- refresh_tokens(session_id) WHERE active, role_assignments(subject_id, role_name, scope).
--
-- `COLLATE "C"` makes id ordering byte-wise, so it matches the code-unit ordering of the in-memory
-- reference adapter and does not depend on the database's locale.

-- SessionStore.createWithLimit / countActive / listActiveByUser:
--   WHERE user_id = $1 AND revoked_at_ms IS NULL AND <unexpired at $now>
--   ORDER BY created_at_ms, id
-- Revoked rows are excluded by the predicate, so the index stays proportional to live sessions.
CREATE INDEX sessions_user_live_idx
  ON aegis.sessions (user_id, created_at_ms, id COLLATE "C")
  WHERE revoked_at_ms IS NULL;

-- Foreign-key support: ON DELETE CASCADE from users must not scan these tables.
CREATE INDEX sessions_user_idx        ON aegis.sessions (user_id);
CREATE INDEX identifiers_user_idx     ON aegis.identifiers (user_id);
CREATE INDEX refresh_tokens_user_idx  ON aegis.refresh_tokens (user_id);

-- RefreshTokenStore.revokeFamily (WHERE session_id = $1 AND status = 'active') is served by the
-- partial unique index of 001; this full index serves cascade deletes and family inspection.
CREATE INDEX refresh_tokens_session_idx ON aegis.refresh_tokens (session_id);

-- AssignmentStore.listSubjectsByRole / last-superuser counting:
--   WHERE role_name = $1 AND <unexpired> ORDER BY subject_id
CREATE INDEX role_assignments_role_idx
  ON aegis.role_assignments (role_name, subject_id COLLATE "C");

-- Housekeeping (PostgresStorage.housekeep): terminal sessions by time. Correctness never depends on
-- these deletions — expiry is always evaluated against `now` at read time — so they are for disk
-- usage only.
CREATE INDEX sessions_revoked_at_idx
  ON aegis.sessions (revoked_at_ms) WHERE revoked_at_ms IS NOT NULL;
CREATE INDEX sessions_expiry_idx
  ON aegis.sessions (least(idle_expires_at_ms, absolute_expires_at_ms)) WHERE revoked_at_ms IS NULL;

-- Audit queries: by time, by type over time, by target.
CREATE INDEX audit_events_at_idx      ON aegis.audit_events (at_ms);
CREATE INDEX audit_events_type_at_idx ON aegis.audit_events (type, at_ms);
CREATE INDEX audit_events_target_idx  ON aegis.audit_events (target_type, target_id);
