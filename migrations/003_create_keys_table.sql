-- Aegis PostgreSQL schema, migration 003: durable JWT signing keys (spec/auth/tokens.md §6).
--
-- Lifecycle, enforced by the database itself (never reversed):
--   pending -> active -> retired,  or  pending -> retired
-- At most one key is active at any instant; a retired key is frozen; a kid is never reused.

-- Every kid ever created, never deleted from: a removed key's kid can never be issued again, so an
-- old token can never be re-validated by a different key that happens to share its kid.
CREATE TABLE aegis.signing_key_registry (
  kid              text           PRIMARY KEY CHECK (kid ~ '^[A-Za-z0-9_.-]{1,64}$'),
  registered_at_ms aegis.epoch_ms NOT NULL
);

CREATE TABLE aegis.signing_keys (
  kid              text           PRIMARY KEY REFERENCES aegis.signing_key_registry (kid),
  type             text           NOT NULL CHECK (type IN ('RSA', 'HMAC')),
  status           text           NOT NULL CHECK (status IN ('pending', 'active', 'retired')),
  created_at_ms    aegis.epoch_ms NOT NULL,
  activated_at_ms  aegis.epoch_ms,
  retired_at_ms    aegis.epoch_ms,
  -- RSA: the public JWK members {kty, n, e}, published by JWKS. HMAC: NULL — a secret is never public.
  public_material  jsonb,
  -- Sealed private material (src/auth/jwt/keySealing.ts): AES-256-GCM ciphertext bound to the kid
  -- ('AEK1' envelope). The PostgreSQL store refuses to start without a master key, so plaintext
  -- ('AEK0') never lands here from Aegis itself; the CHECK below makes that a database rule too.
  private_material bytea          NOT NULL,
  metadata         jsonb          NOT NULL DEFAULT '{}'::jsonb
                   CHECK (jsonb_typeof(metadata) = 'object'),

  CONSTRAINT signing_keys_private_sealed
    CHECK (substring(private_material FROM 1 FOR 4) = '\x41454b31'::bytea),   -- 'AEK1'

  -- The public column can never hold private material: exactly {kty:'RSA', n, e} for RSA keys.
  CONSTRAINT signing_keys_public_material CHECK (
    (type = 'HMAC' AND public_material IS NULL)
    OR (type = 'RSA'
        AND jsonb_typeof(public_material) = 'object'
        AND public_material ->> 'kty' = 'RSA'
        AND public_material ? 'n' AND public_material ? 'e'
        AND public_material - 'kty' - 'n' - 'e' = '{}'::jsonb)
  ),

  -- Timestamps consistent with the status.
  CONSTRAINT signing_keys_status_times CHECK (
    (status = 'pending' AND activated_at_ms IS NULL AND retired_at_ms IS NULL)
    OR (status = 'active' AND activated_at_ms IS NOT NULL AND retired_at_ms IS NULL)
    OR (status = 'retired' AND retired_at_ms IS NOT NULL)
  ),
  CONSTRAINT signing_keys_time_order CHECK (
    (activated_at_ms IS NULL OR activated_at_ms >= created_at_ms)
    AND (retired_at_ms IS NULL OR retired_at_ms >= coalesce(activated_at_ms, created_at_ms))
  )
);

-- At most ONE active key, whatever the application does: a unique index over a constant, restricted
-- to active rows, admits a single row.
CREATE UNIQUE INDEX signing_keys_one_active ON aegis.signing_keys ((true)) WHERE status = 'active';

-- Lifecycle transitions and immutability.
CREATE FUNCTION aegis.signing_keys_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status = 'retired' AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'aegis: retired signing key % is frozen', OLD.kid USING ERRCODE = 'AE030';
  END IF;
  IF NEW.status = 'pending' AND OLD.status <> 'pending' THEN
    RAISE EXCEPTION 'aegis: signing key % cannot return to pending', OLD.kid USING ERRCODE = 'AE031';
  END IF;
  IF NEW.kid <> OLD.kid OR NEW.type <> OLD.type OR NEW.created_at_ms <> OLD.created_at_ms
     OR NEW.public_material IS DISTINCT FROM OLD.public_material
     OR NEW.private_material <> OLD.private_material
     OR (OLD.activated_at_ms IS NOT NULL AND NEW.activated_at_ms IS DISTINCT FROM OLD.activated_at_ms) THEN
    RAISE EXCEPTION 'aegis: immutable signing-key field changed on %', OLD.kid USING ERRCODE = 'AE032';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER signing_keys_guard BEFORE UPDATE ON aegis.signing_keys
  FOR EACH ROW EXECUTE FUNCTION aegis.signing_keys_guard();

-- Listing / loading the keyring: by status.
CREATE INDEX signing_keys_status_idx ON aegis.signing_keys (status);
-- prune(): retired keys by retirement time.
CREATE INDEX signing_keys_retired_at_idx
  ON aegis.signing_keys (retired_at_ms) WHERE status = 'retired';
