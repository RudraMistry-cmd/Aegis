// Encryption at rest for private signing-key material (spec/auth/tokens.md §6.3). The single place
// where private key bytes are encrypted or decrypted; KeyStore adapters only ever see the envelope.
//
// ENVELOPES
//   "AEK1" | nonce(12) | tag(16) | ciphertext   AES-256-GCM under the master key, AAD = kid.
//   "AEK0" | plaintext                           no master key configured (local development only).
// The kid is bound as additional authenticated data, so swapping two rows' ciphertexts — or
// renaming a key — makes decryption fail instead of silently loading the wrong key.
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { configInvalid } from '../../errors/index.js';

const SEALED = Buffer.from('AEK1', 'ascii');
const PLAIN = Buffer.from('AEK0', 'ascii');
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const MASTER_KEY_BYTES = 32;

const aad = (kid: string): Buffer => Buffer.from(`aegis-signing-key:v1:${kid}`, 'utf8');

/**
 * Parses a master key from its environment-variable form: 64 hex characters, or base64/base64url of
 * exactly 32 bytes. Anything else is CONFIG_INVALID; the value never appears in the error.
 */
export function parseMasterKey(value: string, envVar: string): Buffer {
  const trimmed = value.trim();
  let bytes: Buffer | null = null;
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    bytes = Buffer.from(trimmed, 'hex');
  } else if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(trimmed)) {
    const decoded = Buffer.from(trimmed.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    if (decoded.length === MASTER_KEY_BYTES) bytes = decoded;
  }
  if (!bytes || bytes.length !== MASTER_KEY_BYTES || new Set(bytes).size < 8) {
    throw configInvalid([
      {
        path: envVar,
        rule: 'keys.master_key',
        message: 'master key must be 32 random bytes, as 64 hex characters or base64',
      },
    ]);
  }
  return bytes;
}

/** Seals private material for storage. With no master key, marks it plaintext (dev only). */
export function seal(kid: string, privateBytes: Buffer, masterKey: Buffer | null): Uint8Array {
  if (!masterKey) return Buffer.concat([PLAIN, privateBytes]);
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', masterKey, nonce);
  cipher.setAAD(aad(kid));
  const ciphertext = Buffer.concat([cipher.update(privateBytes), cipher.final()]);
  return Buffer.concat([SEALED, nonce, cipher.getAuthTag(), ciphertext]);
}

/** True when the envelope is encrypted (AEK1). */
export function isSealed(envelope: Uint8Array): boolean {
  return Buffer.from(envelope).subarray(0, 4).equals(SEALED);
}

/**
 * Opens an envelope. Any failure — wrong or missing master key, tampered bytes, a ciphertext moved to
 * another kid, an unknown format — is CONFIG_INVALID: a key that cannot be proven intact is not used.
 */
export function unseal(kid: string, envelope: Uint8Array, masterKey: Buffer | null): Buffer {
  const buf = Buffer.from(envelope);
  const fail = (rule: string, message: string): never => {
    throw configInvalid([{ path: `keys.${kid}`, rule, message }]);
  };
  const magic = buf.subarray(0, 4);
  if (magic.equals(PLAIN)) return buf.subarray(4);
  if (!magic.equals(SEALED)) return fail('keys.envelope', 'unknown private-key envelope format');
  if (!masterKey)
    return fail('keys.master_key_missing', 'key is encrypted but no master key is set');
  if (buf.length <= 4 + NONCE_BYTES + TAG_BYTES) return fail('keys.envelope', 'truncated envelope');
  const nonce = buf.subarray(4, 4 + NONCE_BYTES);
  const tag = buf.subarray(4 + NONCE_BYTES, 4 + NONCE_BYTES + TAG_BYTES);
  const ciphertext = buf.subarray(4 + NONCE_BYTES + TAG_BYTES);
  try {
    const decipher = createDecipheriv('aes-256-gcm', masterKey, nonce);
    decipher.setAAD(aad(kid));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    return fail('keys.decrypt', 'key could not be decrypted: wrong master key or tampered data');
  }
}
