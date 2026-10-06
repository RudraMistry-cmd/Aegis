// Implements spec/auth/tokens.md §1.3-§1.5: secret generation and digest-at-rest.
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { Random } from '../ports/index.js';

/** Minimum entropy for refresh, session and one-time tokens (tokens.md §3.1.2, §4.1). */
export const SECRET_BYTES = 32; // 256 bits

/**
 * Generates a high-entropy bearer secret, base64url encoded.
 * @param random CSPRNG port (never a test fake in production).
 */
export function generateSecret(random: Random, bytes: number = SECRET_BYTES): string {
  return Buffer.from(random.bytes(bytes)).toString('base64url');
}

/**
 * The server-side representation of a bearer secret (tokens.md §1.5): a SHA-256 digest.
 * A slow password hash is not required because the input is high-entropy.
 */
export function digest(secret: string): string {
  return createHash('sha256').update(secret, 'utf8').digest('hex');
}

/** Minimum length of the key behind identifier digests (256 bits). */
export const IDENTIFIER_DIGEST_KEY_BYTES = 32;

/**
 * The keyed digest of a (normalized) login identifier: HMAC-SHA256 under a server-side secret.
 *
 * Identifiers such as e-mail addresses are low-entropy, so a plain hash of one can be reversed with
 * a dictionary. Under a secret key that is not possible without the key. Used only for rate-limit
 * keys and the audit `identifierDigest`; bearer secrets keep the plain {@link digest}.
 */
export function identifierDigest(identifier: string, key: Uint8Array): string {
  return createHmac('sha256', key).update(identifier, 'utf8').digest('hex');
}

/** Constant-time comparison of two equal-length hex digests (tokens.md §1.4). */
export function digestEquals(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}
