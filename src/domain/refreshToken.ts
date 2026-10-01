// Implements spec/auth/tokens.md §3.2: refresh token record (digest only; the raw secret is never stored).
import type { Id, Timestamp } from './types.js';

export type RefreshTokenStatus = 'active' | 'used' | 'revoked';
export type RefreshRevokedReason =
  'family_revoked' | 'superseded' | 'session_revoked' | 'reuse_detected' | 'expired_cleanup';

export interface RefreshTokenRecord {
  readonly id: Id;
  /** Hex digest of the token (tokens.md §1.5). */
  readonly hash: string;
  /** Equals the family id. */
  readonly sessionId: Id;
  readonly userId: Id;
  readonly parentId?: Id;
  readonly successorId?: Id;
  readonly status: RefreshTokenStatus;
  readonly revokedReason?: RefreshRevokedReason;
  readonly createdAt: Timestamp;
  readonly expiresAt: Timestamp;
  readonly usedAt?: Timestamp;
}

export type NewRefreshToken = Omit<
  RefreshTokenRecord,
  'status' | 'successorId' | 'usedAt' | 'revokedReason'
>;

/** Result of the atomic `consume` (storage/interfaces.md §6). */
export type ConsumeResult =
  | { readonly kind: 'consumed'; readonly token: RefreshTokenRecord }
  | { readonly kind: 'reused'; readonly token: RefreshTokenRecord }
  | { readonly kind: 'revoked'; readonly token: RefreshTokenRecord }
  | { readonly kind: 'expired'; readonly token: RefreshTokenRecord }
  | { readonly kind: 'unknown' };
