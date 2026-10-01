// Implements spec/auth/session.md §2: Session model and derived status.
import type { Id, Timestamp } from './types.js';

export type RevocationReason =
  | 'logout'
  | 'logout_all'
  | 'admin'
  | 'password_changed'
  | 'password_reset'
  | 'account_state'
  | 'credentials_invalidated'
  | 'refresh_reuse_detected'
  | 'evicted'
  | 'expired_cleanup';

/** Device metadata: informational only, never used for decisions (session.md §2.2.5). */
export interface DeviceInfo {
  readonly label?: string;
  readonly userAgent?: string;
  readonly ip?: string;
}

export interface Session {
  readonly id: Id;
  readonly userId: Id;
  readonly subjectType: string;
  readonly authMethod: string;
  readonly amr: readonly string[];
  readonly authenticatedAt: Timestamp;
  readonly createdAt: Timestamp;
  readonly lastSeenAt: Timestamp;
  readonly idleExpiresAt: Timestamp;
  readonly absoluteExpiresAt: Timestamp;
  readonly revokedAt?: Timestamp;
  readonly revokedReason?: RevocationReason;
  readonly device?: DeviceInfo;
  readonly securityVersionAtIssue: number;
}

export type NewSession = Session;

export type SessionStatus = 'active' | 'expired' | 'revoked';

/** Pure derived status (session.md §2.1). Expiry never depends on a background job. */
export function sessionStatus(s: Session, now: Timestamp): SessionStatus {
  if (s.revokedAt !== undefined) return 'revoked';
  if (now >= s.absoluteExpiresAt) return 'expired';
  if (now >= s.idleExpiresAt) return 'expired';
  return 'active';
}
