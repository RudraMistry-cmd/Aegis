// Implements spec/rbac/assignments.md §1: role assignment record.
import type { Id, Timestamp } from './types.js';

/** Assignment scope (assignments.md §3). Phase 1 supports only global (absent) scope. */
export interface AssignmentScope {
  readonly type: string;
  readonly id: Id;
}

export interface RoleAssignment {
  readonly subjectId: Id;
  readonly roleName: string;
  readonly scope?: AssignmentScope | null;
  /** `undefined` on input means "not supplied" (idempotent re-assign keeps the existing value). */
  readonly expiresAt?: Timestamp | null;
  readonly grantedBy: Id;
  readonly grantedAt: Timestamp;
}

/** An assignment is active iff it has no expiry or now < expiresAt (assignments.md §4.1). */
export function isAssignmentActive(a: Pick<RoleAssignment, 'expiresAt'>, now: Timestamp): boolean {
  return a.expiresAt === undefined || a.expiresAt === null || now < a.expiresAt;
}
