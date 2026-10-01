// Implements spec/storage/interfaces.md §8.1-§8.2 in memory: AssignmentStore and RoleCatalogStore.
import {
  isAssignmentActive,
  type Id,
  type RoleAssignment,
  type Timestamp,
} from '../../domain/index.js';
import { authError } from '../../errors/index.js';
import type { AssignmentStore, Page, PageReq, RoleCatalogStore } from '../../ports/index.js';
import { assignmentKey, type MemoryDatabase } from './database.js';

export class MemoryAssignmentStore implements AssignmentStore {
  constructor(private readonly db: MemoryDatabase) {}

  /**
   * §8.2.1: identity is (subjectId, roleName, scope); idempotent.
   * `expiresAt === undefined` means "not supplied": the existing value is preserved
   * (assignments.md §1.2), as are `grantedBy` and `grantedAt`.
   */
  async assign(a: RoleAssignment, _now: Timestamp): Promise<'created' | 'unchanged' | 'updated'> {
    const t = this.db.tables;
    const key = assignmentKey(a.subjectId, a.roleName, a.scope);
    const existing = t.assignments.get(key);
    if (!existing) {
      t.assignments.set(key, { ...a, expiresAt: a.expiresAt ?? null });
      return 'created';
    }
    if (a.expiresAt === undefined || a.expiresAt === existing.expiresAt) return 'unchanged';
    t.assignments.set(key, { ...existing, expiresAt: a.expiresAt });
    return 'updated';
  }

  /** §8.2: idempotent; true only when a row was removed. */
  async unassign(
    subjectId: Id,
    roleName: string,
    scope: RoleAssignment['scope'],
  ): Promise<boolean> {
    return this.db.tables.assignments.delete(assignmentKey(subjectId, roleName, scope));
  }

  /** §8.2.3: the `now` filter is applied here, not by the caller after pagination. */
  async listActive(subjectId: Id, now: Timestamp): Promise<readonly RoleAssignment[]> {
    return [...this.db.tables.assignments.values()].filter(
      (a) => a.subjectId === subjectId && isAssignmentActive(a, now),
    );
  }

  /** Ordering: subjectId ASC (§8.2 signature). */
  async listSubjectsByRole(roleName: string, page: PageReq, now: Timestamp): Promise<Page<Id>> {
    const all = [...this.db.tables.assignments.values()]
      .filter((a) => a.roleName === roleName && isAssignmentActive(a, now))
      .map((a) => a.subjectId)
      .sort();
    const start = page.cursor ? Number(page.cursor) : 0;
    if (!Number.isInteger(start) || start < 0) {
      throw authError('VALIDATION_FAILED', { details: { field: 'cursor' } });
    }
    const items = all.slice(start, start + page.limit);
    const next = start + items.length;
    return next < all.length ? { items, nextCursor: String(next) } : { items };
  }

  async removeAllForSubject(subjectId: Id): Promise<number> {
    const t = this.db.tables;
    let n = 0;
    for (const [k, a] of [...t.assignments]) {
      if (a.subjectId === subjectId) {
        t.assignments.delete(k);
        n += 1;
      }
    }
    return n;
  }
}

/**
 * §8.1 RoleCatalogStore: a mirror for referential integrity only. Syncing cannot change what the
 * engine evaluates for a catalog role (roles.md §3.3) — the engine reads the immutable in-code
 * catalog, never this table.
 */
export class MemoryRoleCatalogStore implements RoleCatalogStore {
  constructor(private readonly db: MemoryDatabase) {}

  async sync(
    snapshot: { version: string; roles: readonly string[]; permissions: readonly string[] },
    _now: Timestamp,
  ): Promise<void> {
    // Idempotent: syncing the same catalog twice is a no-op (§8.1.1-§8.1.2).
    this.db.tables.catalogVersion = snapshot.version;
  }

  async getCatalogVersion(): Promise<string | null> {
    return this.db.tables.catalogVersion;
  }
}
