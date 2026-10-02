// Implements spec/storage/interfaces.md §8.2 for PostgreSQL: AssignmentStore.
import type { Id, RoleAssignment, Timestamp } from '../../domain/index.js';
import { authError } from '../../errors/index.js';
import type { AssignmentStore, Page, PageReq } from '../../ports/index.js';
import { lockRoleHolders } from './locks.js';
import type { PostgresClient } from './postgresClient.js';
import type { TransactionRunner } from './unitOfWork.js';

interface AssignmentRow {
  subject_id: string;
  role_name: string;
  scope_type: string;
  scope_id: string;
  expires_at_ms: number | null;
  granted_by: string;
  granted_at_ms: number;
}

const COLUMNS =
  'subject_id, role_name, scope_type, scope_id, expires_at_ms, granted_by, granted_at_ms';

/** "Active at $now" (assignments.md §4.1): no expiry, or now < expiresAt. */
const ACTIVE = '(expires_at_ms IS NULL OR expires_at_ms > $2)';

/** The global scope is stored as ('', ''); see migrations/001_init.sql. */
function scopeColumns(scope: RoleAssignment['scope']): [string, string] {
  return scope === undefined || scope === null ? ['', ''] : [scope.type, scope.id];
}

function toAssignment(r: AssignmentRow): RoleAssignment {
  return {
    subjectId: r.subject_id,
    roleName: r.role_name,
    scope: r.scope_type === '' ? null : { type: r.scope_type, id: r.scope_id },
    expiresAt: r.expires_at_ms,
    grantedBy: r.granted_by,
    grantedAt: r.granted_at_ms,
  };
}

export class PostgresAssignmentStore implements AssignmentStore {
  constructor(
    private readonly pg: PostgresClient,
    private readonly tx: TransactionRunner,
  ) {}

  /**
   * §8.2.1: idempotent on (subject, role, scope). `INSERT ... ON CONFLICT DO NOTHING` is
   * concurrency-safe: of N identical concurrent assigns, exactly one inserts and the rest wait for
   * it and then do nothing, reporting `unchanged`. When an explicit, different `expiresAt` is
   * supplied for an existing row, only that field changes; `grantedBy`/`grantedAt` are preserved.
   */
  async assign(a: RoleAssignment, _now: Timestamp): Promise<'created' | 'unchanged' | 'updated'> {
    const [scopeType, scopeId] = scopeColumns(a.scope);
    return this.tx.atomic(async () => {
      await lockRoleHolders(this.pg, a.roleName);
      const inserted = await this.pg.query(
        `INSERT INTO aegis.role_assignments (${COLUMNS})
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (subject_id, role_name, scope_type, scope_id) DO NOTHING`,
        [
          a.subjectId,
          a.roleName,
          scopeType,
          scopeId,
          a.expiresAt ?? null,
          a.grantedBy,
          a.grantedAt,
        ],
      );
      if (inserted.rowCount === 1) return 'created' as const;
      if (a.expiresAt === undefined) return 'unchanged' as const;
      const updated = await this.pg.query(
        `UPDATE aegis.role_assignments SET expires_at_ms = $5
          WHERE subject_id = $1 AND role_name = $2 AND scope_type = $3 AND scope_id = $4
            AND expires_at_ms IS DISTINCT FROM $5`,
        [a.subjectId, a.roleName, scopeType, scopeId, a.expiresAt],
      );
      return updated.rowCount === 1 ? ('updated' as const) : ('unchanged' as const);
    });
  }

  /** §8.2: idempotent; true only when a row was removed. */
  async unassign(
    subjectId: Id,
    roleName: string,
    scope: RoleAssignment['scope'],
  ): Promise<boolean> {
    const [scopeType, scopeId] = scopeColumns(scope);
    return this.tx.atomic(async () => {
      await lockRoleHolders(this.pg, roleName);
      const r = await this.pg.query(
        `DELETE FROM aegis.role_assignments
          WHERE subject_id = $1 AND role_name = $2 AND scope_type = $3 AND scope_id = $4`,
        [subjectId, roleName, scopeType, scopeId],
      );
      return r.rowCount === 1;
    });
  }

  /** §8.2.3: the expiry filter is part of the query, evaluated against the caller's `now`. */
  async listActive(subjectId: Id, now: Timestamp): Promise<readonly RoleAssignment[]> {
    const r = await this.pg.query<AssignmentRow>(
      `SELECT ${COLUMNS} FROM aegis.role_assignments
        WHERE subject_id = $1 AND ${ACTIVE}
        ORDER BY role_name, scope_type, scope_id`,
      [subjectId, now],
    );
    return r.rows.map(toAssignment);
  }

  /**
   * Ordering subjectId ASC (byte-wise), keyset pagination. Inside a transaction this takes the
   * role-holder lock first, so a guard that counts holders and then removes one (last-superuser
   * protection, assignments.md §6.5) cannot interleave with another transaction doing the same.
   */
  async listSubjectsByRole(roleName: string, page: PageReq, now: Timestamp): Promise<Page<Id>> {
    if (!Number.isInteger(page.limit) || page.limit < 1 || page.limit > 1000) {
      throw authError('VALIDATION_FAILED', { details: { field: 'limit', rule: 'page.limit' } });
    }
    await lockRoleHolders(this.pg, roleName);
    const params: unknown[] = [roleName, now, page.limit + 1];
    let after = '';
    if (page.cursor !== undefined) {
      params.push(page.cursor);
      after = 'AND subject_id COLLATE "C" > $4';
    }
    const r = await this.pg.query<{ subject_id: string }>(
      `SELECT DISTINCT subject_id COLLATE "C" AS subject_id FROM aegis.role_assignments
        WHERE role_name = $1 AND ${ACTIVE} ${after}
        ORDER BY 1
        LIMIT $3`,
      params,
    );
    const items = r.rows.slice(0, page.limit).map((x) => x.subject_id);
    const last = items[items.length - 1];
    return r.rowCount > page.limit && last !== undefined ? { items, nextCursor: last } : { items };
  }

  async removeAllForSubject(subjectId: Id): Promise<number> {
    const r = await this.pg.query('DELETE FROM aegis.role_assignments WHERE subject_id = $1', [
      subjectId,
    ]);
    return r.rowCount;
  }
}
