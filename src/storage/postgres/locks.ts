// Lock acquisition for the PostgreSQL adapter, in one global order so that no two transactions can
// wait on each other in a cycle.
//
// LOCK ORDER (every flow acquires a prefix of this sequence, never out of order):
//   1. users row                  SELECT ... FOR NO KEY UPDATE      the per-user mutex
//   2. sessions rows of that user UPDATE / SELECT ... FOR UPDATE
//   3. refresh_tokens rows        UPDATE / SELECT ... FOR UPDATE
// Every store operation that changes a session or a refresh token takes the owning user's row lock
// FIRST, even when it only needs one token row. Two transactions touching the same user therefore
// queue on step 1 and can never hold steps 2/3 in opposite orders. Operations on different users
// share no locks. No flow ever locks two users.
//
// The role-holder lock (an advisory transaction lock per role name) is a separate domain: the
// assignment flows take it and never take user/session/token locks, and the session/token flows
// never take it, so the two domains cannot form a cycle. Within the role domain, multiple roles are
// always locked in ascending name order (the catalog's sorted role list).
//
// FOR NO KEY UPDATE rather than FOR UPDATE: inserting a session or token takes FOR KEY SHARE on the
// user row for its foreign key, which NO KEY UPDATE does not block. The mutex therefore serializes
// the flows we care about without blocking unrelated foreign-key checks.
import { authError } from '../../errors/index.js';
import type { PostgresClient } from './postgresClient.js';

function assertInTransaction(pg: PostgresClient): void {
  // A row lock outside a transaction is released at the end of its own statement: useless, and a
  // sign that the caller forgot to wrap a multi-step operation in `atomic`.
  if (!pg.ambient()) throw authError('INTERNAL');
}

/**
 * Locks the user's row for the rest of the transaction. Returns false when the user does not
 * exist (nothing is locked then).
 */
export async function lockUser(pg: PostgresClient, userId: string): Promise<boolean> {
  assertInTransaction(pg);
  const r = await pg.query('SELECT 1 FROM aegis.users WHERE id = $1 FOR NO KEY UPDATE', [userId]);
  return r.rowCount === 1;
}

/** Locks the user's row for deletion (the strongest row lock). */
export async function lockUserForDelete(pg: PostgresClient, userId: string): Promise<boolean> {
  assertInTransaction(pg);
  const r = await pg.query('SELECT 1 FROM aegis.users WHERE id = $1 FOR UPDATE', [userId]);
  return r.rowCount === 1;
}

/**
 * Serializes, until the transaction ends, every transaction that reads or changes the holders of
 * `roleName`. This is what makes "count the superuser holders, then remove one" atomic across
 * concurrent transactions under READ COMMITTED (assignments.md §6.5, INV-AUTHZ-07) without a table
 * lock. Outside a transaction there is nothing to protect, so it is a no-op.
 */
export async function lockRoleHolders(pg: PostgresClient, roleName: string): Promise<void> {
  if (!pg.ambient()) return;
  await pg.query("SELECT pg_advisory_xact_lock(hashtextextended('aegis.role:' || $1, 0))", [
    roleName,
  ]);
}
