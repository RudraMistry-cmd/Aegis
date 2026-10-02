// Implements spec/storage/interfaces.md §6 for PostgreSQL: RefreshTokenStore, including the atomic
// single-use `consume` that replay protection rests on (INV-TOK-02).
import type {
  ConsumeResult,
  Id,
  NewRefreshToken,
  RefreshRevokedReason,
  RefreshTokenRecord,
  RefreshTokenStatus,
  Timestamp,
} from '../../domain/index.js';
import { authError } from '../../errors/index.js';
import type { RefreshTokenStore } from '../../ports/index.js';
import { lockUser } from './locks.js';
import { optional, type PostgresClient } from './postgresClient.js';
import type { TransactionRunner } from './unitOfWork.js';

interface TokenRow {
  id: string;
  hash: string;
  session_id: string;
  user_id: string;
  parent_id: string | null;
  successor_id: string | null;
  status: RefreshTokenStatus;
  revoked_reason: RefreshRevokedReason | null;
  created_at_ms: number;
  expires_at_ms: number;
  used_at_ms: number | null;
}

const COLUMNS = `id, hash, session_id, user_id, parent_id, successor_id, status, revoked_reason,
  created_at_ms, expires_at_ms, used_at_ms`;

function toRecord(r: TokenRow): RefreshTokenRecord {
  return {
    id: r.id,
    hash: r.hash,
    sessionId: r.session_id,
    userId: r.user_id,
    ...optional('parentId', r.parent_id),
    ...optional('successorId', r.successor_id),
    status: r.status,
    ...optional('revokedReason', r.revoked_reason),
    createdAt: r.created_at_ms,
    expiresAt: r.expires_at_ms,
    ...optional('usedAt', r.used_at_ms),
  };
}

export class PostgresRefreshTokenStore implements RefreshTokenStore {
  constructor(
    private readonly pg: PostgresClient,
    private readonly tx: TransactionRunner,
  ) {}

  /**
   * Locks the owner of a session, then re-reads the session (fresh under READ COMMITTED, because
   * this statement runs after the lock was granted). §6.7: no token may be minted for a revoked or
   * missing session — and while we hold the user lock, no revocation of it can commit.
   */
  private async lockUsableSession(sessionId: Id): Promise<void> {
    const owner = await this.pg.query<{ user_id: string }>(
      'SELECT user_id FROM aegis.sessions WHERE id = $1',
      [sessionId],
    );
    const userId = owner.rows[0]?.user_id;
    if (userId === undefined || !(await lockUser(this.pg, userId))) {
      throw authError('PRECONDITION_FAILED');
    }
    const s = await this.pg.query<{ revoked_at_ms: number | null }>(
      'SELECT revoked_at_ms FROM aegis.sessions WHERE id = $1',
      [sessionId],
    );
    if (!s.rows[0] || s.rows[0].revoked_at_ms !== null) throw authError('PRECONDITION_FAILED');
  }

  /** Locks the user that owns a token. Returns false when the token does not exist. */
  private async lockTokenOwner(tokenId: Id): Promise<boolean> {
    const owner = await this.pg.query<{ user_id: string }>(
      'SELECT user_id FROM aegis.refresh_tokens WHERE id = $1',
      [tokenId],
    );
    const userId = owner.rows[0]?.user_id;
    return userId !== undefined && (await lockUser(this.pg, userId));
  }

  /** Fresh check, to be called while holding the owner's lock: §6.7. */
  private async assertSessionUsable(sessionId: Id): Promise<void> {
    const s = await this.pg.query<{ revoked_at_ms: number | null }>(
      'SELECT revoked_at_ms FROM aegis.sessions WHERE id = $1',
      [sessionId],
    );
    if (!s.rows[0] || s.rows[0].revoked_at_ms !== null) throw authError('PRECONDITION_FAILED');
  }

  private async insertRow(record: NewRefreshToken): Promise<void> {
    await this.pg.query(
      `INSERT INTO aegis.refresh_tokens
         (id, hash, session_id, user_id, parent_id, status, created_at_ms, expires_at_ms)
       VALUES ($1, $2, $3, $4, $5, 'active', $6, $7)`,
      [
        record.id,
        record.hash,
        record.sessionId,
        record.userId,
        record.parentId ?? null,
        record.createdAt,
        record.expiresAt,
      ],
    );
  }

  async insert(record: NewRefreshToken): Promise<void> {
    await this.tx.atomic(async () => {
      await this.lockUsableSession(record.sessionId);
      await this.insertRow(record);
    });
  }

  /**
   * §6.1-§6.3. Exactly one of N concurrent callers presenting the same active token is told
   * `consumed`; every other caller is told `reused`.
   *
   *   1. Find the token's owner (plain read; the user id of a token never changes).
   *   2. Lock the owner's user row          — lock order step 1 (see locks.ts).
   *   3. SELECT the token row FOR UPDATE    — lock order step 3.
   *   4. Apply the precedence of §6.1 to that row and, only for an active unexpired token,
   *      UPDATE it to `used` in the same transaction.
   *
   * Why exactly one wins: step 3 grants the row lock to one transaction at a time. Under READ
   * COMMITTED, a waiter that acquires it re-reads the latest committed row version — it now sees
   * `used` and reports `reused`. Under SERIALIZABLE the waiter instead gets a serialization failure
   * (the row changed after its snapshot), is rolled back and re-run, and then sees `used`. Either
   * way no second transaction can observe `active` once the first has committed `used`, and the
   * partial unique index on active tokens per family is a second, independent guarantee.
   */
  async consume(hash: string, now: Timestamp): Promise<ConsumeResult> {
    return this.tx.atomic(async () => {
      const owner = await this.pg.query<{ user_id: string }>(
        'SELECT user_id FROM aegis.refresh_tokens WHERE hash = $1',
        [hash],
      );
      const userId = owner.rows[0]?.user_id;
      if (userId === undefined) return { kind: 'unknown' as const };
      await lockUser(this.pg, userId);

      const locked = await this.pg.query<TokenRow>(
        `SELECT ${COLUMNS} FROM aegis.refresh_tokens WHERE hash = $1 FOR UPDATE`,
        [hash],
      );
      const row = locked.rows[0];
      if (!row) return { kind: 'unknown' as const }; // deleted between steps 1 and 3
      if (row.status === 'revoked') return { kind: 'revoked' as const, token: toRecord(row) };
      if (row.status === 'used') return { kind: 'reused' as const, token: toRecord(row) };
      if (row.expires_at_ms <= now) return { kind: 'expired' as const, token: toRecord(row) };

      const updated = await this.pg.query<TokenRow>(
        `UPDATE aegis.refresh_tokens SET status = 'used', used_at_ms = $2
          WHERE id = $1 AND status = 'active'
          RETURNING ${COLUMNS}`,
        [row.id, now],
      );
      // We hold the row lock and just saw it active: anything else is an invariant breach.
      if (updated.rowCount !== 1) throw authError('INTERNAL');
      return { kind: 'consumed' as const, token: toRecord(updated.rows[0] as TokenRow) };
    });
  }

  /**
   * §6.5: completes a rotation. The parent must be `used` with no successor yet, and the session
   * must still be usable; otherwise PRECONDITION_FAILED and nothing is written.
   */
  async rotate(consumedTokenId: Id, successor: NewRefreshToken): Promise<void> {
    await this.tx.atomic(async () => {
      if (!(await this.lockTokenOwner(consumedTokenId))) throw authError('PRECONDITION_FAILED');
      const parent = await this.pg.query<TokenRow>(
        `SELECT ${COLUMNS} FROM aegis.refresh_tokens WHERE id = $1 FOR UPDATE`,
        [consumedTokenId],
      );
      const row = parent.rows[0];
      if (!row || row.status !== 'used' || row.successor_id !== null) {
        throw authError('PRECONDITION_FAILED');
      }
      // A successor always belongs to its parent's family, so the lock we hold covers it.
      if (successor.sessionId !== row.session_id) throw authError('PRECONDITION_FAILED');
      await this.assertSessionUsable(successor.sessionId);
      await this.insertRow(successor);
      await this.pg.query('UPDATE aegis.refresh_tokens SET successor_id = $2 WHERE id = $1', [
        row.id,
        successor.id,
      ]);
    });
  }

  /** tokens.md §3.5: supersedes an active successor with a replacement, atomically. */
  async replaceActiveSuccessor(
    oldSuccessorId: Id,
    replacement: NewRefreshToken,
    parentId: Id,
  ): Promise<'replaced' | 'not_active'> {
    return this.tx.atomic(async () => {
      if (!(await this.lockTokenOwner(oldSuccessorId))) return 'not_active' as const;
      const old = await this.pg.query<TokenRow>(
        `SELECT ${COLUMNS} FROM aegis.refresh_tokens WHERE id = $1 FOR UPDATE`,
        [oldSuccessorId],
      );
      if (!old.rows[0] || old.rows[0].status !== 'active') return 'not_active' as const;
      const parent = await this.pg.query<{ id: string }>(
        'SELECT id FROM aegis.refresh_tokens WHERE id = $1 FOR UPDATE',
        [parentId],
      );
      if (!parent.rows[0]) return 'not_active' as const;
      if (replacement.sessionId !== old.rows[0].session_id) throw authError('PRECONDITION_FAILED');
      await this.assertSessionUsable(replacement.sessionId);
      // Revoke first: the partial unique index allows one active token per family at a time.
      await this.pg.query(
        `UPDATE aegis.refresh_tokens SET status = 'revoked', revoked_reason = 'superseded'
          WHERE id = $1`,
        [oldSuccessorId],
      );
      await this.insertRow(replacement);
      await this.pg.query('UPDATE aegis.refresh_tokens SET successor_id = $2 WHERE id = $1', [
        parentId,
        replacement.id,
      ]);
      return 'replaced' as const;
    });
  }

  /** §6.6: idempotent; returns the number of records changed. */
  async revokeFamily(sessionId: Id, reason: RefreshRevokedReason): Promise<number> {
    const narrowed =
      reason === 'session_revoked' || reason === 'family_revoked' || reason === 'reuse_detected'
        ? reason
        : 'family_revoked';
    return this.tx.atomic(async () => {
      const owner = await this.pg.query<{ user_id: string }>(
        'SELECT user_id FROM aegis.sessions WHERE id = $1',
        [sessionId],
      );
      const userId = owner.rows[0]?.user_id;
      // Tokens reference their session, so a missing session has no tokens to revoke.
      if (userId === undefined) return 0;
      await lockUser(this.pg, userId);
      const r = await this.pg.query(
        `UPDATE aegis.refresh_tokens SET status = 'revoked', revoked_reason = $2
          WHERE session_id = $1 AND status = 'active'`,
        [sessionId, narrowed],
      );
      return r.rowCount;
    });
  }

  async getById(id: Id): Promise<RefreshTokenRecord | null> {
    const r = await this.pg.query<TokenRow>(
      `SELECT ${COLUMNS} FROM aegis.refresh_tokens WHERE id = $1`,
      [id],
    );
    return r.rows[0] ? toRecord(r.rows[0]) : null;
  }
}
