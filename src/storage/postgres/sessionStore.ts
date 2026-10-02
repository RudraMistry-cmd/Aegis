// Implements spec/storage/interfaces.md §5 for PostgreSQL: SessionStore, including the atomic
// session-limit enforcement of §5.1 and the revocation semantics of §5.3-§5.4.
import type {
  DeviceInfo,
  Id,
  NewSession,
  RevocationReason,
  Session,
  Timestamp,
} from '../../domain/index.js';
import { authError } from '../../errors/index.js';
import type { CreateWithLimitResult, Page, PageReq, SessionStore } from '../../ports/index.js';
import { lockUser } from './locks.js';
import { optional, type PostgresClient } from './postgresClient.js';
import type { TransactionRunner } from './unitOfWork.js';

interface SessionRow {
  id: string;
  user_id: string;
  subject_type: string;
  auth_method: string;
  amr: string[];
  authenticated_at_ms: number;
  created_at_ms: number;
  last_seen_at_ms: number;
  idle_expires_at_ms: number;
  absolute_expires_at_ms: number;
  revoked_at_ms: number | null;
  revoked_reason: RevocationReason | null;
  device: DeviceInfo | null;
  security_version_at_issue: number;
}

const COLUMNS = `id, user_id, subject_type, auth_method, amr, authenticated_at_ms, created_at_ms,
  last_seen_at_ms, idle_expires_at_ms, absolute_expires_at_ms, revoked_at_ms, revoked_reason, device,
  security_version_at_issue`;

/** "Active at $now" (session.md §2.1), as a predicate on a sessions row. */
const LIVE = `revoked_at_ms IS NULL AND idle_expires_at_ms > $2 AND absolute_expires_at_ms > $2`;

function toSession(r: SessionRow): Session {
  return {
    id: r.id,
    userId: r.user_id,
    subjectType: r.subject_type,
    authMethod: r.auth_method,
    amr: [...r.amr],
    authenticatedAt: r.authenticated_at_ms,
    createdAt: r.created_at_ms,
    lastSeenAt: r.last_seen_at_ms,
    idleExpiresAt: r.idle_expires_at_ms,
    absoluteExpiresAt: r.absolute_expires_at_ms,
    ...optional('revokedAt', r.revoked_at_ms),
    ...optional('revokedReason', r.revoked_reason),
    ...optional('device', r.device),
    securityVersionAtIssue: r.security_version_at_issue,
  };
}

/** Keyset cursor for (created_at_ms DESC, id DESC): stable under concurrent inserts. */
function encodeCursor(s: Session): string {
  return Buffer.from(JSON.stringify([s.createdAt, s.id]), 'utf8').toString('base64url');
}

function decodeCursor(cursor: string): [number, string] {
  try {
    const v = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as unknown;
    if (Array.isArray(v) && Number.isSafeInteger(v[0]) && typeof v[1] === 'string') {
      return [v[0] as number, v[1] as string];
    }
  } catch {
    // fall through
  }
  throw authError('VALIDATION_FAILED', { details: { field: 'cursor', rule: 'page.cursor' } });
}

function assertLimit(limit: number): void {
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000) {
    throw authError('VALIDATION_FAILED', { details: { field: 'limit', rule: 'page.limit' } });
  }
}

export class PostgresSessionStore implements SessionStore {
  constructor(
    private readonly pg: PostgresClient,
    private readonly tx: TransactionRunner,
  ) {}

  /**
   * §5.1: count, evict or reject, and insert — all while holding the user's row lock.
   *
   * Every createWithLimit for a user starts by locking that user's row, so concurrent logins for
   * the same user queue on it and run one at a time. Under READ COMMITTED each statement after the
   * lock sees every session committed by the logins ahead in the queue, so the count is never
   * stale and the limit is never exceeded (INV-SESS-05). Evicted sessions and their refresh tokens
   * are revoked in the same transaction (session.md §6.6).
   */
  async createWithLimit(
    session: NewSession,
    limit: number | null,
    policy: 'evict-oldest' | 'reject',
    now: Timestamp,
  ): Promise<CreateWithLimitResult> {
    return this.tx.atomic(async () => {
      if (!(await lockUser(this.pg, session.userId))) throw authError('NOT_FOUND');

      const taken = await this.pg.query('SELECT 1 FROM aegis.sessions WHERE id = $1', [session.id]);
      if (taken.rowCount > 0) throw authError('CONFLICT', { details: { field: 'id' } });

      const evicted: Id[] = [];
      if (limit !== null) {
        const live = await this.pg.query<{ id: string }>(
          `SELECT id FROM aegis.sessions
            WHERE user_id = $1 AND ${LIVE}
            ORDER BY created_at_ms, id COLLATE "C"`,
          [session.userId, now],
        );
        if (live.rowCount >= limit) {
          if (policy === 'reject') return { kind: 'limit_reached' as const };
          const overflow = live.rowCount - limit + 1;
          evicted.push(...live.rows.slice(0, overflow).map((r) => r.id));
          await this.pg.query(
            `UPDATE aegis.sessions SET revoked_at_ms = $2, revoked_reason = 'evicted'
              WHERE id = ANY($1::text[]) AND revoked_at_ms IS NULL`,
            [evicted, now],
          );
          await this.pg.query(
            `UPDATE aegis.refresh_tokens SET status = 'revoked', revoked_reason = 'session_revoked'
              WHERE session_id = ANY($1::text[]) AND status = 'active'`,
            [evicted],
          );
        }
      }

      const inserted = await this.pg.query<SessionRow>(
        `INSERT INTO aegis.sessions (${COLUMNS})
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
         RETURNING ${COLUMNS}`,
        [
          session.id,
          session.userId,
          session.subjectType,
          session.authMethod,
          [...session.amr],
          session.authenticatedAt,
          session.createdAt,
          session.lastSeenAt,
          session.idleExpiresAt,
          session.absoluteExpiresAt,
          session.revokedAt ?? null,
          session.revokedReason ?? null,
          session.device === undefined ? null : JSON.stringify(session.device),
          session.securityVersionAtIssue,
        ],
      );
      return {
        kind: 'created' as const,
        session: toSession(inserted.rows[0] as SessionRow),
        evicted,
      };
    });
  }

  /** §5.6: returns revoked and expired sessions too; null only when absent. */
  async get(id: Id): Promise<Session | null> {
    const r = await this.pg.query<SessionRow>(
      `SELECT ${COLUMNS} FROM aegis.sessions WHERE id = $1`,
      [id],
    );
    return r.rows[0] ? toSession(r.rows[0]) : null;
  }

  /** Ordering createdAt DESC, id DESC; keyset pagination (stable under concurrent inserts). */
  async listActiveByUser(userId: Id, page: PageReq, now: Timestamp): Promise<Page<Session>> {
    assertLimit(page.limit);
    const params: unknown[] = [userId, now, page.limit + 1];
    let after = '';
    if (page.cursor !== undefined) {
      const [createdAt, id] = decodeCursor(page.cursor);
      params.push(createdAt, id);
      after = `AND (created_at_ms < $4 OR (created_at_ms = $4 AND id COLLATE "C" < $5))`;
    }
    const r = await this.pg.query<SessionRow>(
      `SELECT ${COLUMNS} FROM aegis.sessions
        WHERE user_id = $1 AND ${LIVE} ${after}
        ORDER BY created_at_ms DESC, id COLLATE "C" DESC
        LIMIT $3`,
      params,
    );
    const items = r.rows.slice(0, page.limit).map(toSession);
    const last = items[items.length - 1];
    return r.rowCount > page.limit && last ? { items, nextCursor: encodeCursor(last) } : { items };
  }

  /**
   * §5.3: the first call revokes and returns true; later calls change nothing and return false.
   * The conditional UPDATE (`WHERE revoked_at_ms IS NULL`) is the compare-and-set: of two concurrent
   * revokes, the second waits for the first's row lock, re-evaluates the condition against the
   * committed row, matches nothing, and returns false — so the first reason wins and exactly one
   * caller audits it (INV-SESS-07). The family is revoked in the same transaction (INV-TOK-05).
   */
  async revoke(id: Id, reason: RevocationReason, now: Timestamp): Promise<boolean> {
    return this.tx.atomic(async () => {
      const owner = await this.pg.query<{ user_id: string }>(
        'SELECT user_id FROM aegis.sessions WHERE id = $1',
        [id],
      );
      const userId = owner.rows[0]?.user_id;
      if (userId === undefined) return false;
      await lockUser(this.pg, userId);
      const changed = await this.pg.query(
        `UPDATE aegis.sessions SET revoked_at_ms = $2, revoked_reason = $3
          WHERE id = $1 AND revoked_at_ms IS NULL`,
        [id, now, reason],
      );
      await this.pg.query(
        `UPDATE aegis.refresh_tokens SET status = 'revoked', revoked_reason = 'session_revoked'
          WHERE session_id = $1 AND status = 'active'`,
        [id],
      );
      return changed.rowCount === 1;
    });
  }

  /**
   * §5.4: revokes every non-revoked session of the user, and their families, under the user lock.
   * A concurrent createWithLimit for the same user holds the same lock, so a session is either
   * created before this runs (and revoked by it) or after it commits — never in a gap (INV-SESS-06).
   */
  async revokeAllForUser(
    userId: Id,
    except: Id | null,
    reason: RevocationReason,
    now: Timestamp,
  ): Promise<number> {
    return this.tx.atomic(async () => {
      if (!(await lockUser(this.pg, userId))) return 0;
      const revoked = await this.pg.query<{ id: string }>(
        `UPDATE aegis.sessions SET revoked_at_ms = $3, revoked_reason = $4
          WHERE user_id = $1 AND revoked_at_ms IS NULL AND id IS DISTINCT FROM $2
          RETURNING id`,
        [userId, except, now, reason],
      );
      const ids = revoked.rows.map((r) => r.id);
      if (ids.length > 0) {
        await this.pg.query(
          `UPDATE aegis.refresh_tokens SET status = 'revoked', revoked_reason = 'session_revoked'
            WHERE session_id = ANY($1::text[]) AND status = 'active'`,
          [ids],
        );
      }
      return ids.length;
    });
  }

  /**
   * §5.5: a single conditional UPDATE. It applies only to a session that is neither revoked nor
   * already expired at `now` (so a touch can never resurrect an expired session, INV-SESS-02), and
   * only when the new idle expiry neither shrinks nor passes the absolute expiry.
   */
  async touch(id: Id, now: Timestamp, newIdleExpiresAt: Timestamp): Promise<boolean> {
    const r = await this.pg.query(
      `UPDATE aegis.sessions SET idle_expires_at_ms = $3, last_seen_at_ms = $2
        WHERE id = $1 AND ${LIVE}
          AND $3 >= idle_expires_at_ms AND $3 <= absolute_expires_at_ms`,
      [id, now, newIdleExpiresAt],
    );
    return r.rowCount === 1;
  }

  async countActive(userId: Id, now: Timestamp): Promise<number> {
    const r = await this.pg.query<{ n: number }>(
      `SELECT count(*)::bigint AS n FROM aegis.sessions WHERE user_id = $1 AND ${LIVE}`,
      [userId, now],
    );
    return Number(r.rows[0]?.n ?? 0);
  }
}
