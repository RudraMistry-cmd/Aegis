// Implements spec/storage/interfaces.md §5 in memory: SessionStore with atomic limit enforcement.
import {
  sessionStatus,
  type Id,
  type NewSession,
  type RevocationReason,
  type Session,
  type Timestamp,
} from '../../domain/index.js';
import { authError } from '../../errors/index.js';
import type { CreateWithLimitResult, Page, PageReq, SessionStore } from '../../ports/index.js';
import type { MemoryDatabase } from './database.js';

/** Revokes every active refresh record of a family. Shared with MemoryRefreshTokenStore. */
function revokeFamilyRows(
  db: MemoryDatabase,
  sessionId: Id,
  reason: 'session_revoked' | 'family_revoked' | 'reuse_detected',
): number {
  let n = 0;
  for (const [k, row] of [...db.tables.refreshTokens]) {
    if (row.sessionId === sessionId && row.status === 'active') {
      db.tables.refreshTokens.set(k, { ...row, status: 'revoked', revokedReason: reason });
      n += 1;
    }
  }
  return n;
}

export class MemorySessionStore implements SessionStore {
  constructor(private readonly db: MemoryDatabase) {}

  /**
   * §5.1: count-check-evict-insert in one synchronous step, so the active count can never exceed
   * the limit under concurrent logins (INV-SESS-05). Evicted sessions' refresh tokens are revoked
   * in the same step.
   */
  async createWithLimit(
    session: NewSession,
    limit: number | null,
    policy: 'evict-oldest' | 'reject',
    now: Timestamp,
  ): Promise<CreateWithLimitResult> {
    const t = this.db.tables;
    if (t.sessions.has(session.id)) throw authError('CONFLICT', { details: { field: 'id' } });
    const evicted: Id[] = [];
    if (limit !== null) {
      const active = [...t.sessions.values()]
        .filter((s) => s.userId === session.userId && sessionStatus(s, now) === 'active')
        .sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
      if (active.length >= limit) {
        if (policy === 'reject') return { kind: 'limit_reached' };
        const overflow = active.length - limit + 1;
        for (const victim of active.slice(0, overflow)) {
          t.sessions.set(victim.id, {
            ...victim,
            revokedAt: now,
            revokedReason: 'evicted' satisfies RevocationReason,
          });
          revokeFamilyRows(this.db, victim.id, 'session_revoked');
          evicted.push(victim.id);
        }
      }
    }
    t.sessions.set(session.id, session);
    return { kind: 'created', session, evicted };
  }

  /** §5.6: returns revoked/expired records too; null only when absent. */
  async get(id: Id): Promise<Session | null> {
    return this.db.tables.sessions.get(id) ?? null;
  }

  /** Ordering: createdAt DESC, id DESC (§5 signature). Cursor is the index into that order. */
  async listActiveByUser(userId: Id, page: PageReq, now: Timestamp): Promise<Page<Session>> {
    const all = [...this.db.tables.sessions.values()]
      .filter((s) => s.userId === userId && sessionStatus(s, now) === 'active')
      .sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? 1 : a.id > b.id ? -1 : 0));
    const start = page.cursor ? Number(page.cursor) : 0;
    if (!Number.isInteger(start) || start < 0)
      throw authError('VALIDATION_FAILED', { details: { field: 'cursor' } });
    const items = all.slice(start, start + page.limit);
    const next = start + items.length;
    return next < all.length ? { items, nextCursor: String(next) } : { items };
  }

  /** §5.3: first call wins and returns true; later calls change nothing and return false. */
  async revoke(id: Id, reason: RevocationReason, now: Timestamp): Promise<boolean> {
    const t = this.db.tables;
    const s = t.sessions.get(id);
    if (!s) return false;
    if (s.revokedAt !== undefined) return false;
    t.sessions.set(id, { ...s, revokedAt: now, revokedReason: reason });
    // §5.4 / INV-TOK-05: the family is revoked in the same synchronous step as the session.
    revokeFamilyRows(this.db, id, 'session_revoked');
    return true;
  }

  /** §5.4: revokes every non-revoked session of the user (and its family) in one step. */
  async revokeAllForUser(
    userId: Id,
    except: Id | null,
    reason: RevocationReason,
    now: Timestamp,
  ): Promise<number> {
    const t = this.db.tables;
    let n = 0;
    for (const [k, s] of [...t.sessions]) {
      if (s.userId !== userId || k === except || s.revokedAt !== undefined) continue;
      t.sessions.set(k, { ...s, revokedAt: now, revokedReason: reason });
      revokeFamilyRows(this.db, k, 'session_revoked');
      n += 1;
    }
    return n;
  }

  /** §5.5: applies only to a non-revoked session and never shrinks or exceeds the bounds. */
  async touch(id: Id, now: Timestamp, newIdleExpiresAt: Timestamp): Promise<boolean> {
    const t = this.db.tables;
    const s = t.sessions.get(id);
    if (!s || s.revokedAt !== undefined) return false;
    if (newIdleExpiresAt < s.idleExpiresAt || newIdleExpiresAt > s.absoluteExpiresAt) return false;
    t.sessions.set(id, { ...s, idleExpiresAt: newIdleExpiresAt, lastSeenAt: now });
    return true;
  }

  async countActive(userId: Id, now: Timestamp): Promise<number> {
    return [...this.db.tables.sessions.values()].filter(
      (s) => s.userId === userId && sessionStatus(s, now) === 'active',
    ).length;
  }
}

export { revokeFamilyRows };
