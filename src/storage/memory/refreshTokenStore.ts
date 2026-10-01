// Implements spec/storage/interfaces.md §6 in memory: RefreshTokenStore with atomic consume/rotate.
import type {
  ConsumeResult,
  Id,
  NewRefreshToken,
  RefreshRevokedReason,
  RefreshTokenRecord,
  Timestamp,
} from '../../domain/index.js';
import { authError } from '../../errors/index.js';
import type { RefreshTokenStore } from '../../ports/index.js';
import type { MemoryDatabase } from './database.js';
import { revokeFamilyRows } from './sessionStore.js';

export class MemoryRefreshTokenStore implements RefreshTokenStore {
  constructor(private readonly db: MemoryDatabase) {}

  /** §6.7: no record may be minted for a revoked session. */
  private assertSessionUsable(sessionId: Id): void {
    const s = this.db.tables.sessions.get(sessionId);
    if (!s || s.revokedAt !== undefined) throw authError('PRECONDITION_FAILED');
  }

  private insertRow(record: NewRefreshToken): void {
    const t = this.db.tables;
    if (t.refreshTokenIndex.has(record.hash)) {
      throw authError('CONFLICT', { details: { field: 'hash' } });
    }
    const row: RefreshTokenRecord = { ...record, status: 'active' };
    t.refreshTokens.set(row.id, row);
    t.refreshTokenIndex.set(row.hash, row.id);
  }

  async insert(record: NewRefreshToken): Promise<void> {
    this.assertSessionUsable(record.sessionId);
    this.insertRow(record);
  }

  /**
   * §6.1-§6.3: one synchronous compare-and-set. Exactly one of N concurrent callers with the same
   * active hash receives `consumed` (INV-TOK-02); the rest receive `reused`.
   */
  async consume(hash: string, now: Timestamp): Promise<ConsumeResult> {
    const t = this.db.tables;
    const id = t.refreshTokenIndex.get(hash);
    if (!id) return { kind: 'unknown' };
    const row = t.refreshTokens.get(id);
    if (!row) return { kind: 'unknown' };
    if (row.status === 'revoked') return { kind: 'revoked', token: row };
    if (row.status === 'used') return { kind: 'reused', token: row };
    if (row.expiresAt <= now) return { kind: 'expired', token: row };
    const used: RefreshTokenRecord = { ...row, status: 'used', usedAt: now };
    t.refreshTokens.set(id, used);
    return { kind: 'consumed', token: used };
  }

  /**
   * §6.5: completes a rotation. Requires the parent to be `used` with no successor yet, and the
   * session to still be usable; otherwise PRECONDITION_FAILED and nothing is written.
   */
  async rotate(consumedTokenId: Id, successor: NewRefreshToken): Promise<void> {
    const t = this.db.tables;
    const parent = t.refreshTokens.get(consumedTokenId);
    if (!parent || parent.status !== 'used' || parent.successorId !== undefined) {
      throw authError('PRECONDITION_FAILED');
    }
    this.assertSessionUsable(successor.sessionId);
    this.insertRow(successor);
    t.refreshTokens.set(parent.id, { ...parent, successorId: successor.id });
  }

  /** §6 replaceActiveSuccessor: the reuse-grace replacement of tokens.md §3.5. */
  async replaceActiveSuccessor(
    oldSuccessorId: Id,
    replacement: NewRefreshToken,
    parentId: Id,
  ): Promise<'replaced' | 'not_active'> {
    const t = this.db.tables;
    const old = t.refreshTokens.get(oldSuccessorId);
    if (!old || old.status !== 'active') return 'not_active';
    const parent = t.refreshTokens.get(parentId);
    if (!parent) return 'not_active';
    this.assertSessionUsable(replacement.sessionId);
    t.refreshTokens.set(old.id, {
      ...old,
      status: 'revoked',
      revokedReason: 'superseded' satisfies RefreshRevokedReason,
    });
    this.insertRow(replacement);
    t.refreshTokens.set(parent.id, { ...parent, successorId: replacement.id });
    return 'replaced';
  }

  /** §6.6: idempotent; returns the number of records changed. */
  async revokeFamily(sessionId: Id, reason: RefreshRevokedReason): Promise<number> {
    const narrowed =
      reason === 'session_revoked' || reason === 'family_revoked' || reason === 'reuse_detected'
        ? reason
        : 'family_revoked';
    return revokeFamilyRows(this.db, sessionId, narrowed);
  }

  async getById(id: Id): Promise<RefreshTokenRecord | null> {
    return this.db.tables.refreshTokens.get(id) ?? null;
  }
}
