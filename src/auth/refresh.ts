// Implements spec/flows/refresh.md: refresh-token rotation, reuse detection and the optional grace.
import {
  findState,
  sessionStatus,
  type ConsumeResult,
  type Id,
  type NewRefreshToken,
  type Principal,
  type RefreshTokenRecord,
  type Session,
  type Timestamp,
  type User,
} from '../domain/index.js';
import type { StoreSet } from '../ports/index.js';
import { authError, isAuthError, toInfraError } from '../errors/index.js';
import { digest, generateSecret } from './digest.js';
import { emitAudit, type AuthContext } from './config.js';
import { clampIdle, type IssuedCredentials } from './issue.js';
import { buildPrincipal } from './resolve.js';
import type { RevocationService } from './revoke.js';

export interface RefreshInput {
  readonly refreshToken: string;
  readonly clientIp?: string;
  readonly requestId?: string;
}

export interface RefreshResult {
  readonly credentials: IssuedCredentials;
  readonly principal: Principal;
}

/** The maximum accepted refresh-token length (refresh.md §2 step 1). */
const MAX_REFRESH_TOKEN_LENGTH = 512;

/** Why a presented token that was genuinely consumed cannot be rotated (refresh.md §2 steps 5-8). */
type RejectReason =
  | 'session_not_active'
  | 'identity_mismatch'
  | 'user_missing'
  | 'can_refresh_false'
  | 'sv_mismatch'
  | 'expired_successor';

type Outcome =
  | { readonly kind: 'not_consumed'; readonly consume: ConsumeResult }
  | {
      readonly kind: 'rejected';
      readonly reason: RejectReason;
      readonly sessionId: Id;
      readonly status?: string;
    }
  | {
      readonly kind: 'rotated';
      readonly session: Session;
      readonly user: User;
      readonly secret: string;
      readonly expiresAt: Timestamp;
    };

export class RefreshService {
  constructor(
    private readonly ctx: AuthContext,
    private readonly revocation: RevocationService,
  ) {}

  /**
   * refresh.md §2: rotates a refresh token.
   *
   * The presented token is the only authenticator; an access token is never accepted in its place.
   * Every failure path returns TOKEN_INVALID except the two cases that prove possession of a
   * genuine token: an expired record (TOKEN_EXPIRED) and a restricted account (ACCOUNT_RESTRICTED).
   *
   * `consume` and `rotate` run in ONE unit of work. The spec allows them to be separate (§6.5), but
   * joining them means a concurrent loser's reuse-revocation cannot cancel the winner's rotation,
   * so exactly one of N concurrent callers receives credentials (conformance REF-03).
   */
  async refresh(input: RefreshInput): Promise<RefreshResult> {
    const { storage, clock } = this.ctx;
    const now = clock.now();

    // ---- Step 1: shape. No store call for malformed input (conformance REF-19).
    const presented = input?.refreshToken;
    if (
      typeof presented !== 'string' ||
      presented.length === 0 ||
      presented.length > MAX_REFRESH_TOKEN_LENGTH
    ) {
      throw authError('TOKEN_INVALID');
    }

    // ---- Step 3: digest. The raw token is not retained.
    const hash = digest(presented);
    // The successor secret is generated outside the unit so a retry cannot change it.
    const secret = generateSecret(this.ctx.random);

    let outcome: Outcome;
    try {
      outcome = await storage.uow.run((tx) => this.runRotation(tx, hash, secret, now));
    } catch (e) {
      throw toInfraError(e);
    }

    if (outcome.kind === 'rotated') {
      // ---- Steps 10-11
      return this.completeRotation(outcome.session, outcome.user, outcome, now);
    }
    if (outcome.kind === 'rejected') return this.reportRejection(outcome, now);
    return this.reportNotConsumed(outcome.consume, now);
  }

  /**
   * refresh.md §2 steps 4-9, inside one transaction. This function never throws: it returns a
   * verdict, so a rejection does not roll back the revocations it performed.
   */
  private async runRotation(
    tx: StoreSet,
    hash: string,
    secret: string,
    now: Timestamp,
  ): Promise<Outcome> {
    const { config } = this.ctx;

    // ---- Step 4: atomic consume
    const consumed = await tx.refreshTokens.consume(hash, now);
    if (consumed.kind !== 'consumed') return { kind: 'not_consumed', consume: consumed };
    const token = consumed.token;

    // ---- Step 5: session check
    const session = await tx.sessions.get(token.sessionId);
    if (!session || sessionStatus(session, now) !== 'active') {
      await tx.refreshTokens.revokeFamily(token.sessionId, 'session_revoked');
      return { kind: 'rejected', reason: 'session_not_active', sessionId: token.sessionId };
    }
    if (session.userId !== token.userId) {
      // Corruption: revoke outright (§2 step 5).
      await tx.sessions.revoke(session.id, 'admin', now);
      await tx.refreshTokens.revokeFamily(session.id, 'session_revoked');
      return { kind: 'rejected', reason: 'identity_mismatch', sessionId: session.id };
    }

    // ---- Step 6: account check
    const user = await tx.users.getById(session.userId);
    if (!user) {
      await tx.sessions.revoke(session.id, 'admin', now);
      await tx.refreshTokens.revokeFamily(session.id, 'session_revoked');
      return { kind: 'rejected', reason: 'user_missing', sessionId: session.id };
    }
    const state = findState(config.accountStates, user.status);
    if (!state || !state.canRefresh) {
      await tx.sessions.revoke(session.id, 'account_state', now);
      await tx.refreshTokens.revokeFamily(session.id, 'session_revoked');
      await tx.users.bumpSecurityVersion(user.id, now);
      return {
        kind: 'rejected',
        reason: 'can_refresh_false',
        sessionId: session.id,
        status: user.status,
      };
    }

    // ---- Step 7: security-version check
    if (user.securityVersion !== session.securityVersionAtIssue) {
      await tx.sessions.revoke(session.id, 'credentials_invalidated', now);
      await tx.refreshTokens.revokeFamily(session.id, 'session_revoked');
      return { kind: 'rejected', reason: 'sv_mismatch', sessionId: session.id };
    }

    // ---- Step 8: mint the successor, never outliving the session
    const expiresAt = clampIdle(now + config.tokens.refreshIdleTtlMs, session.absoluteExpiresAt);
    if (expiresAt <= now) {
      return { kind: 'rejected', reason: 'expired_successor', sessionId: session.id };
    }
    const record: NewRefreshToken = {
      id: this.ctx.ids.newId(),
      hash: digest(secret),
      sessionId: session.id,
      userId: session.userId,
      parentId: token.id,
      createdAt: now,
      expiresAt,
    };

    // ---- Step 9: rotate and slide the idle expiry
    await tx.refreshTokens.rotate(token.id, record);
    await tx.sessions.touch(
      session.id,
      now,
      clampIdle(now + config.sessions.idleTtlMs, session.absoluteExpiresAt),
    );
    return { kind: 'rotated', session, user, secret, expiresAt };
  }

  /** refresh.md §2 steps 4a-4d: the token was not consumable. */
  private async reportNotConsumed(consume: ConsumeResult, now: Timestamp): Promise<RefreshResult> {
    switch (consume.kind) {
      case 'unknown':
        await this.auditRejected('unknown', now);
        throw authError('TOKEN_INVALID');
      case 'expired':
        // §2 step 4b: the caller possesses a genuine secret, so expiry may be reported.
        await this.auditRejected('expired', now);
        throw authError('TOKEN_EXPIRED');
      case 'revoked': {
        if (consume.token.revokedReason === 'superseded') {
          // §2 step 4c: a benign race; do not escalate.
          await emitAudit(
            this.ctx,
            {
              type: 'refresh.superseded_presented',
              outcome: 'denied',
              reason: 'superseded',
              target: { type: 'session', id: consume.token.sessionId },
            },
            now,
          );
        } else {
          await this.auditRejected('revoked', now);
          await this.ctx.storage.refreshTokens
            .revokeFamily(consume.token.sessionId, 'family_revoked')
            .catch(() => 0);
        }
        throw authError('TOKEN_INVALID');
      }
      case 'reused':
        return this.handleReuse(consume.token, now);
      case 'consumed':
        // Unreachable: the caller handles `consumed`.
        throw authError('INTERNAL');
    }
  }

  /** Emits the audit event for a rejected rotation and raises the mapped error (errors.md §3). */
  private async reportRejection(
    outcome: Extract<Outcome, { kind: 'rejected' }>,
    now: Timestamp,
  ): Promise<never> {
    const { reason, sessionId, status } = outcome;
    if (reason === 'identity_mismatch') {
      await emitAudit(
        this.ctx,
        {
          type: 'refresh.integrity_failure',
          severity: 'high',
          outcome: 'denied',
          reason: 'identity_mismatch',
          target: { type: 'session', id: sessionId },
        },
        now,
      );
      throw authError('TOKEN_INVALID');
    }
    if (reason === 'can_refresh_false') {
      await emitAudit(
        this.ctx,
        {
          type: 'auth.rejected',
          outcome: 'denied',
          reason,
          target: { type: 'session', id: sessionId },
        },
        now,
      );
      throw authError('ACCOUNT_RESTRICTED', {
        ...(this.ctx.config.revealRestrictedState && status !== undefined
          ? { details: { state: status } }
          : {}),
      });
    }
    await emitAudit(
      this.ctx,
      {
        type: 'auth.rejected',
        severity: reason === 'sv_mismatch' ? 'high' : 'info',
        outcome: 'denied',
        reason,
        target: { type: 'session', id: sessionId },
      },
      now,
    );
    if (reason === 'expired_successor') throw authError('TOKEN_EXPIRED');
    throw authError('TOKEN_INVALID');
  }

  /**
   * refresh.md §3: the reuse procedure. Outside the grace window this revokes the whole family and
   * the session, and reports TOKEN_INVALID with no hint that reuse was detected (INV-TOK-03).
   */
  private async handleReuse(token: RefreshTokenRecord, now: Timestamp): Promise<RefreshResult> {
    const grace = this.ctx.config.tokens.reuseGraceMs;
    const withinGrace = grace > 0 && token.usedAt !== undefined && now - token.usedAt <= grace;

    if (withinGrace && token.successorId === undefined) {
      // §3.1.1: the winner has not finished rotating. Retryable, no revocation.
      await this.auditRejected('in_flight', now);
      throw authError('TOKEN_INVALID', { retryable: true });
    }

    if (withinGrace && token.successorId !== undefined) {
      const replaced = await this.tryGraceReplacement(token, token.successorId, now);
      if (replaced) return replaced;
    }

    // §3.2-§3.4: revoke the family and the session, alert, respond TOKEN_INVALID.
    await this.revocation.terminateSession(token.sessionId, 'refresh_reuse_detected');
    await emitAudit(
      this.ctx,
      {
        type: 'refresh.reuse_detected',
        severity: 'high',
        outcome: 'denied',
        reason: 'reuse_detected',
        target: { type: 'session', id: token.sessionId },
        // §10.4: ids only, never the token value.
        details: { userId: token.userId, tokenId: token.id },
      },
      now,
    );
    throw authError('TOKEN_INVALID');
  }

  /**
   * tokens.md §3.5 / refresh.md §3.1.2: within the grace window the previous successor is replaced
   * rather than replayed (only digests are stored, so the original response cannot be reproduced).
   *
   * Returns the completed rotation, or null when the grace does not apply and the caller must fall
   * through to the revocation path.
   */
  private async tryGraceReplacement(
    token: RefreshTokenRecord,
    successorId: Id,
    now: Timestamp,
  ): Promise<RefreshResult | null> {
    const secret = generateSecret(this.ctx.random);
    try {
      const outcome = await this.ctx.storage.uow.run(async (tx) => {
        const session = await tx.sessions.get(token.sessionId);
        if (!session || sessionStatus(session, now) !== 'active') return null;
        const user = await tx.users.getById(session.userId);
        if (!user) return null;
        const state = findState(this.ctx.config.accountStates, user.status);
        if (!state || !state.canRefresh) return null;
        if (user.securityVersion !== session.securityVersionAtIssue) return null;
        const expiresAt = clampIdle(
          now + this.ctx.config.tokens.refreshIdleTtlMs,
          session.absoluteExpiresAt,
        );
        if (expiresAt <= now) return null;
        const replacement: NewRefreshToken = {
          id: this.ctx.ids.newId(),
          hash: digest(secret),
          sessionId: session.id,
          userId: session.userId,
          parentId: token.id,
          createdAt: now,
          expiresAt,
        };
        const result = await tx.refreshTokens.replaceActiveSuccessor(
          successorId,
          replacement,
          token.id,
        );
        return result === 'replaced' ? { session, user, expiresAt } : null;
      });
      if (!outcome) return null;
      return this.completeRotation(
        outcome.session,
        outcome.user,
        { secret, expiresAt: outcome.expiresAt },
        now,
      );
    } catch (e) {
      if (!isAuthError(e)) throw toInfraError(e);
      return null;
    }
  }

  /** refresh.md §2 steps 10-11: issue the access token and respond. */
  private async completeRotation(
    session: Session,
    user: User,
    successor: { readonly secret: string; readonly expiresAt: Timestamp },
    now: Timestamp,
  ): Promise<RefreshResult> {
    let access;
    try {
      access = this.ctx.accessTokens.issue(
        {
          subjectId: session.userId,
          sessionId: session.id,
          securityVersion: user.securityVersion,
          ttlMs: this.ctx.config.tokens.accessTtlMs,
        },
        now,
      );
    } catch (e) {
      // §2 step 10: the successor is unreachable; revoke the family.
      await this.revocation.terminateSession(session.id, 'admin');
      throw toInfraError(e);
    }
    const principal = await buildPrincipal(this.ctx, session, user, now);
    await emitAudit(
      this.ctx,
      {
        type: 'refresh.succeeded',
        actor: { id: user.id, type: session.subjectType, sessionId: session.id },
        target: { type: 'session', id: session.id },
      },
      now,
    );
    return {
      principal,
      credentials: {
        accessToken: access.token,
        accessTokenExpiresAt: access.expiresAt,
        refreshToken: successor.secret,
        refreshTokenExpiresAt: successor.expiresAt,
      },
    };
  }

  private async auditRejected(reason: string, now: Timestamp): Promise<void> {
    await emitAudit(this.ctx, { type: 'auth.rejected', outcome: 'denied', reason }, now);
  }
}
