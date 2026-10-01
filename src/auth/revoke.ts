// Implements spec/flows/revoke.md: the common `terminate` procedure, logout, logout-all,
// remote revoke and administrative credential invalidation.
import type { Id, Principal, RevocationReason, Subject } from '../domain/index.js';
import { authError, isAuthError, toInfraError } from '../errors/index.js';
import type { Authorizer } from '../policy/authorizer.js';
import { digest } from './digest.js';
import { emitAudit, type AuthContext } from './config.js';

/** Causes that must also increment `securityVersion` (revoke.md §4). */
const BUMPS_SECURITY_VERSION: ReadonlySet<RevocationReason> = new Set<RevocationReason>([
  'password_changed',
  'password_reset',
  'account_state',
  'credentials_invalidated',
]);

export interface LogoutInput {
  readonly principal?: Principal;
  readonly refreshToken?: string;
  readonly sessionId?: Id;
}

export interface TerminateResult {
  /** Sessions newly revoked by this call (already-revoked sessions are not counted). */
  readonly revoked: number;
}

export class RevocationService {
  constructor(
    private readonly ctx: AuthContext,
    private readonly authorizer?: Authorizer,
  ) {}

  /**
   * revoke.md §2: revokes one session and its refresh family atomically, then emits audit events
   * outside the unit. Returns true when this call performed the revocation (idempotent otherwise).
   */
  async terminateSession(
    sessionId: Id,
    reason: RevocationReason,
    options: { readonly actor?: Subject; readonly bumpSecurityVersion?: boolean } = {},
  ): Promise<boolean> {
    const { storage, clock } = this.ctx;
    const now = clock.now();
    let userId: Id | undefined;
    let newlyRevoked = false;
    try {
      await storage.uow.run(async (tx) => {
        const session = await tx.sessions.get(sessionId);
        if (!session) return;
        userId = session.userId;
        newlyRevoked = await tx.sessions.revoke(sessionId, reason, now);
        // Step 3: the family is revoked in the same unit, so no interval exists in which the
        // session is revoked while a refresh token is usable (INV-TOK-05).
        await tx.refreshTokens.revokeFamily(sessionId, 'session_revoked');
        const bump = options.bumpSecurityVersion ?? BUMPS_SECURITY_VERSION.has(reason);
        if (bump && newlyRevoked) await tx.users.bumpSecurityVersion(session.userId, now);
      });
    } catch (e) {
      // §5 / §6: an inability to confirm revocation is reported as failure, never success.
      throw toInfraError(e);
    }
    if (newlyRevoked) {
      await emitAudit(
        this.ctx,
        {
          type: 'session.revoked',
          severity: reason === 'refresh_reuse_detected' ? 'high' : 'notice',
          actor: options.actor ? { id: options.actor.id, type: options.actor.type } : {},
          target: { type: 'session', id: sessionId },
          reason,
          ...(userId !== undefined ? { details: { userId } } : {}),
        },
        now,
      );
    }
    return newlyRevoked;
  }

  /** revoke.md §2 for every session of a user. */
  async terminateAllForUser(
    userId: Id,
    reason: RevocationReason,
    options: {
      readonly except?: Id | null;
      readonly actor?: Subject;
      readonly bumpSecurityVersion?: boolean;
    } = {},
  ): Promise<TerminateResult> {
    const { storage, clock } = this.ctx;
    const now = clock.now();
    const except = options.except ?? null;
    let revoked = 0;
    try {
      await storage.uow.run(async (tx) => {
        revoked = await tx.sessions.revokeAllForUser(userId, except, reason, now);
        const bump = options.bumpSecurityVersion ?? BUMPS_SECURITY_VERSION.has(reason);
        if (bump) await tx.users.bumpSecurityVersion(userId, now);
      });
    } catch (e) {
      throw toInfraError(e);
    }
    if (revoked > 0) {
      await emitAudit(
        this.ctx,
        {
          type: 'session.revoked',
          severity: 'notice',
          actor: options.actor ? { id: options.actor.id, type: options.actor.type } : {},
          target: { type: 'user', id: userId },
          reason,
          details: { count: revoked },
        },
        now,
      );
    }
    return { revoked };
  }

  /**
   * revoke.md §3.1: logout of the current session. Succeeds identically whether the presented
   * credential was valid, expired, unknown or already revoked (INV-LEAK-01).
   */
  async logout(input: LogoutInput): Promise<void> {
    const sessionId = await this.resolveTarget(input);
    if (sessionId === undefined) {
      // No target: succeed without effect (§3.1.2, §3.1.3).
      return;
    }
    await this.terminateSession(sessionId, 'logout');
    await emitAudit(this.ctx, {
      type: 'logout',
      severity: 'info',
      target: { type: 'session', id: sessionId },
    });
  }

  /** revoke.md §3.2: logout of all sessions, optionally keeping the caller's own. */
  async logoutAll(
    principal: Principal,
    options: { readonly includeCurrent?: boolean } = {},
  ): Promise<number> {
    const includeCurrent = options.includeCurrent === true;
    const except = includeCurrent ? null : (principal.sessionId ?? null);
    const result = await this.terminateAllForUser(principal.id, 'logout_all', {
      except,
      actor: principal,
      // §3.2.3: logout-all does not bump securityVersion by default.
      bumpSecurityVersion: false,
    });
    await emitAudit(this.ctx, {
      type: 'logout.all',
      actor: {
        id: principal.id,
        type: principal.type,
        ...(principal.sessionId ? { sessionId: principal.sessionId } : {}),
      },
      target: { type: 'user', id: principal.id },
      details: { count: result.revoked, includeCurrent },
    });
    return result.revoked;
  }

  /**
   * revoke.md §3.3: remote revoke. A session that the actor neither owns nor is authorized for is
   * reported as NOT_FOUND, identically to an unknown id (INV-LEAK-04).
   */
  async revokeSession(actor: Principal | Subject, sessionId: Id): Promise<void> {
    const session = await this.ctx.storage.sessions.get(sessionId);
    if (!session) throw authError('NOT_FOUND');
    if (session.userId !== actor.id) {
      if (!this.authorizer) throw authError('NOT_FOUND');
      const decision = await this.authorizer.authorize(actor, 'revoke', {
        type: 'session',
        id: sessionId,
        ownerId: session.userId,
      });
      if (decision.effect === 'deny') throw authError('NOT_FOUND');
      await this.terminateSession(sessionId, 'admin', { actor });
      return;
    }
    await this.terminateSession(sessionId, 'logout', { actor });
  }

  /** revoke.md §3.4: administrative invalidation of a user's credentials. */
  async invalidateCredentials(actor: Principal | Subject, userId: Id): Promise<number> {
    if (!this.authorizer) throw authError('FORBIDDEN');
    // revoke.md §3.4 names `account:setstatus` as the reserved permission for this capability and
    // allows a project to register a dedicated one; Phase 1 requires the reserved permission.
    await this.authorizer.assert(actor, 'setstatus', { type: 'account', id: userId });
    const user = await this.ctx.storage.users.getById(userId);
    if (!user) throw authError('NOT_FOUND');
    const result = await this.terminateAllForUser(userId, 'credentials_invalidated', {
      actor,
      bumpSecurityVersion: true,
    });
    return result.revoked;
  }

  /** revoke.md §3.1 step 1: find the session a logout refers to. */
  private async resolveTarget(input: LogoutInput): Promise<Id | undefined> {
    if (input.principal?.sessionId !== undefined) return input.principal.sessionId;
    if (input.sessionId !== undefined) return input.sessionId;
    if (typeof input.refreshToken === 'string' && input.refreshToken.length > 0) {
      try {
        // §3.1.5: the token is consumed; harmless because the family is revoked next.
        const result = await this.ctx.storage.refreshTokens.consume(
          digest(input.refreshToken),
          this.ctx.clock.now(),
        );
        return result.kind === 'unknown' ? undefined : result.token.sessionId;
      } catch (e) {
        if (isAuthError(e)) throw e;
        throw toInfraError(e);
      }
    }
    return undefined;
  }
}
