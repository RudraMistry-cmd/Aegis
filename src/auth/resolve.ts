// Implements spec/auth/principal.md §7: request resolution (credentials -> Principal | null).
import {
  createSubject,
  findState,
  sessionStatus,
  type Json,
  type Principal,
  type Session,
  type Timestamp,
  type User,
} from '../domain/index.js';
import { authError, toInfraError } from '../errors/index.js';
import { clampIdle } from './issue.js';
import { emitAudit, type AuthContext } from './config.js';

/**
 * Builds the immutable Principal for a session (principal.md §2, §7.2 step 6).
 *
 * `authMethod`, `amr` and `authenticatedAt` are copied from the **session record**, never from
 * request input (INV-AUTH-01). An attribute-provider failure propagates: a Principal is never
 * returned without its attributes (principal.md §2.3.2).
 */
export async function buildPrincipal(
  ctx: AuthContext,
  session: Session,
  user: User,
  now: Timestamp,
): Promise<Principal> {
  let tenantId: string | undefined;
  let attributes: Record<string, Json> = {};
  if (ctx.attributes) {
    try {
      const provided = await ctx.attributes.attributesFor(user.id, now);
      attributes = { ...provided.attributes };
      tenantId = provided.tenantId;
    } catch (e) {
      throw toInfraError(e);
    }
  }
  // principal.md §6.1.4: the core always exposes the restricted flag.
  const state = findState(ctx.config.accountStates, user.status);
  attributes['accountRestricted'] = state?.restricted === true;

  const subject = createSubject({
    id: user.id,
    type: session.subjectType,
    ...(tenantId !== undefined ? { tenantId } : {}),
    attributes,
  });
  return Object.freeze({
    ...subject,
    authMethod: session.authMethod,
    authenticatedAt: session.authenticatedAt,
    sessionId: session.id,
    amr: Object.freeze([...session.amr]),
  });
}

/**
 * Turns the credentials of an incoming request into a Principal.
 *
 * Strict revocation (spec/auth/tokens.md §2.5): the session and `securityVersion` are checked on
 * every request against the store, never a cache, so a revoked session's tokens are rejected
 * immediately (INV-SESS-01).
 */
export class ResolutionService {
  constructor(private readonly ctx: AuthContext) {}

  /**
   * @param accessToken the bearer credential, or any untrusted string.
   * @returns the Principal, or `null` for every credential problem (absent, malformed, bad
   *          signature, expired, revoked session, unknown session, state forbids). Infrastructure
   *          failures throw STORAGE_UNAVAILABLE instead of returning null (principal.md §7.1).
   */
  async resolve(accessToken: string | null | undefined): Promise<Principal | null> {
    const outcome = await this.evaluate(accessToken);
    return outcome.ok ? outcome.principal : null;
  }

  /**
   * Like `resolve`, but raises the external error instead of returning null (errors.md §3):
   * - no credential                                        → UNAUTHENTICATED
   * - a genuine token (signature verified) that has expired → TOKEN_EXPIRED
   * - anything else: malformed, bad signature, unknown kid, revoked or expired session,
   *   securityVersion mismatch, account state                → TOKEN_INVALID (never says which)
   * Infrastructure failures throw STORAGE_UNAVAILABLE, exactly as in `resolve`.
   */
  async authenticate(accessToken: string | null | undefined): Promise<Principal> {
    const outcome = await this.evaluate(accessToken);
    if (outcome.ok) return outcome.principal;
    if (outcome.reason === 'absent') throw authError('UNAUTHENTICATED');
    if (outcome.reason === 'expired') throw authError('TOKEN_EXPIRED');
    throw authError('TOKEN_INVALID');
  }

  /** principal.md §7.2, shared by `resolve` and `authenticate`. */
  private async evaluate(
    accessToken: string | null | undefined,
  ): Promise<
    | { readonly ok: true; readonly principal: Principal }
    | { readonly ok: false; readonly reason: 'absent' | 'expired' | 'invalid' }
  > {
    const { storage, clock, config } = this.ctx;
    const now = clock.now();
    const reject = async (reason: string, kind: 'expired' | 'invalid' = 'invalid') => {
      await this.auditRejected(reason, now);
      return { ok: false as const, reason: kind };
    };

    // Step 1: extract.
    if (typeof accessToken !== 'string' || accessToken.length === 0) {
      return { ok: false, reason: 'absent' };
    }

    // Step 2: verify the transport credential. This proves only that this server issued the token;
    // it never decides whether the session may act (tokens.md §2.5).
    const verified = this.ctx.accessTokens.verify(accessToken, now);
    if (!verified.ok) {
      return reject(verified.failure, verified.failure === 'expired' ? 'expired' : 'invalid');
    }

    try {
      // Step 3: load the session — the single source of truth.
      const session = await storage.sessions.get(verified.token.sessionId);
      if (!session || sessionStatus(session, now) !== 'active') {
        return reject('session_not_active');
      }
      if (session.userId !== verified.token.subjectId) return reject('subject_mismatch');

      // Step 5: account state.
      const user = await storage.users.getById(session.userId);
      if (!user) return reject('user_missing');
      const state = findState(config.accountStates, user.status);
      if (!state || !state.canLogin) return reject('account_state');

      // Step 4: strict revocation check (always applied; see the class note).
      if (verified.token.securityVersion !== user.securityVersion)
        return reject('security_version');

      // Step 6: build the Principal.
      const principal = await buildPrincipal(this.ctx, session, user, now);

      // Step 7: touch, throttled. A touch failure must not fail resolution (§7.2 step 7).
      if (now - session.lastSeenAt >= config.sessions.touchIntervalMs) {
        const idle = clampIdle(now + config.sessions.idleTtlMs, session.absoluteExpiresAt);
        await storage.sessions.touch(session.id, now, idle).catch(() => false);
      }
      return { ok: true, principal };
    } catch (e) {
      // Fail closed and distinguishable from "unauthenticated".
      throw toInfraError(e);
    }
  }

  private async auditRejected(reason: string, now: Timestamp): Promise<void> {
    await emitAudit(this.ctx, { type: 'auth.rejected', outcome: 'denied', reason }, now);
  }
}
