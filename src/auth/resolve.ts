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
import { toInfraError } from '../errors/index.js';
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
 * DEVIATION (documented in docs/CONFORMANCE.md): `tokens.revocation` is accepted in configuration
 * but this implementation always applies **strict** semantics — the session and `securityVersion`
 * are checked on every request. spec/auth/tokens.md §2.5 permits `eventual` to accept an access
 * token of a revoked session until its `exp`, which contradicts INV-SESS-01; Phase 1 resolves that
 * conflict in favour of the invariant (fail closed).
 * TODO(spec/auth/tokens.md §2.5): revisit when a cache layer exists.
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
    const { storage, clock, config } = this.ctx;
    const now = clock.now();

    // Step 1: extract.
    if (typeof accessToken !== 'string' || accessToken.length === 0) return null;

    // Step 2: verify the transport credential.
    const verified = this.ctx.accessTokens.verify(accessToken, now);
    if (!verified.ok) {
      await this.auditRejected(verified.failure, now);
      return null;
    }

    try {
      // Step 3: load the session.
      const session = await storage.sessions.get(verified.token.sessionId);
      if (!session || sessionStatus(session, now) !== 'active') {
        await this.auditRejected('session_not_active', now);
        return null;
      }
      if (session.userId !== verified.token.subjectId) {
        await this.auditRejected('subject_mismatch', now);
        return null;
      }

      // Step 5: account state.
      const user = await storage.users.getById(session.userId);
      if (!user) {
        await this.auditRejected('user_missing', now);
        return null;
      }
      const state = findState(config.accountStates, user.status);
      if (!state || !state.canLogin) {
        await this.auditRejected('account_state', now);
        return null;
      }

      // Step 4: strict revocation check (always applied; see the class note).
      if (verified.token.securityVersion !== user.securityVersion) {
        await this.auditRejected('security_version', now);
        return null;
      }

      // Step 6: build the Principal.
      const principal = await buildPrincipal(this.ctx, session, user, now);

      // Step 7: touch, throttled. A touch failure must not fail resolution (§7.2 step 7).
      if (now - session.lastSeenAt >= config.sessions.touchIntervalMs) {
        const idle = clampIdle(now + config.sessions.idleTtlMs, session.absoluteExpiresAt);
        await storage.sessions.touch(session.id, now, idle).catch(() => false);
      }
      return principal;
    } catch (e) {
      // Fail closed and distinguishable from "unauthenticated".
      throw toInfraError(e);
    }
  }

  private async auditRejected(reason: string, now: Timestamp): Promise<void> {
    await emitAudit(this.ctx, { type: 'auth.rejected', outcome: 'denied', reason }, now);
  }
}
