// Implements spec/auth/tokens.md §7 and spec/auth/session.md §4: session creation and the
// issuance of client credentials.
import type {
  DeviceInfo,
  Id,
  NewRefreshToken,
  NewSession,
  Session,
  Timestamp,
  User,
} from '../domain/index.js';
import { authError, toInfraError } from '../errors/index.js';
import { digest, generateSecret } from './digest.js';
import { emitAudit, type AuthContext } from './config.js';

/** Credentials handed to the client exactly once, at issue (tokens.md §7.1). */
export interface IssuedCredentials {
  readonly accessToken: string;
  readonly accessTokenExpiresAt: Timestamp;
  readonly refreshToken: string;
  readonly refreshTokenExpiresAt: Timestamp;
}

export interface SessionCreationInput {
  readonly user: User;
  readonly authMethod: string;
  readonly amr: readonly string[];
  readonly device?: DeviceInfo;
}

export interface SessionCreationResult {
  readonly session: Session;
  readonly credentials: IssuedCredentials;
  readonly evicted: readonly Id[];
}

/** Clamps the idle expiry to the absolute expiry (session.md §2.2.3). */
export function clampIdle(idleCandidate: Timestamp, absoluteExpiresAt: Timestamp): Timestamp {
  return Math.min(idleCandidate, absoluteExpiresAt);
}

/**
 * login.md §3.2 steps 9-10: creates a session under the concurrency limit and issues credentials.
 *
 * The session row and the first refresh-token row are written in one unit of work. The access token
 * is minted after commit; if that fails the new session is revoked, so no half-issued session can
 * exist (tokens.md §7.3).
 *
 * @returns the session, its evicted predecessors and the client credentials.
 * @throws SESSION_LIMIT_REACHED when the limit policy is `reject`; ACCOUNT_RESTRICTED when the
 *         account state changed to a non-login state in the meantime; STORAGE_UNAVAILABLE on
 *         infrastructure failure.
 */
export async function createSessionWithCredentials(
  ctx: AuthContext,
  input: SessionCreationInput,
): Promise<SessionCreationResult> {
  const { storage, clock, ids, random, config } = ctx;
  const now = clock.now();

  // The secret is generated outside the unit so a transaction retry cannot change it.
  const refreshSecret = generateSecret(random);
  const refreshHash = digest(refreshSecret);
  const sessionId = ids.newId();
  const absoluteExpiresAt = now + config.sessions.absoluteTtlMs;
  const idleExpiresAt = clampIdle(now + config.sessions.idleTtlMs, absoluteExpiresAt);
  const refreshExpiresAt = clampIdle(now + config.tokens.refreshIdleTtlMs, absoluteExpiresAt);

  let created: { session: Session; evicted: readonly Id[] } | undefined;
  try {
    created = await storage.uow.run(async (tx) => {
      // Re-read inside the unit: the state may have changed after the password was verified
      // (login.md §3.2 step 9).
      const fresh = await tx.users.getById(input.user.id);
      if (!fresh) throw authError('NOT_FOUND');
      const state = config.accountStates.states.find((x) => x.name === fresh.status);
      if (!state || !state.canLogin) {
        throw authError('ACCOUNT_RESTRICTED', {
          ...(config.revealRestrictedState ? { details: { state: fresh.status } } : {}),
        });
      }
      const session: NewSession = {
        id: sessionId,
        userId: fresh.id,
        subjectType: config.subjectType,
        authMethod: input.authMethod,
        amr: [...input.amr],
        authenticatedAt: now,
        createdAt: now,
        lastSeenAt: now,
        idleExpiresAt,
        absoluteExpiresAt,
        // session.md §2.2.7: read in the same atomic step that creates the session.
        securityVersionAtIssue: fresh.securityVersion,
        ...(input.device !== undefined ? { device: input.device } : {}),
      };
      const result = await tx.sessions.createWithLimit(
        session,
        config.sessions.max,
        config.sessions.onLimit,
        now,
      );
      if (result.kind === 'limit_reached') throw authError('SESSION_LIMIT_REACHED');
      const record: NewRefreshToken = {
        id: ids.newId(),
        hash: refreshHash,
        sessionId: result.session.id,
        userId: fresh.id,
        createdAt: now,
        expiresAt: refreshExpiresAt,
      };
      await tx.refreshTokens.insert(record);
      return { session: result.session, evicted: result.evicted };
    });
  } catch (e) {
    throw toInfraError(e);
  }

  const session = created.session;
  let access;
  try {
    access = ctx.accessTokens.issue(
      {
        subjectId: session.userId,
        sessionId: session.id,
        securityVersion: session.securityVersionAtIssue,
        ttlMs: config.tokens.accessTtlMs,
      },
      now,
    );
  } catch (e) {
    // tokens.md §7.3: never leave a session behind that the client cannot use.
    await storage.sessions.revoke(session.id, 'logout', now).catch(() => undefined);
    await storage.refreshTokens.revokeFamily(session.id, 'session_revoked').catch(() => undefined);
    throw toInfraError(e);
  }

  await emitAudit(
    ctx,
    {
      type: 'session.created',
      target: { type: 'session', id: session.id },
      details: { userId: session.userId, authMethod: session.authMethod },
    },
    now,
  );
  for (const id of session ? created.evicted : []) {
    await emitAudit(
      ctx,
      {
        type: 'session.evicted',
        severity: 'notice',
        target: { type: 'session', id },
        reason: 'evicted',
      },
      now,
    );
  }

  return {
    session,
    evicted: created.evicted,
    credentials: {
      accessToken: access.token,
      accessTokenExpiresAt: access.expiresAt,
      refreshToken: refreshSecret,
      refreshTokenExpiresAt: refreshExpiresAt,
    },
  };
}
