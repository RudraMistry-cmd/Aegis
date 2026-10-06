// Implements spec/flows/login.md §3 (password login) and §6.1 (registration).
import {
  assertPasswordAcceptable,
  findState,
  isOversizePassword,
  looseNormalize,
  normalizeIdentifier,
  normalizePassword,
  scalarLength,
  type DeviceInfo,
  type Id,
  type Json,
  type Principal,
  type Timestamp,
  type User,
} from '../domain/index.js';
import { authError, isAuthError, toInfraError } from '../errors/index.js';
import { emitAudit, type AuthContext } from './config.js';
import { createSessionWithCredentials, type IssuedCredentials } from './issue.js';
import { buildPrincipal } from './resolve.js';

export interface LoginInput {
  readonly identifier: string;
  readonly password: string;
  readonly device?: DeviceInfo;
  readonly clientIp?: string;
  readonly requestId?: string;
}

export interface LoginResult {
  readonly principal: Principal;
  readonly credentials: IssuedCredentials;
}

export interface RegisterInput {
  readonly identifier: string;
  readonly password: string;
  readonly metadata?: Record<string, Json>;
  readonly clientIp?: string;
  /** Identifier type; must be one of the configured types. Defaults to the first configured. */
  readonly identifierType?: string;
}

/** login.md §6.1.7: the uniform registration response carries no user id and no token. */
export interface RegistrationAccepted {
  readonly accepted: true;
}

/** Fields that request payloads may never set (principal.md §3.4, INV-AUTHZ-09). */
const FORBIDDEN_METADATA_KEYS = new Set([
  'id',
  'status',
  'version',
  'securityVersion',
  'roles',
  'role',
  'permissions',
  'tenantId',
]);

export class LoginService {
  constructor(private readonly ctx: AuthContext) {}

  /**
   * login.md §3.2: password login.
   *
   * Step order is normative where it matters: the throttle gate precedes any lookup or hashing
   * (§5.1), exactly one hasher operation of equal cost runs on every credential path (§5.2), and
   * the account state is revealed only after a correct password (§5.3).
   */
  async login(input: LoginInput): Promise<LoginResult> {
    const { config, clock, hasher, storage } = this.ctx;
    const now = clock.now();

    // ---- Step 1: shape validation (programmer errors only; never credential-dependent)
    if (typeof input?.identifier !== 'string' || typeof input?.password !== 'string') {
      throw authError('VALIDATION_FAILED', {
        details: { field: 'credentials', rule: 'login.shape' },
      });
    }
    if (scalarLength(input.identifier) > 320) {
      throw authError('VALIDATION_FAILED', {
        details: { field: 'identifier', rule: 'identifier.max_length' },
      });
    }
    const oversizePassword = isOversizePassword(input.password);

    // ---- Step 3 (pure): normalize, so the throttle key is stable. Failure follows the unknown-user path.
    const candidates = this.normalizeCandidates(input.identifier);
    const throttleIdentifier = candidates[0]?.normalized ?? looseNormalize(input.identifier);

    // ---- Step 2: throttle gate, before any store read or hash
    const keys = this.throttleKeys(throttleIdentifier, input.clientIp);
    const gate = await this.throttleGate(keys, now, input.requestId);
    if (gate.blocked) {
      throw authError('RATE_LIMITED', {
        ...(gate.retryAfterMs !== undefined ? { retryAfterMs: gate.retryAfterMs } : {}),
      });
    }

    const failLogin = async (reason: string): Promise<never> => {
      // ---- Step 5a: identical bookkeeping and response for every credential failure
      await this.recordFailures(keys, now);
      await emitAudit(
        this.ctx,
        {
          type: 'login.failed',
          outcome: 'failure',
          reason: 'invalid_credentials',
          // §10.4: the identifier is recorded only as a keyed digest, with no existence hint.
          details: {
            identifierDigest: this.ctx.config.digestIdentifier(throttleIdentifier),
            detail: reason,
          },
          context: {
            ...(input.requestId ? { requestId: input.requestId } : {}),
            ...(input.clientIp ? { ip: input.clientIp } : {}),
          },
        },
        now,
      );
      throw authError('INVALID_CREDENTIALS');
    };

    // §3.2 step 1: an oversize password fails without invoking the hasher at all.
    if (oversizePassword) return failLogin('oversize_password');

    // ---- Step 4: lookup
    let found: { user: User; credentialPayload: string; credentialId: Id } | undefined;
    try {
      for (const c of candidates) {
        const identifier = await storage.identifiers.findByNormalized(c.type, c.normalized);
        if (!identifier) continue;
        const user = await storage.users.getById(identifier.userId);
        if (!user) continue;
        const credential = await storage.credentials.get(user.id, 'password');
        if (!credential) break; // user exists without a password credential: same outcome as unknown
        found = { user, credentialPayload: credential.payload, credentialId: credential.id };
        break;
      }
    } catch (e) {
      await emitAudit(
        this.ctx,
        { type: 'login.failed', outcome: 'failure', reason: 'unavailable' },
        now,
      );
      throw toInfraError(e);
    }

    // ---- Step 5: exactly one hasher operation of equal cost on every path
    const password = normalizePassword(input.password);
    if (!found) {
      await hasher.dummyVerify(password);
      return failLogin('unknown_identifier');
    }
    const ok = await hasher.verify(password, found.credentialPayload);
    if (!ok) return failLogin('wrong_password');

    // ---- Step 6: account-state gate, only after a correct password
    const state = findState(config.accountStates, found.user.status);
    if (!state) {
      // Unknown stored state: fail closed (§3.2 step 6).
      await emitAudit(
        this.ctx,
        {
          type: 'config.warning',
          severity: 'warning',
          outcome: 'failure',
          reason: 'unknown_account_state',
          details: { status: found.user.status },
        },
        now,
      );
      throw authError('ACCOUNT_RESTRICTED');
    }
    if (!state.canLogin) {
      if (!config.revealRestrictedState) {
        return failLogin('account_state');
      }
      await emitAudit(
        this.ctx,
        {
          type: 'login.failed',
          severity: 'notice',
          outcome: 'failure',
          reason: 'account_state',
          target: { type: 'user', id: found.user.id },
        },
        now,
      );
      throw authError('ACCOUNT_RESTRICTED', { details: { state: found.user.status } });
    }

    // ---- Step 7: transparent rehash (best effort; a failure must not fail the login)
    if (hasher.needsRehash(found.credentialPayload)) {
      try {
        const upgraded = await hasher.hash(password);
        await storage.credentials.put(found.user.id, 'password', upgraded, now);
      } catch {
        // Ignored by design (§3.2 step 7).
      }
    }

    // Out of scope for Phase 1 (spec/flows/login.md §3.2 step 8): additional factors / MFA
    // challenges. See README, "Not included".

    // ---- Steps 9-10: create the session and issue credentials
    const { session, credentials } = await createSessionWithCredentials(this.ctx, {
      user: found.user,
      authMethod: 'password',
      amr: ['pwd'],
      ...(input.device !== undefined ? { device: input.device } : {}),
    });

    // ---- Step 11: post-commit effects (§3.2 step 11): reset only the identifier bucket
    if (this.ctx.rateLimiter) {
      try {
        await this.ctx.rateLimiter.reset(keys.identifier);
      } catch {
        // Not fatal.
      }
    }
    await emitAudit(
      this.ctx,
      {
        type: 'login.succeeded',
        actor: { id: found.user.id, type: config.subjectType, sessionId: session.id },
        target: { type: 'user', id: found.user.id },
        details: { authMethod: 'password' },
        context: {
          ...(input.requestId ? { requestId: input.requestId } : {}),
          ...(input.clientIp ? { ip: input.clientIp } : {}),
        },
      },
      now,
    );

    // ---- Step 12: build the Principal; an attribute failure revokes the new session
    try {
      const principal = await buildPrincipal(this.ctx, session, found.user, now);
      return { principal, credentials };
    } catch (e) {
      await storage.sessions.revoke(session.id, 'logout', now).catch(() => undefined);
      await storage.refreshTokens
        .revokeFamily(session.id, 'session_revoked')
        .catch(() => undefined);
      throw isAuthError(e) ? e : toInfraError(e);
    }
  }

  /**
   * login.md §6.1: registration. With `enumerationSafeRegistration` (the default) an existing
   * identifier yields the same `RegistrationAccepted` as a fresh one (INV-LEAK-01).
   */
  async register(input: RegisterInput): Promise<RegistrationAccepted> {
    const { config, clock, hasher, storage, ids } = this.ctx;
    const now = clock.now();
    const type = input.identifierType ?? (config.identifiers[0] as string);
    if (!config.identifiers.includes(type)) {
      throw authError('VALIDATION_FAILED', {
        details: { field: 'identifierType', rule: 'identifier.type' },
      });
    }
    const normalized = normalizeIdentifier(type, input.identifier);
    if (!normalized.ok) {
      throw authError('VALIDATION_FAILED', {
        details: { field: 'identifier', rule: `identifier.${normalized.reason}` },
      });
    }
    // Step 1: policy validation and mass-assignment rejection.
    const password = assertPasswordAcceptable(input.password, config.passwordMinLength);
    const metadata = input.metadata ?? {};
    for (const k of Object.keys(metadata)) {
      if (FORBIDDEN_METADATA_KEYS.has(k)) {
        throw authError('VALIDATION_FAILED', {
          details: { field: `metadata.${k}`, rule: 'metadata.forbidden_field' },
        });
      }
    }
    if (looseNormalize(password) === normalized.normalized) {
      throw authError('VALIDATION_FAILED', {
        details: { field: 'password', rule: 'password.equals_identifier' },
      });
    }

    // Step 2: throttle by IP bucket.
    if (this.ctx.rateLimiter && input.clientIp !== undefined) {
      const key = `register-ip:${input.clientIp}`;
      const peek = await this.ctx.rateLimiter
        .peek(key, now)
        .catch(() => ({ blocked: false, failures: 0, retryAfterMs: undefined }));
      if (peek.blocked) {
        throw authError('RATE_LIMITED', {
          ...(peek.retryAfterMs !== undefined ? { retryAfterMs: peek.retryAfterMs } : {}),
        });
      }
    }

    // Step 3: hash before checking existence, so both paths pay the same cost.
    const payload = await hasher.hash(password);

    // Step 4: create user, identifier and credential atomically.
    const userId = ids.newId();
    try {
      await storage.uow.run(async (tx) => {
        await tx.users.create({
          id: userId,
          status: config.accountStates.initial,
          metadata,
          createdAt: now,
        });
        await tx.identifiers.add(userId, type, input.identifier, normalized.normalized, false, now);
        await tx.credentials.put(userId, 'password', payload, now);
      });
    } catch (e) {
      if (isAuthError(e) && e.code === 'CONFLICT') {
        // Step 5: uniform response unless the project opted out.
        if (config.enumerationSafeRegistration) return { accepted: true };
        throw e;
      }
      throw toInfraError(e);
    }

    // Out of scope for Phase 1 (spec/flows/login.md §6.1.6): e-mail verification tokens need a
    // Notifier port. See README, "Not included".
    await emitAudit(
      this.ctx,
      {
        type: 'account.registered',
        target: { type: 'user', id: userId },
        details: { identifierType: type },
      },
      now,
    );
    return { accepted: true };
  }

  /** The identifier types to try, in configured order (principal.md §4.2). */
  private normalizeCandidates(raw: string): readonly { type: string; normalized: string }[] {
    const out: { type: string; normalized: string }[] = [];
    for (const type of this.ctx.config.identifiers) {
      const r = normalizeIdentifier(type, raw);
      if (r.ok) out.push({ type, normalized: r.normalized });
    }
    return out;
  }

  private throttleKeys(
    normalizedIdentifier: string,
    clientIp: string | undefined,
  ): { identifier: string; ip?: string; global: string } {
    return {
      // §9.8.2: the raw identifier is never stored in a shared limiter.
      identifier: `login:${this.ctx.config.digestIdentifier(normalizedIdentifier)}`,
      ...(clientIp !== undefined ? { ip: `login-ip:${clientIp}` } : {}),
      global: 'login-global',
    };
  }

  /** login.md §5.7: the throttle outage behavior is explicit configuration. */
  private async throttleGate(
    keys: { identifier: string; ip?: string; global: string },
    now: Timestamp,
    requestId: string | undefined,
  ): Promise<{ blocked: boolean; retryAfterMs?: number }> {
    const limiter = this.ctx.rateLimiter;
    if (!limiter) return { blocked: false };
    const list = [keys.identifier, keys.global, ...(keys.ip !== undefined ? [keys.ip] : [])];
    let retryAfterMs: number | undefined;
    let blocked = false;
    for (const key of list) {
      try {
        const r = await limiter.peek(key, now);
        if (r.blocked) {
          blocked = true;
          retryAfterMs = Math.max(retryAfterMs ?? 0, r.retryAfterMs ?? 0);
        }
      } catch {
        await emitAudit(
          this.ctx,
          {
            type: 'security.throttle_unavailable',
            severity: 'warning',
            outcome: 'failure',
            context: { ...(requestId ? { requestId } : {}) },
          },
          now,
        );
        if (this.ctx.config.throttleFailMode === 'closed') return { blocked: true };
        return { blocked: false };
      }
    }
    if (blocked) {
      await emitAudit(
        this.ctx,
        { type: 'login.throttled', outcome: 'denied', reason: 'rate_limited' },
        now,
      );
    }
    return { blocked, ...(retryAfterMs !== undefined ? { retryAfterMs } : {}) };
  }

  /** login.md §3.2 step 5a / §5 INV-THR-02: identical for existing and non-existing identifiers. */
  private async recordFailures(
    keys: { identifier: string; ip?: string; global: string },
    now: Timestamp,
  ): Promise<void> {
    const limiter = this.ctx.rateLimiter;
    if (!limiter) return;
    for (const key of [keys.identifier, keys.global, ...(keys.ip !== undefined ? [keys.ip] : [])]) {
      try {
        await limiter.recordFailure(key, now);
      } catch {
        // A limiter outage is reported by the gate, not here.
      }
    }
  }
}
