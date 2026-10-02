// Implements the configuration contract of spec/auth/* (TTLs, session limits, account states,
// enumeration and throttle modes) with boot-time validation per spec/errors.md §2 (CONFIG_INVALID)
// and spec/invariants.md INV-CFG-01..03.
import {
  DEFAULT_STATE_MACHINE,
  deepFreeze,
  validateStateMachine,
  type AccountStateMachine,
  type Timestamp,
} from '../domain/index.js';
import { configInvalid, type ConfigViolation } from '../errors/index.js';
import type {
  AccessTokenProvider,
  AttributeProvider,
  AuditEvent,
  AuditSink,
  Clock,
  IdGenerator,
  PasswordHasher,
  RateLimiter,
  Random,
  Storage,
} from '../ports/index.js';

/** Ports the authentication services depend on (constructor injection only). */
export interface AuthDeps {
  readonly storage: Storage;
  readonly hasher: PasswordHasher;
  readonly accessTokens: AccessTokenProvider;
  readonly clock: Clock;
  readonly random: Random;
  readonly ids: IdGenerator;
  readonly rateLimiter?: RateLimiter;
  readonly audit?: AuditSink;
  readonly attributes?: AttributeProvider;
}

export interface SessionConfigInput {
  /** Maximum concurrent active sessions; `null` means unlimited and must be explicit (§6.5). */
  readonly max?: number | null;
  readonly onLimit?: 'evict-oldest' | 'reject';
  readonly idleTtlMs?: number;
  readonly absoluteTtlMs?: number;
  /** Touch throttle; must be <= idleTtlMs/4 (session.md §5.2). */
  readonly touchIntervalMs?: number;
}

export interface TokenConfigInput {
  /** Default 10 min; above 60 min requires `allowLongAccessTtl` (tokens.md §2.3.1). */
  readonly accessTtlMs?: number;
  readonly allowLongAccessTtl?: boolean;
  readonly refreshIdleTtlMs?: number;
  /** tokens.md §3.5: default 0 (disabled), maximum 10 000 ms. */
  readonly reuseGraceMs?: number;
  /** tokens.md §2.5: strict revocation is the only mode; anything else is CONFIG_INVALID. */
  readonly revocation?: 'strict';
}

export interface AuthConfigInput {
  readonly identifiers?: readonly string[];
  readonly passwordMinLength?: number;
  readonly accountStates?: AccountStateMachine;
  readonly sessions?: SessionConfigInput;
  readonly tokens?: TokenConfigInput;
  /** login.md §3.2 step 6: reveal ACCOUNT_RESTRICTED after a correct password. Default true. */
  readonly revealRestrictedState?: boolean;
  /** login.md §6.1.5: uniform registration response. Default true. */
  readonly enumerationSafeRegistration?: boolean;
  /** login.md §5.7. Default 'open-with-alert'. */
  readonly throttleFailMode?: 'open-with-alert' | 'closed';
  /** The subject type stamped on sessions and principals. Default 'user'. */
  readonly subjectType?: string;
}

export interface ResolvedAuthConfig {
  readonly identifiers: readonly string[];
  readonly passwordMinLength: number;
  readonly accountStates: AccountStateMachine;
  readonly sessions: {
    readonly max: number | null;
    readonly onLimit: 'evict-oldest' | 'reject';
    readonly idleTtlMs: number;
    readonly absoluteTtlMs: number;
    readonly touchIntervalMs: number;
  };
  readonly tokens: {
    readonly accessTtlMs: number;
    readonly refreshIdleTtlMs: number;
    readonly reuseGraceMs: number;
    readonly revocation: 'strict';
  };
  readonly revealRestrictedState: boolean;
  readonly enumerationSafeRegistration: boolean;
  readonly throttleFailMode: 'open-with-alert' | 'closed';
  readonly subjectType: string;
  /** Insecure relaxations, emitted as `config.warning` at start-up (INV-CFG-02). */
  readonly warnings: readonly { readonly path: string; readonly message: string }[];
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/**
 * Validates and freezes the configuration. Throws CONFIG_INVALID listing **all** violations.
 * Called once at construction; no request path may raise CONFIG_INVALID (errors.md §4.4).
 */
export function resolveAuthConfig(input: AuthConfigInput = {}): ResolvedAuthConfig {
  const v: ConfigViolation[] = [];
  const warnings: { path: string; message: string }[] = [];

  const identifiers = input.identifiers ?? ['email'];
  for (const t of identifiers) {
    if (t !== 'email' && t !== 'username') {
      v.push({
        path: 'identifiers',
        rule: 'identifier.type',
        message: `unsupported identifier type ${String(t)} (Phase 1 supports email, username)`,
      });
    }
  }
  if (identifiers.length === 0) {
    v.push({
      path: 'identifiers',
      rule: 'identifier.required',
      message: 'at least one identifier type is required',
    });
  }

  const passwordMinLength = input.passwordMinLength ?? 12;
  if (!Number.isInteger(passwordMinLength) || passwordMinLength < 8) {
    // principal.md §5.1.5.4: the minimum must not be configurable below 8.
    v.push({
      path: 'passwordMinLength',
      rule: 'password.min_length',
      message: 'must be an integer >= 8',
    });
  }

  const accountStates = input.accountStates ?? DEFAULT_STATE_MACHINE;
  v.push(
    ...validateStateMachine(accountStates).map((x) => ({ ...x, path: `accountStates.${x.path}` })),
  );

  const s = input.sessions ?? {};
  const max = s.max === undefined ? 10 : s.max;
  if (max !== null && (!Number.isInteger(max) || max < 1)) {
    v.push({
      path: 'sessions.max',
      rule: 'session.max',
      message: 'max must be an integer >= 1 or null',
    });
  }
  if (max === null) {
    warnings.push({ path: 'sessions.max', message: 'unlimited concurrent sessions' });
  }
  const idleTtlMs = s.idleTtlMs ?? 14 * DAY;
  const absoluteTtlMs = s.absoluteTtlMs ?? 60 * DAY;
  if (!Number.isInteger(idleTtlMs) || idleTtlMs < 1) {
    v.push({
      path: 'sessions.idleTtlMs',
      rule: 'session.idle_ttl',
      message: 'must be a positive integer',
    });
  }
  if (!Number.isInteger(absoluteTtlMs) || absoluteTtlMs < idleTtlMs) {
    v.push({
      path: 'sessions.absoluteTtlMs',
      rule: 'session.absolute_ttl',
      message: 'must be a positive integer >= idleTtlMs',
    });
  }
  const touchIntervalMs = s.touchIntervalMs ?? Math.floor(idleTtlMs / 8);
  if (
    !Number.isInteger(touchIntervalMs) ||
    touchIntervalMs < 0 ||
    touchIntervalMs > idleTtlMs / 4
  ) {
    // session.md §5.2: the touch interval must be <= idleTtl/4.
    v.push({
      path: 'sessions.touchIntervalMs',
      rule: 'session.touch_interval',
      message: 'must be an integer in 0..idleTtlMs/4',
    });
  }

  const t = input.tokens ?? {};
  const accessTtlMs = t.accessTtlMs ?? 10 * MINUTE;
  if (!Number.isInteger(accessTtlMs) || accessTtlMs < 1) {
    v.push({
      path: 'tokens.accessTtlMs',
      rule: 'token.access_ttl',
      message: 'must be a positive integer',
    });
  } else if (accessTtlMs > 60 * MINUTE) {
    if (t.allowLongAccessTtl !== true) {
      v.push({
        path: 'tokens.accessTtlMs',
        rule: 'token.access_ttl_max',
        message: 'exceeds 60 minutes; set allowLongAccessTtl to override',
      });
    } else {
      warnings.push({ path: 'tokens.accessTtlMs', message: 'access token TTL exceeds 60 minutes' });
    }
  }
  const refreshIdleTtlMs = t.refreshIdleTtlMs ?? 14 * DAY;
  if (!Number.isInteger(refreshIdleTtlMs) || refreshIdleTtlMs < 1) {
    v.push({
      path: 'tokens.refreshIdleTtlMs',
      rule: 'token.refresh_ttl',
      message: 'must be a positive integer',
    });
  }
  const reuseGraceMs = t.reuseGraceMs ?? 0;
  if (!Number.isInteger(reuseGraceMs) || reuseGraceMs < 0 || reuseGraceMs > 10_000) {
    v.push({
      path: 'tokens.reuseGraceMs',
      rule: 'token.reuse_grace',
      message: 'must be an integer in 0..10000',
    });
  } else if (reuseGraceMs > 0) {
    warnings.push({ path: 'tokens.reuseGraceMs', message: 'refresh reuse grace is enabled' });
  }
  const revocation = t.revocation ?? 'strict';
  if (revocation !== 'strict') {
    // tokens.md §2.5: eventual revocation is not supported.
    v.push({
      path: 'tokens.revocation',
      rule: 'token.revocation',
      message: 'only strict revocation is supported',
    });
  }

  const enumerationSafeRegistration = input.enumerationSafeRegistration ?? true;
  if (!enumerationSafeRegistration) {
    warnings.push({
      path: 'enumerationSafeRegistration',
      message: 'registration reveals whether an identifier exists',
    });
  }
  const throttleFailMode = input.throttleFailMode ?? 'open-with-alert';
  if (throttleFailMode === 'open-with-alert') {
    warnings.push({
      path: 'throttleFailMode',
      message: 'login proceeds when the rate limiter is unavailable',
    });
  }
  const subjectType = input.subjectType ?? 'user';
  if (!/^[a-z][a-z0-9_-]{0,31}$/.test(subjectType)) {
    v.push({ path: 'subjectType', rule: 'subject.type', message: 'invalid subject type' });
  }

  if (v.length > 0) throw configInvalid(v);

  return deepFreeze({
    identifiers: [...identifiers],
    passwordMinLength,
    accountStates,
    sessions: {
      max,
      onLimit: s.onLimit ?? 'evict-oldest',
      idleTtlMs,
      absoluteTtlMs,
      touchIntervalMs,
    },
    tokens: { accessTtlMs, refreshIdleTtlMs, reuseGraceMs, revocation },
    revealRestrictedState: input.revealRestrictedState ?? true,
    enumerationSafeRegistration,
    throttleFailMode,
    subjectType,
    warnings,
  });
}

/** Shared service context: resolved config plus the ports. */
export interface AuthContext extends AuthDeps {
  readonly config: ResolvedAuthConfig;
}

export interface AuditInput {
  readonly type: string;
  readonly severity?: AuditEvent['severity'];
  readonly outcome?: AuditEvent['outcome'];
  readonly actor?: AuditEvent['actor'];
  readonly target?: AuditEvent['target'];
  readonly reason?: string;
  readonly context?: AuditEvent['context'];
  readonly details?: AuditEvent['details'];
}

/**
 * Emits an audit event. A sink failure is swallowed (spec/storage/interfaces.md §10.1,
 * spec/flows/revoke.md §6): it never changes the outcome of the operation.
 */
export async function emitAudit(
  ctx: AuthContext,
  input: AuditInput,
  at?: Timestamp,
): Promise<void> {
  if (!ctx.audit) return;
  try {
    await ctx.audit.write({
      id: ctx.ids.newId(),
      type: input.type,
      at: at ?? ctx.clock.now(),
      severity: input.severity ?? 'info',
      actor: input.actor ?? {},
      target: input.target ?? {},
      outcome: input.outcome ?? 'success',
      ...(input.reason !== undefined ? { reason: input.reason } : {}),
      context: input.context ?? {},
      details: input.details ?? {},
    });
  } catch {
    // Intentionally ignored; see above.
  }
}
