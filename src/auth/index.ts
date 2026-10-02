// The public facade: wires the domain services over the injected ports.
// Implements the configuration and public-API shape of spec/auth/*, spec/rbac/*, spec/policy/*.
import type { Id, Principal, RoleAssignment, Subject } from '../domain/index.js';
import { authError, configInvalid } from '../errors/index.js';
import { Authorizer } from '../policy/authorizer.js';
import type { AuthScope, Decision, Policy, Resource } from '../policy/index.js';
import {
  AssignmentService,
  type AssignInput,
  type EscalationGuardOptions,
} from '../rbac/assignmentService.js';
import { Catalog } from '../rbac/catalog.js';
import type { LintFinding } from '../rbac/catalog.js';
import { Rbac } from '../rbac/resolver.js';
import {
  emitAudit,
  resolveAuthConfig,
  type AuthConfigInput,
  type AuthContext,
  type AuthDeps,
} from './config.js';
import {
  LoginService,
  type LoginInput,
  type LoginResult,
  type RegisterInput,
  type RegistrationAccepted,
} from './login.js';
import { RefreshService, type RefreshInput, type RefreshResult } from './refresh.js';
import { ResolutionService } from './resolve.js';
import { RevocationService, type LogoutInput } from './revoke.js';

export interface CreateAuthInput extends AuthDeps, AuthConfigInput {
  readonly catalog: Catalog;
  readonly policies?: readonly Policy[];
  /** policy.md §6.4. Default false. */
  readonly strictPolicies?: boolean;
  readonly resolveType?: (resource: Resource) => string | undefined;
  readonly auditAllows?: 'none' | 'all';
  readonly guards?: EscalationGuardOptions;
}

/** A session as exposed to callers (session.md §7.1): no token or digest. */
export interface SessionView {
  readonly id: Id;
  readonly createdAt: number;
  readonly lastSeenAt: number;
  readonly authMethod: string;
  readonly device?: { readonly label?: string; readonly userAgent?: string; readonly ip?: string };
  readonly current: boolean;
}

export interface Auth {
  readonly authn: {
    register(input: RegisterInput): Promise<RegistrationAccepted>;
    login(input: LoginInput): Promise<LoginResult>;
    refresh(input: RefreshInput): Promise<RefreshResult>;
    /** Returns null for every credential problem; throws only on infrastructure failure. */
    resolve(accessToken: string | null | undefined): Promise<Principal | null>;
    /** Like resolve, but throws UNAUTHENTICATED / TOKEN_EXPIRED / TOKEN_INVALID instead of null. */
    authenticate(accessToken: string | null | undefined): Promise<Principal>;
    logout(input: LogoutInput): Promise<void>;
    logoutAll(principal: Principal, options?: { includeCurrent?: boolean }): Promise<number>;
    revokeSession(actor: Principal | Subject, sessionId: Id): Promise<void>;
    invalidateCredentials(actor: Principal | Subject, userId: Id): Promise<number>;
    listSessions(principal: Principal, userId?: Id): Promise<readonly SessionView[]>;
  };
  readonly authz: {
    can(subject: unknown, action: string, resource?: Resource | string | null): Promise<boolean>;
    authorize(
      subject: unknown,
      action: string,
      resource?: Resource | string | null,
      options?: { explain?: boolean },
    ): Promise<Decision>;
    assert(subject: unknown, action: string, resource?: Resource | string | null): Promise<void>;
    authorizeScope(subject: unknown, action: string, resourceType: string): Promise<AuthScope>;
    permissionsFor(subject: Subject | Pick<Subject, 'id'>): Promise<readonly string[]>;
    rolesFor(subject: Subject | Pick<Subject, 'id'>): Promise<readonly string[]>;
    hasRole(subject: Subject | Pick<Subject, 'id'>, roleName: string): Promise<boolean>;
    readonly roles: {
      assign(
        actor: Principal | Subject,
        targetSubjectId: Id,
        input: AssignInput,
      ): Promise<'created' | 'unchanged' | 'updated'>;
      revoke(actor: Principal | Subject, targetSubjectId: Id, roleName: string): Promise<boolean>;
      listFor(actor: Principal | Subject, targetSubjectId: Id): Promise<readonly RoleAssignment[]>;
    };
  };
  /** Lint findings (roles.md §8) plus configuration warnings. */
  doctor(): readonly LintFinding[];
  /** Effective configuration with secrets redacted (INV-CFG-03). */
  describe(): Record<string, unknown>;
}

/**
 * Creates an Aegis instance. All validation happens here: after this returns, no request path
 * raises CONFIG_INVALID (errors.md §4.4).
 *
 * @throws CONFIG_INVALID listing every violation found in the configuration.
 */
export function createAuth(input: CreateAuthInput): Auth {
  // tokens.md §2.3.1: an access-token provider that fixes its lifetime (the JWT provider does) and
  // the core must agree on it. If the core leaves it unset, the provider's lifetime is adopted.
  const providerTtl = input.accessTokens.ttlMs;
  const coreTtl = input.tokens?.accessTtlMs;
  if (providerTtl !== undefined && coreTtl !== undefined && coreTtl !== providerTtl) {
    throw configInvalid([
      {
        path: 'tokens.accessTtlMs',
        rule: 'token.ttl_mismatch',
        message: 'must equal the access-token provider ttl',
      },
    ]);
  }
  const config = resolveAuthConfig(
    providerTtl !== undefined && coreTtl === undefined
      ? { ...input, tokens: { ...input.tokens, accessTtlMs: providerTtl } }
      : input,
  );
  const ctx: AuthContext = {
    storage: input.storage,
    hasher: input.hasher,
    accessTokens: input.accessTokens,
    clock: input.clock,
    random: input.random,
    ids: input.ids,
    ...(input.rateLimiter !== undefined ? { rateLimiter: input.rateLimiter } : {}),
    ...(input.audit !== undefined ? { audit: input.audit } : {}),
    ...(input.attributes !== undefined ? { attributes: input.attributes } : {}),
    config,
  };

  const rbac = new Rbac(input.catalog, input.storage.assignments, input.clock);
  const authorizer = new Authorizer({
    rbac,
    clock: input.clock,
    ...(input.policies !== undefined ? { policies: input.policies } : {}),
    ...(input.audit !== undefined ? { audit: input.audit } : {}),
    ids: input.ids,
    ...(input.strictPolicies !== undefined ? { strictPolicies: input.strictPolicies } : {}),
    ...(input.resolveType !== undefined ? { resolveType: input.resolveType } : {}),
    ...(input.auditAllows !== undefined ? { auditAllows: input.auditAllows } : {}),
  });
  const revocation = new RevocationService(ctx, authorizer);
  const loginService = new LoginService(ctx);
  const refreshService = new RefreshService(ctx, revocation);
  const resolution = new ResolutionService(ctx);
  const assignments = new AssignmentService({
    rbac,
    authorizer,
    assignments: input.storage.assignments,
    users: input.storage.users,
    uow: input.storage.uow,
    clock: input.clock,
    ...(input.audit !== undefined ? { audit: input.audit } : {}),
    ids: input.ids,
    ...(input.guards !== undefined ? { guards: input.guards } : {}),
  });

  // INV-CFG-02: every insecure relaxation is announced at start-up.
  for (const w of config.warnings) {
    void emitAudit(ctx, {
      type: 'config.warning',
      severity: 'warning',
      reason: 'insecure_option',
      details: { path: w.path, message: w.message },
    });
  }

  const listSessions = async (
    principal: Principal,
    userId?: Id,
  ): Promise<readonly SessionView[]> => {
    const target = userId ?? principal.id;
    if (target !== principal.id) {
      // session.md §7.3: acting on another subject's sessions requires authorization.
      await authorizer.assert(principal, 'read', { type: 'session', id: target, ownerId: target });
    }
    const page = await input.storage.sessions.listActiveByUser(
      target,
      { limit: 100 },
      input.clock.now(),
    );
    return page.items.map((s) => ({
      id: s.id,
      createdAt: s.createdAt,
      lastSeenAt: s.lastSeenAt,
      authMethod: s.authMethod,
      ...(s.device !== undefined ? { device: s.device } : {}),
      current: s.id === principal.sessionId,
    }));
  };

  return {
    authn: {
      register: (i) => loginService.register(i),
      login: (i) => loginService.login(i),
      refresh: (i) => refreshService.refresh(i),
      resolve: (t) => resolution.resolve(t),
      authenticate: (t) => resolution.authenticate(t),
      logout: (i) => revocation.logout(i),
      logoutAll: (p, o) => revocation.logoutAll(p, o ?? {}),
      revokeSession: (a, s) => revocation.revokeSession(a, s),
      invalidateCredentials: (a, u) => revocation.invalidateCredentials(a, u),
      listSessions,
    },
    authz: {
      can: (s, a, r) => authorizer.can(s, a, r),
      authorize: (s, a, r, o) => authorizer.authorize(s, a, r, o ?? {}),
      assert: (s, a, r) => authorizer.assert(s, a, r),
      authorizeScope: (s, a, t) => authorizer.authorizeScope(s, a, t),
      permissionsFor: (s) => rbac.permissionsFor(s),
      rolesFor: (s) => rbac.rolesFor(s),
      hasRole: (s, r) => rbac.hasRole(s, r),
      roles: {
        assign: (actor, target, i) => assignments.assign(actor, target, i),
        revoke: (actor, target, r) => assignments.unassign(actor, target, r),
        listFor: (actor, target) => assignments.listFor(actor, target),
      },
    },
    doctor: () => [
      ...input.catalog.lint(),
      ...authorizer.lint().map((f) => ({ ...f, severity: f.severity as 'warning' | 'info' })),
      ...config.warnings.map((w) => ({
        finding: 'insecure_option' as const,
        severity: 'warning' as const,
        path: w.path,
        message: w.message,
      })),
    ],
    describe: () => ({
      catalogVersion: input.catalog.version,
      features: input.catalog.features,
      identifiers: config.identifiers,
      passwordMinLength: config.passwordMinLength,
      accountStates: config.accountStates.states.map((s) => s.name),
      sessions: config.sessions,
      tokens: config.tokens,
      revocationApplied: 'strict (spec/auth/tokens.md §2.5)',
      revealRestrictedState: config.revealRestrictedState,
      enumerationSafeRegistration: config.enumerationSafeRegistration,
      throttleFailMode: config.throttleFailMode,
      strictPolicies: input.strictPolicies ?? false,
      secrets: '[redacted]',
    }),
  };
}

/** Throws UNAUTHENTICATED when a guard receives no Principal (errors.md §2). */
export function requireAuth(principal: Principal | null | undefined): Principal {
  if (!principal) throw authError('UNAUTHENTICATED');
  return principal;
}

export { Catalog };
export * from './config.js';
export * from './digest.js';
export * from './jwt/keyProvider.js';
export * from './jwt/jwtProvider.js';
export * from './jwt/keySealing.js';
export * from './jwt/persistentKeyProvider.js';
export * from './jwt/jwks.js';
export * from './issue.js';
export * from './login.js';
export * from './refresh.js';
export * from './resolve.js';
export * from './revoke.js';
