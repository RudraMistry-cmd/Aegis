// Shared test fixtures: the F-CAT catalog, F-USERS users and F-POL policies of
// spec/conformance.md §4, wired over the in-memory adapter with a controllable clock.
import {
  createAuth,
  createMemoryStorage,
  CryptoRandom,
  defineCatalog,
  definePolicy,
  ManualClock,
  MemoryAuditSink,
  MemoryRateLimiter,
  ScryptHasher,
  SequentialIdGenerator,
  StubAccessTokenProvider,
  SYSTEM_ACTOR,
  type Auth,
  type AttributeProvider,
  type Catalog,
  type Id,
  type Json,
  type MemoryStorage,
  type Policy,
  type Principal,
} from '../../src/index.js';

export const TEST_PASSWORD = 'correct-horse-battery-staple';
export const START = Date.UTC(2030, 0, 1);
export const MINUTE = 60_000;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;

/** F-CAT (conformance.md §4) with every optional feature enabled. */
export function testCatalog(): Catalog {
  return defineCatalog({
    permissions: [
      'post:read',
      'post:update',
      'post:delete',
      'project:read',
      'project:update',
      'project:delete',
      'user:read',
      'user:update',
      'user:delete',
      'role:assign',
      'role:revoke',
      'role:read',
      'session:read',
      'session:revoke',
      'account:setstatus',
    ],
    features: { hierarchy: true, deny: true, wildcards: true },
    roles: {
      viewer: { permissions: ['post:read', 'project:read'] },
      editor: { inherits: ['viewer'], permissions: ['post:update', 'project:update'] },
      admin: {
        inherits: ['editor'],
        permissions: [
          'user:*',
          'post:delete',
          'project:delete',
          'role:assign',
          'role:revoke',
          'role:read',
          'session:read',
          'session:revoke',
          'account:setstatus',
        ],
      },
      contractor: { inherits: ['editor'], deny: ['post:delete', 'project:delete'] },
      root: { permissions: ['*:*'], superuser: true },
      auditor: { permissions: ['user:read', 'role:read'] },
    },
  });
}

/** F-POL: the `post` ownership policy. */
export function postPolicy(): Policy {
  return definePolicy({
    name: 'post',
    resource: 'post',
    mode: 'rbacAndPolicy',
    rules: {
      update: ({ subject, resource }) => resource['authorId'] === subject.id,
      delete: ({ subject, resource }) =>
        resource['authorId'] === subject.id || subject.attributes?.['moderator'] === true,
    },
    scope: {
      update: ({ subject }) => ({ op: 'eq', field: 'authorId', value: subject.id }),
    },
  });
}

/** F-POL: the tenant wall. */
export function tenantWall(): Policy {
  return definePolicy({
    name: 'tenant-wall',
    resource: '*',
    rules: {
      '*': ({ subject, resource }) =>
        subject.tenantId !== undefined && resource['tenantId'] === subject.tenantId,
    },
    scope: {
      '*': ({ subject }) => ({ op: 'eq', field: 'tenantId', value: subject.tenantId ?? null }),
    },
  });
}

/** A configurable AttributeProvider so tests can supply tenant ids and ABAC attributes. */
export class FakeAttributeProvider implements AttributeProvider {
  readonly byUser = new Map<Id, { tenantId?: Id; attributes: Record<string, Json> }>();
  failNext = false;

  async attributesFor(userId: Id): Promise<{ tenantId?: Id; attributes: Record<string, Json> }> {
    if (this.failNext) {
      this.failNext = false;
      throw new Error('attribute provider unavailable');
    }
    return this.byUser.get(userId) ?? { attributes: {} };
  }
}

export interface TestSystemOptions {
  readonly policies?: readonly Policy[];
  readonly sessions?: {
    max?: number | null;
    onLimit?: 'evict-oldest' | 'reject';
    idleTtlMs?: number;
    absoluteTtlMs?: number;
  };
  readonly tokens?: { accessTtlMs?: number; refreshIdleTtlMs?: number; reuseGraceMs?: number };
  readonly strictPolicies?: boolean;
  readonly withRateLimiter?: boolean;
  readonly revealRestrictedState?: boolean;
  readonly enumerationSafeRegistration?: boolean;
  readonly catalog?: Catalog;
}

export interface TestSystem {
  readonly auth: Auth;
  readonly clock: ManualClock;
  readonly storage: MemoryStorage;
  readonly audit: MemoryAuditSink;
  readonly hasher: ScryptHasher;
  readonly limiter: MemoryRateLimiter;
  readonly attributes: FakeAttributeProvider;
  readonly catalog: Catalog;
  /** Registers a user and returns its id, optionally assigning roles as the system actor. */
  createUser(identifier: string, roles?: readonly string[], status?: string): Promise<Id>;
  /** Logs in and returns the Principal plus credentials. */
  login(
    identifier: string,
  ): Promise<{ principal: Principal; accessToken: string; refreshToken: string }>;
  /** Sets the account status directly (the state-change flow is not part of Phase 1's public API). */
  setStatus(userId: Id, status: string): Promise<void>;
}

/** Builds a complete in-memory system. */
export function createTestSystem(options: TestSystemOptions = {}): TestSystem {
  const clock = new ManualClock(START);
  const ids = new SequentialIdGenerator('t');
  const storage = createMemoryStorage(new SequentialIdGenerator('s'));
  const audit = new MemoryAuditSink();
  // Deliberately weak scrypt parameters: tests need speed, not resistance.
  const hasher = new ScryptHasher({ N: 1 << 12, maxConcurrency: 4 });
  const limiter = new MemoryRateLimiter();
  const attributes = new FakeAttributeProvider();
  const catalog = options.catalog ?? testCatalog();
  const accessTokens = new StubAccessTokenProvider({
    secret: 'test-secret-value-of-at-least-32-bytes!!',
    issuer: 'aegis-test',
    audience: 'aegis-test-api',
    ids,
  });

  const auth = createAuth({
    storage,
    hasher,
    accessTokens,
    clock,
    random: new CryptoRandom(),
    ids,
    audit,
    attributes,
    catalog,
    ...(options.policies !== undefined ? { policies: options.policies } : {}),
    ...(options.strictPolicies !== undefined ? { strictPolicies: options.strictPolicies } : {}),
    ...(options.withRateLimiter === false ? {} : { rateLimiter: limiter }),
    ...(options.revealRestrictedState !== undefined
      ? { revealRestrictedState: options.revealRestrictedState }
      : {}),
    ...(options.enumerationSafeRegistration !== undefined
      ? { enumerationSafeRegistration: options.enumerationSafeRegistration }
      : {}),
    identifiers: ['email', 'username'],
    sessions: options.sessions ?? {},
    tokens: options.tokens ?? {},
  });

  const createUser = async (
    identifier: string,
    roles: readonly string[] = [],
    status = 'active',
  ): Promise<Id> => {
    const type = identifier.includes('@') ? 'email' : 'username';
    await auth.authn.register({ identifier, password: TEST_PASSWORD, identifierType: type });
    const normalized = identifier.trim().normalize('NFKC').toLowerCase();
    const row = await storage.identifiers.findByNormalized(type, normalized);
    if (!row) throw new Error(`fixture: user ${identifier} was not created`);
    const userId = row.userId;
    const user = await storage.users.getById(userId);
    if (!user) throw new Error('fixture: user row missing');
    if (user.status !== status) {
      await storage.users.setStatus(userId, status, user.version, clock.now());
    }
    for (const r of roles) {
      await auth.authz.roles.assign({ id: SYSTEM_ACTOR, type: 'user' }, userId, { roleName: r });
    }
    return userId;
  };

  const login = async (
    identifier: string,
  ): Promise<{ principal: Principal; accessToken: string; refreshToken: string }> => {
    const r = await auth.authn.login({ identifier, password: TEST_PASSWORD });
    return {
      principal: r.principal,
      accessToken: r.credentials.accessToken,
      refreshToken: r.credentials.refreshToken,
    };
  };

  const setStatus = async (userId: Id, status: string): Promise<void> => {
    const user = await storage.users.getById(userId);
    if (!user) throw new Error('fixture: unknown user');
    await storage.uow.run(async (tx) => {
      await tx.users.setStatus(userId, status, user.version, clock.now());
      const state = catalogState(status);
      if (state === 'no-login') {
        await tx.sessions.revokeAllForUser(userId, null, 'account_state', clock.now());
        await tx.users.bumpSecurityVersion(userId, clock.now());
      }
    });
  };

  return {
    auth,
    clock,
    storage,
    audit,
    hasher,
    limiter,
    attributes,
    catalog,
    createUser,
    login,
    setStatus,
  };
}

function catalogState(status: string): 'login' | 'no-login' {
  return status === 'suspended' || status === 'disabled' ? 'no-login' : 'login';
}
