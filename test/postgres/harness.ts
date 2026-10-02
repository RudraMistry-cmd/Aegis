// Test harness for the PostgreSQL adapter: one fresh database per caller, plus a full Aegis system
// wired over it with the same fixtures as the Phase 1 suite (catalog F-CAT, controllable clock).
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import {
  createAuth,
  CryptoRandom,
  ManualClock,
  MemoryAuditSink,
  MemoryRateLimiter,
  ScryptHasher,
  SequentialIdGenerator,
  createJwtAccessTokens,
  SYSTEM_ACTOR,
  type Auth,
  type AuditSink,
  type Catalog,
  type Id,
  type Policy,
  type Principal,
} from '../../src/index.js';
import {
  createPostgresStorage,
  PostgresAuditSink,
  type PostgresConfig,
  type PostgresStorage,
} from '../../src/storage/postgres/index.js';
import { START, TEST_PASSWORD, testCatalog } from '../support/fixtures.js';

/** The admin connection string. The suite refuses to run silently without a database. */
export function adminUrl(): string {
  const url = process.env['AEGIS_PG_URL'];
  if (!url) {
    throw new Error(
      'AEGIS_PG_URL is not set. Run the PostgreSQL suite with `npm run test:pg`, which starts a ' +
        'throwaway server, or point AEGIS_PG_URL at a server you may create databases on.',
    );
  }
  return url;
}

export type Isolation = NonNullable<PostgresConfig['isolation']>;

export interface TestDatabase {
  readonly url: string;
  drop(): Promise<void>;
}

/** Creates an empty database with a random name on the admin server. */
export async function createTestDatabase(): Promise<TestDatabase> {
  const name = `aegis_t_${randomBytes(6).toString('hex')}`;
  const admin = new pg.Client({ connectionString: adminUrl() });
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${name}`);
  } finally {
    await admin.end();
  }
  const url = new URL(adminUrl());
  url.pathname = `/${name}`;
  return {
    url: url.toString(),
    drop: async () => {
      const c = new pg.Client({ connectionString: adminUrl() });
      await c.connect();
      try {
        await c.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      } finally {
        await c.end();
      }
    },
  };
}

export interface PgStorageHandle {
  readonly storage: PostgresStorage;
  readonly url: string;
  /** Closes the pool and drops the database. */
  dispose(): Promise<void>;
}

/** A migrated PostgreSQL storage on its own fresh database. */
export async function createPgStorage(
  config: Partial<Omit<PostgresConfig, 'connectionString'>> = {},
): Promise<PgStorageHandle> {
  const db = await createTestDatabase();
  const storage = createPostgresStorage({
    connectionString: db.url,
    maxConnections: 20,
    ids: new SequentialIdGenerator(`s${randomBytes(3).toString('hex')}`),
    ...config,
  });
  await storage.migrate();
  return {
    storage,
    url: db.url,
    dispose: async () => {
      await storage.close().catch(() => undefined);
      await db.drop();
    },
  };
}

export interface PgSystemOptions {
  readonly isolation?: Isolation;
  readonly catalog?: Catalog;
  readonly policies?: readonly Policy[];
  readonly sessions?: {
    max?: number | null;
    onLimit?: 'evict-oldest' | 'reject';
    idleTtlMs?: number;
    absoluteTtlMs?: number;
  };
  readonly tokens?: { accessTtlMs?: number; refreshIdleTtlMs?: number; reuseGraceMs?: number };
  /** Persist audit events to PostgreSQL instead of memory. */
  readonly pgAudit?: boolean;
  readonly maxTransactionAttempts?: number;
}

export interface PgSystem {
  readonly auth: Auth;
  readonly clock: ManualClock;
  readonly storage: PostgresStorage;
  readonly audit: AuditSink;
  readonly memoryAudit: MemoryAuditSink | null;
  readonly catalog: Catalog;
  createUser(identifier: string, roles?: readonly string[]): Promise<Id>;
  login(
    identifier: string,
  ): Promise<{ principal: Principal; accessToken: string; refreshToken: string }>;
  dispose(): Promise<void>;
}

/** A complete Aegis system over PostgreSQL, mirroring test/support/fixtures.ts. */
export async function createPgSystem(options: PgSystemOptions = {}): Promise<PgSystem> {
  const handle = await createPgStorage({
    ...(options.isolation !== undefined ? { isolation: options.isolation } : {}),
    ...(options.maxTransactionAttempts !== undefined
      ? { maxTransactionAttempts: options.maxTransactionAttempts }
      : {}),
  });
  const { storage } = handle;
  const clock = new ManualClock(START);
  const ids = new SequentialIdGenerator(`t${randomBytes(3).toString('hex')}`);
  const memoryAudit = options.pgAudit ? null : new MemoryAuditSink();
  const audit: AuditSink = memoryAudit ?? new PostgresAuditSink(storage.client);
  const catalog = options.catalog ?? testCatalog();
  const { accessTokens } = createJwtAccessTokens(
    {
      tokens: { algorithm: 'HS256', issuer: 'aegis-test', audience: 'aegis-test-api' },
      keys: { rotationEnabled: true },
    },
    {
      keys: [{ kid: 'test-key-1', secret: 'test-secret-value-of-at-least-32-bytes!!' }],
      clock,
      ids,
    },
  );
  const auth = createAuth({
    storage,
    hasher: new ScryptHasher({ N: 1 << 12, maxConcurrency: 8 }),
    accessTokens,
    clock,
    random: new CryptoRandom(),
    ids,
    audit,
    rateLimiter: new MemoryRateLimiter([
      // Concurrency tests hammer one identifier on purpose; keep the throttle out of their way.
      { prefix: 'login', rule: { max: 100_000, windowMs: 60_000 } },
    ]),
    catalog,
    ...(options.policies !== undefined ? { policies: options.policies } : {}),
    identifiers: ['email', 'username'],
    sessions: options.sessions ?? {},
    tokens: options.tokens ?? {},
  });

  const createUser = async (identifier: string, roles: readonly string[] = []): Promise<Id> => {
    await auth.authn.register({ identifier, password: TEST_PASSWORD, identifierType: 'email' });
    const row = await storage.identifiers.findByNormalized('email', identifier.toLowerCase());
    if (!row) throw new Error(`harness: user ${identifier} was not created`);
    const user = await storage.users.getById(row.userId);
    if (user && user.status !== 'active') {
      await storage.users.setStatus(row.userId, 'active', user.version, clock.now());
    }
    for (const r of roles) {
      await auth.authz.roles.assign({ id: SYSTEM_ACTOR, type: 'user' }, row.userId, {
        roleName: r,
      });
    }
    return row.userId;
  };

  const login = async (identifier: string) => {
    const r = await auth.authn.login({ identifier, password: TEST_PASSWORD });
    return {
      principal: r.principal,
      accessToken: r.credentials.accessToken,
      refreshToken: r.credentials.refreshToken,
    };
  };

  return {
    auth,
    clock,
    storage,
    audit,
    memoryAudit,
    catalog,
    createUser,
    login,
    dispose: async () => {
      if (audit instanceof PostgresAuditSink) await audit.flush();
      await handle.dispose();
    },
  };
}

/** Runs `n` copies of `fn` concurrently, all released at the same instant. */
export async function inParallel<T>(
  n: number,
  fn: (i: number) => Promise<T>,
): Promise<PromiseSettledResult<T>[]> {
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const runs = Array.from({ length: n }, (_, i) => gate.then(() => fn(i)));
  release();
  return Promise.allSettled(runs);
}

export { START, TEST_PASSWORD };
