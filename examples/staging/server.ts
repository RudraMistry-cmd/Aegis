// Staging server: Aegis on PostgreSQL with durable RS256 keys, the Express adapter, and Prometheus
// metrics on a separate internal port. Run by docker-compose.yml; see docs/STAGING.md.
//
// Environment (no defaults for secrets):
//   DATABASE_URL         required  postgres://user:pass@host:5432/db (migrations already applied)
//   AEGIS_MASTER_KEY     required  32 bytes as 64 hex chars; seals the private signing keys
//   PORT                 3000      public HTTP port (auth routes + JWKS)
//   METRICS_PORT         9464      internal port serving only GET /metrics
//   AEGIS_GENERATE_KEY   true      create the first signing key if the key store is EMPTY
//   STAGING_SEED_EMAIL / STAGING_SEED_PASSWORD   optional smoke-test user (role "user")
import { createServer } from 'node:http';
import { createExpressApp } from '../../src/adapters/express/index.js';
import {
  createAegisMetrics,
  createAuth,
  CryptoIdGenerator,
  CryptoRandom,
  defineCatalog,
  instrumentAuth,
  isAuthError,
  MemoryRateLimiter,
  metricsHandler,
  openJwtAccessTokens,
  ScryptHasher,
  SYSTEM_ACTOR,
  SystemClock,
  watchKeyRotations,
} from '../../src/index.js';
import { createPostgresStorage, PostgresAuditSink } from '../../src/storage/postgres/index.js';

const env = process.env;
const databaseUrl = env['DATABASE_URL'];
if (!databaseUrl) {
  console.error('[staging] DATABASE_URL is required');
  process.exit(1);
}
const port = Number(env['PORT'] ?? 3000);
const metricsPort = Number(env['METRICS_PORT'] ?? 9464);

const clock = new SystemClock();
const ids = new CryptoIdGenerator();
const storage = createPostgresStorage({ connectionString: databaseUrl });

// Fails with CONFIG_INVALID (and the process exits) when AEGIS_MASTER_KEY is missing or weak, or
// when the store has no usable active key: no silent fallback.
const tokens = await openJwtAccessTokens(
  {
    tokens: {
      algorithm: 'RS256',
      issuer: 'aegis-staging',
      audience: 'aegis-staging-api',
      ttl: 15 * 60_000,
    },
    keys: {
      rotationEnabled: true,
      storage: 'postgres',
      generateIfMissing: (env['AEGIS_GENERATE_KEY'] ?? 'true') === 'true',
      jwks: { cacheTtlSec: 300 },
    },
  },
  { keyStore: storage.keys, clock, ids },
);

const catalog = defineCatalog({
  permissions: ['profile:read'],
  roles: { user: { permissions: ['profile:read'] } },
});

const metrics = createAegisMetrics();
const core = createAuth({
  storage,
  hasher: new ScryptHasher({ N: 1 << 15 }),
  accessTokens: tokens.accessTokens,
  clock,
  random: new CryptoRandom(),
  ids,
  rateLimiter: new MemoryRateLimiter(),
  audit: new PostgresAuditSink(storage.client),
  catalog,
  identifiers: ['email'],
});
const auth = instrumentAuth(core, metrics);
watchKeyRotations(() => tokens.keys.getActiveKey().kid, metrics);

// Optional smoke-test user. Idempotent: registration of an existing email is accepted silently
// (enumeration-safe) and a repeated role assignment is a no-op.
const seedEmail = env['STAGING_SEED_EMAIL'];
const seedPassword = env['STAGING_SEED_PASSWORD'];
if (seedEmail && seedPassword) {
  try {
    await core.authn.register({ identifier: seedEmail, password: seedPassword });
  } catch (e) {
    if (!isAuthError(e) || e.code !== 'CONFLICT') throw e;
  }
  const row = await storage.identifiers.findByNormalized('email', seedEmail.trim().toLowerCase());
  if (row) {
    await core.authz.roles.assign({ id: SYSTEM_ACTOR, type: 'user' }, row.userId, {
      roleName: 'user',
    });
    console.log(`[staging] seed user ready: ${seedEmail}`);
  }
}

const app = createExpressApp({ auth, jwks: tokens.jwks });
app.set('trust proxy', 'loopback, linklocal, uniquelocal');
const server = app.listen(port, () => console.log(`[staging] auth API on :${port}`));
const serveMetrics = metricsHandler(metrics);
const metricsServer = createServer((req, res) => {
  if ((req.url ?? '').split('?')[0] === '/metrics') serveMetrics(req, res);
  else res.writeHead(404).end();
}).listen(metricsPort, () => console.log(`[staging] metrics on :${metricsPort}/metrics`));

const shutdown = (): void => {
  tokens.keys.close();
  metricsServer.close();
  server.close(() => void storage.close().then(() => process.exit(0)));
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
