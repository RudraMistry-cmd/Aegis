// Signing-key operations for staging, against the same PostgreSQL key store the app uses. Every
// command goes through PersistentKeyProvider, so the lifecycle rules (one active key, no kid reuse,
// retired keys verify only inside their window) are enforced exactly as in the app.
//
//   node dist/examples/staging/keys.js list
//   node dist/examples/staging/keys.js stage              # new PENDING key (published in JWKS)
//   node dist/examples/staging/keys.js activate <kid>     # pending -> active; previous active retired now
//   node dist/examples/staging/keys.js rotate             # stage + activate at once (single instance / emergency)
//   node dist/examples/staging/keys.js remove <kid>       # compromised key: stops verifying everywhere
//   node dist/examples/staging/keys.js prune              # delete retired keys past ttl + leeway
//
// Requires DATABASE_URL and AEGIS_MASTER_KEY (the same values as the app). Running instances pick
// up changes within their key refresh interval (30 s by default).
import {
  CryptoIdGenerator,
  openJwtAccessTokens,
  SystemClock,
  type PersistentKeyProvider,
} from '../../src/index.js';
import { createPostgresStorage } from '../../src/storage/postgres/index.js';

const [command, kid] = process.argv.slice(2);
const usage = 'usage: keys.js list | stage | activate <kid> | rotate | remove <kid> | prune';

const databaseUrl = process.env['DATABASE_URL'];
if (!databaseUrl || !command) {
  console.error(databaseUrl ? usage : 'DATABASE_URL is required');
  process.exit(2);
}

const storage = createPostgresStorage({ connectionString: databaseUrl });
try {
  // Must match examples/staging/server.ts: the retired-key window is ttl + leeway.
  const { keys } = await openJwtAccessTokens(
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
        generateIfMissing: false,
        refreshIntervalMs: 0,
      },
    },
    { keyStore: storage.keys, clock: new SystemClock(), ids: new CryptoIdGenerator() },
  );
  const p: PersistentKeyProvider = keys;
  const needKid = (): string => {
    if (!kid) {
      console.error(usage);
      process.exit(2);
    }
    return kid;
  };
  switch (command) {
    case 'list':
      break;
    case 'stage':
      console.log(`staged ${await p.stage()}`);
      break;
    case 'activate':
      await p.activate(needKid());
      console.log(`activated ${kid}`);
      break;
    case 'rotate':
      console.log(`rotated; active is now ${await p.rotate()}`);
      break;
    case 'remove':
      await p.remove(needKid());
      console.log(`removed ${kid}`);
      break;
    case 'prune':
      console.log(`pruned ${await p.prune()} key(s)`);
      break;
    default:
      console.error(usage);
      process.exitCode = 2;
  }
  await p.refresh();
  // Metadata only: kid, algorithm, status and timestamps. Never key material.
  console.table(p.list());
  p.close();
} catch (e) {
  const err = e as { code?: string; details?: unknown };
  console.error(`failed: ${err.code ?? 'error'}`, err.details ? JSON.stringify(err.details) : '');
  process.exitCode = 1;
} finally {
  await storage.close();
}
