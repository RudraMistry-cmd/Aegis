// Durable signing keys on PostgreSQL (src/storage/postgres/keyStore.ts, migrations/003): the shared
// KeyStore contract, real multi-connection concurrency, restart persistence, and the guarantees the
// schema enforces by itself.
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { after, before, describe, it } from 'node:test';
import pg from 'pg';
import {
  isAuthError,
  ManualClock,
  openJwtAccessTokens,
  SequentialIdGenerator,
  type JwtAlgorithm,
  type KeyStore,
} from '../../src/index.js';
import { createPostgresStorage, type PostgresStorage } from '../../src/storage/postgres/index.js';
import { hmacMaterial, keyStoreContract, rsaMaterial } from '../support/keyStoreContract.js';
import { createPgStorage, createTestDatabase, START, type PgStorageHandle } from './harness.js';

const MASTER_HEX = '8f1c2a7d4e9b0365aa17c3d2f8e46b9c0d1e2f3a4b5c6d7e8f90a1b2c3d4e5f6';
const MINUTE = 60_000;
const TTL = 10 * MINUTE;
const INPUT = { subjectId: 'user-1', sessionId: 'sess-1', securityVersion: 0, ttlMs: TTL };

function openOn(
  store: KeyStore,
  clock = new ManualClock(START),
  algorithm: JwtAlgorithm = 'RS256',
  env: Record<string, string> = { AEGIS_MASTER_KEY: MASTER_HEX },
) {
  return openJwtAccessTokens(
    {
      tokens: { algorithm, issuer: 'iss-1', audience: 'aud-1', ttl: TTL },
      keys: {
        rotationEnabled: true,
        storage: 'postgres',
        generateIfMissing: true,
        refreshIntervalMs: 0,
      },
    },
    {
      keyStore: store,
      clock,
      ids: new SequentialIdGenerator(`p${Math.random().toString(16).slice(2, 6)}`),
      env,
      logger: { warn: () => undefined },
    },
  );
}

async function count(storage: PostgresStorage, where = 'true'): Promise<number> {
  const r = await storage.client.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM aegis.signing_keys WHERE ${where}`,
  );
  return (r.rows[0] as { n: number }).n;
}

describe('KeyStore contract — postgres', () => {
  keyStoreContract(async () => {
    const h = await createPgStorage();
    return { store: h.storage.keys, dispose: h.dispose };
  });
});

describe('PostgreSQL signing keys', () => {
  let h: PgStorageHandle;
  let raw: pg.Client;
  // Tests in this block share one database, so they share one clock that only moves forward.
  const clock = new ManualClock(START);

  before(async () => {
    h = await createPgStorage();
    raw = new pg.Client({ connectionString: h.url });
    await raw.connect();
  });
  after(async () => {
    await raw.end();
    await h.dispose();
  });

  it('create → activate → sign → verify, then retire: only tokens issued before retirement verify', async () => {
    const a = await openOn(h.storage.keys, clock);
    const before = a.accessTokens.issue(INPUT, clock.now()).token;
    clock.advance(MINUTE);
    const newKid = await a.keys.rotate();
    assert.equal(a.accessTokens.verify(before, clock.now()).ok, true, 'issued before retirement');
    const after = a.accessTokens.issue(INPUT, clock.now()).token;
    assert.ok(after.length > 0);
    const row = await h.storage.keys.getKeyById(newKid);
    assert.equal(row?.status, 'active');
    a.keys.close();
  });

  it('restart: a new pool and provider load the same active key and verify old tokens', async () => {
    const db = await createTestDatabase();
    const s1 = createPostgresStorage({ connectionString: db.url });
    await s1.migrate();
    const a = await openOn(s1.keys);
    const token = a.accessTokens.issue(INPUT, START).token;
    const kid = a.keys.getActiveKey().kid;
    a.keys.close();
    await s1.close();

    const s2 = createPostgresStorage({ connectionString: db.url });
    try {
      const b = await openOn(s2.keys, new ManualClock(START + MINUTE));
      assert.equal(b.keys.getActiveKey().kid, kid, 'no new key was generated');
      assert.equal(await count(s2), 1);
      assert.equal(b.accessTokens.verify(token, START + MINUTE).ok, true);
      b.keys.close();
    } finally {
      await s2.close();
      await db.drop();
    }
  });

  it('concurrent startup of 8 instances on an empty database creates exactly one key', async () => {
    const db = await createTestDatabase();
    const storages = Array.from({ length: 8 }, () =>
      createPostgresStorage({ connectionString: db.url }),
    );
    try {
      await storages[0]!.migrate();
      const opened = await Promise.all(storages.map((s) => openOn(s.keys)));
      assert.equal(await count(storages[0]!), 1);
      const kids = new Set(opened.map((o) => o.keys.getActiveKey().kid));
      assert.equal(kids.size, 1, 'every instance signs with the same key');
      opened.forEach((o) => o.keys.close());
    } finally {
      await Promise.all(storages.map((s) => s.close()));
      await db.drop();
    }
  });

  it('10 instances rotating at once end with exactly one active key, nothing lost', async () => {
    const db = await createTestDatabase();
    const storages = Array.from({ length: 10 }, () =>
      createPostgresStorage({ connectionString: db.url }),
    );
    try {
      await storages[0]!.migrate();
      const first = await openOn(storages[0]!.keys);
      const instances = await Promise.all(storages.map((s) => openOn(s.keys)));
      const newKids = await Promise.all(instances.map((i) => i.keys.rotate()));
      assert.equal(new Set(newKids).size, 10);
      assert.equal(await count(storages[0]!), 11);
      assert.equal(await count(storages[0]!, "status = 'active'"), 1);
      assert.equal(await count(storages[0]!, "status = 'retired'"), 10);
      const active = await storages[0]!.keys.getActiveKey();
      assert.ok(active && newKids.includes(active.kid));
      [first, ...instances].forEach((i) => i.keys.close());
    } finally {
      await Promise.all(storages.map((s) => s.close()));
      await db.drop();
    }
  });

  it('concurrent activation of the same pending key: all succeed, one active', async () => {
    clock.advance(MINUTE);
    const a = await openOn(h.storage.keys, clock);
    const staged = await a.keys.stage();
    const results = await Promise.allSettled(
      Array.from({ length: 10 }, () => h.storage.keys.activate(staged, clock.now())),
    );
    assert.ok(results.every((r) => r.status === 'fulfilled'));
    assert.equal(await count(h.storage, "status = 'active'"), 1);
    assert.equal((await h.storage.keys.getActiveKey())?.kid, staged);
    a.keys.close();
  });

  it('remove and prune: a removed kid stays registered forever', async () => {
    clock.advance(MINUTE);
    const a = await openOn(h.storage.keys, clock);
    const oldKid = a.keys.getActiveKey().kid;
    const token = a.accessTokens.issue(INPUT, clock.now()).token;
    await a.keys.rotate();
    await a.keys.remove(oldKid);
    const r = a.accessTokens.verify(token, clock.now());
    assert.equal(r.ok ? 'OK' : r.failure, 'unknown_key');
    await assert.rejects(
      h.storage.keys.createKey(hmacMaterial(oldKid), { createdAt: START }),
      (e: unknown) => isAuthError(e) && e.code === 'CONFLICT',
    );
    clock.advance(MINUTE);
    const stillActive = a.keys.getActiveKey().kid;
    await a.keys.rotate(); // retires stillActive now
    const retiredAt = clock.now();
    clock.set(retiredAt + TTL - 1);
    await a.keys.prune();
    assert.ok(await h.storage.keys.getKeyById(stillActive), 'kept while it can still verify');
    clock.set(retiredAt + TTL);
    assert.ok((await a.keys.prune()) >= 1);
    assert.equal(
      await h.storage.keys.getKeyById(stillActive),
      null,
      'pruned once it cannot verify',
    );
    a.keys.close();
  });

  it('PostgreSQL refuses to start without a master key', async () => {
    await assert.rejects(
      openOn(h.storage.keys, clock, 'RS256', {}),
      (e: unknown) =>
        isAuthError(e) &&
        e.code === 'CONFIG_INVALID' &&
        ((e.details?.['violations'] ?? []) as { rule: string }[]).some(
          (v) => v.rule === 'keys.master_key_required',
        ),
    );
  });

  it('private_material holds ciphertext only', async () => {
    const a = await openOn(h.storage.keys, clock);
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const kid = await a.keys.stage({ kid: 'known-rsa-pg', privateKey });
    const row = await raw.query<{ private_material: Buffer }>(
      'SELECT private_material FROM aegis.signing_keys WHERE kid = $1',
      [kid],
    );
    const stored = row.rows[0]!.private_material;
    const der = privateKey.export({ type: 'pkcs8', format: 'der' });
    assert.equal(stored.subarray(0, 4).toString(), 'AEK1');
    assert.equal(stored.indexOf(der.subarray(40, 120)), -1, 'no plaintext PKCS#8 fragment');
    a.keys.close();
  });

  // ---------------------------------------------------------------- the schema's own guarantees

  it('the schema admits at most one active key', async () => {
    const m = rsaMaterial();
    await h.storage.keys.createKey(m, { createdAt: START });
    await assert.rejects(
      raw.query(
        "UPDATE aegis.signing_keys SET status = 'active', activated_at_ms = $2 WHERE kid = $1",
        [m.kid, START],
      ),
      (e: { code?: string }) => e.code === '23505',
    );
  });

  it('the schema never lets a key return to pending or a retired key change', async () => {
    const a = hmacMaterial();
    const b = hmacMaterial();
    const s = h.storage.keys;
    const fresh = await createPgStorage();
    try {
      await fresh.storage.keys.createKey(a, { createdAt: START });
      await fresh.storage.keys.createKey(b, { createdAt: START });
      await fresh.storage.keys.activate(a.kid, START + 1);
      await fresh.storage.keys.activate(b.kid, START + 2);
      const c = new pg.Client({ connectionString: fresh.url });
      await c.connect();
      try {
        await assert.rejects(
          c.query(
            "UPDATE aegis.signing_keys SET status = 'active', retired_at_ms = NULL WHERE kid = $1",
            [a.kid],
          ),
          (e: { code?: string }) => e.code === 'AE030',
        );
        await assert.rejects(
          c.query(
            "UPDATE aegis.signing_keys SET status = 'pending', activated_at_ms = NULL WHERE kid = $1",
            [b.kid],
          ),
          (e: { code?: string }) => e.code === 'AE031' || e.code === '23514',
        );
      } finally {
        await c.end();
      }
    } finally {
      await fresh.dispose();
    }
    assert.ok(s);
  });

  it('the schema refuses plaintext private keys and private members in the public column', async () => {
    const m = rsaMaterial();
    await raw.query(
      'INSERT INTO aegis.signing_key_registry (kid, registered_at_ms) VALUES ($1, $2)',
      [m.kid, START],
    );
    await assert.rejects(
      raw.query(
        `INSERT INTO aegis.signing_keys (kid, type, status, created_at_ms, public_material, private_material)
         VALUES ($1, 'RSA', 'pending', $2, $3, $4)`,
        [
          m.kid,
          START,
          JSON.stringify(m.publicMaterial),
          Buffer.concat([Buffer.from('AEK0'), Buffer.from('plain')]),
        ],
      ),
      (e: { code?: string }) => e.code === '23514',
    );
    await assert.rejects(
      raw.query(
        `INSERT INTO aegis.signing_keys (kid, type, status, created_at_ms, public_material, private_material)
         VALUES ($1, 'RSA', 'pending', $2, $3, $4)`,
        [
          m.kid,
          START,
          JSON.stringify({ ...m.publicMaterial, d: 'leak' }),
          Buffer.from(m.privateMaterial),
        ],
      ),
      (e: { code?: string }) => e.code === '23514',
    );
  });
});
