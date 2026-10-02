// Durable signing keys (PersistentKeyProvider + openJwtAccessTokens): startup rules, persistence,
// rotation and retirement semantics, encryption at rest, and that strict revocation is unchanged.
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import {
  createAuth,
  createMemoryStorage,
  CryptoRandom,
  FileKeyStore,
  InMemoryKeyStore,
  isAuthError,
  ManualClock,
  openJwtAccessTokens,
  ScryptHasher,
  SequentialIdGenerator,
  type JwtAlgorithm,
  type KeyStore,
  type PersistentJwtConfigInput,
} from '../../src/index.js';
import { START, testCatalog } from '../support/fixtures.js';

const MASTER_HEX = '8f1c2a7d4e9b0365aa17c3d2f8e46b9c0d1e2f3a4b5c6d7e8f90a1b2c3d4e5f6';
const OTHER_MASTER_HEX = '11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff';
const MINUTE = 60_000;
const TTL = 10 * MINUTE;
const INPUT = { subjectId: 'user-1', sessionId: 'sess-1', securityVersion: 0, ttlMs: TTL };

let dir: string;
let fileNo = 0;
before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'aegis-pkeys-'));
});
after(async () => {
  await rm(dir, { recursive: true, force: true });
});
const freshFile = (): string => join(dir, `keys-${++fileNo}.json`);

/** Captures warnings instead of printing them. */
function captureLogger(): { warn(m: string): void; messages: string[] } {
  const messages: string[] = [];
  return { warn: (m: string) => messages.push(m), messages };
}

function config(
  store: KeyStore,
  overrides: Partial<PersistentJwtConfigInput['keys']> = {},
  algorithm: JwtAlgorithm = 'RS256',
): PersistentJwtConfigInput {
  return {
    tokens: { algorithm, issuer: 'iss-1', audience: 'aud-1', ttl: TTL },
    keys: {
      rotationEnabled: true,
      storage: store.kind,
      generateIfMissing: true,
      refreshIntervalMs: 0,
      ...overrides,
    },
  };
}

async function open(
  store: KeyStore,
  opts: {
    overrides?: Partial<PersistentJwtConfigInput['keys']>;
    algorithm?: JwtAlgorithm;
    master?: string | null;
    clock?: ManualClock;
    logger?: { warn(m: string): void };
  } = {},
) {
  const clock = opts.clock ?? new ManualClock(START);
  const opened = await openJwtAccessTokens(config(store, opts.overrides, opts.algorithm), {
    keyStore: store,
    clock,
    ids: new SequentialIdGenerator(`j${randomBytes(2).toString('hex')}`),
    env: opts.master === null ? {} : { AEGIS_MASTER_KEY: opts.master ?? MASTER_HEX },
    logger: opts.logger ?? captureLogger(),
  });
  return { ...opened, clock };
}

async function codeOf(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (e) {
    assert.ok(isAuthError(e), `expected an AuthError, got ${String(e)}`);
    return e.code;
  }
  return 'OK';
}

async function rulesOf(fn: () => Promise<unknown>): Promise<string[]> {
  try {
    await fn();
  } catch (e) {
    assert.ok(isAuthError(e) && e.code === 'CONFIG_INVALID', String(e));
    return ((e.details?.['violations'] ?? []) as { rule: string }[]).map((v) => v.rule);
  }
  assert.fail('expected CONFIG_INVALID');
}

const kidOf = (jwt: string): string =>
  (JSON.parse(Buffer.from(jwt.split('.')[0] as string, 'base64url').toString()) as { kid: string })
    .kid;

// ---------------------------------------------------------------- startup

describe('startup', () => {
  it('generateIfMissing creates exactly one active key, once', async () => {
    const store = new InMemoryKeyStore();
    const a = await open(store);
    const first = a.keys.list();
    assert.equal(first.length, 1);
    assert.equal(first[0]?.status, 'active');
    const b = await open(store);
    assert.deepEqual(
      b.keys.list().map((k) => k.kid),
      first.map((k) => k.kid),
      'no second key on restart',
    );
  });

  it('fails startup without an active key unless it may generate into an empty store', async () => {
    assert.ok(
      (
        await rulesOf(() =>
          open(new InMemoryKeyStore(), { overrides: { generateIfMissing: false } }),
        )
      ).includes('keys.no_active_key'),
    );

    // Keys exist but none is active: never generate "around" an operator's half-done rotation.
    const store = new InMemoryKeyStore();
    const a = await open(store);
    const active = a.keys.getActiveKey().kid;
    await a.keys.stage();
    await store.retire(active, START);
    assert.ok((await rulesOf(() => open(store))).includes('keys.no_active_key'));
    assert.equal((await store.listKeys()).length, 2, 'nothing generated');
  });

  it('rotation disabled: exactly one key, and every lifecycle operation is refused', async () => {
    const store = new InMemoryKeyStore();
    const a = await open(store, { overrides: { rotationEnabled: false } });
    assert.equal(await codeOf(() => a.keys.rotate()), 'VALIDATION_FAILED');
    assert.equal(await codeOf(() => a.keys.stage()), 'VALIDATION_FAILED');
    const b = await open(new InMemoryKeyStore());
    await b.keys.stage();
    // Re-open that two-key store with rotation disabled.
    const store2 = new InMemoryKeyStore();
    const c = await open(store2);
    await c.keys.stage();
    assert.ok(
      (await rulesOf(() => open(store2, { overrides: { rotationEnabled: false } }))).includes(
        'keys.rotation_disabled',
      ),
    );
  });

  it('rejects invalid configuration, listing every problem', async () => {
    const store = new InMemoryKeyStore();
    const rules = await rulesOf(() =>
      openJwtAccessTokens(
        {
          tokens: { algorithm: 'RS256', issuer: '', audience: 'a', ttl: TTL },
          keys: {
            rotationEnabled: true,
            storage: 'file',
            masterKeyEnvVar: 'not a var',
            refreshIntervalMs: -1,
          },
        },
        {
          keyStore: store,
          clock: new ManualClock(START),
          ids: new SequentialIdGenerator('x'),
          env: {},
        },
      ),
    );
    for (const r of [
      'jwt.issuer',
      'keys.storage_mismatch',
      'keys.master_key_var',
      'keys.refresh',
    ]) {
      assert.ok(rules.includes(r), `missing ${r} in ${rules.join(',')}`);
    }
  });
});

// ---------------------------------------------------------------- persistence and rotation

describe('persistence and rotation', () => {
  it('a token survives a restart: a new provider over the same file verifies it', async () => {
    const path = freshFile();
    const a = await open(new FileKeyStore(path));
    const token = a.accessTokens.issue(INPUT, a.clock.now()).token;
    a.keys.close();
    const b = await open(new FileKeyStore(path), { clock: new ManualClock(START + MINUTE) });
    assert.equal(b.accessTokens.verify(token, b.clock.now()).ok, true);
    assert.equal(b.keys.getActiveKey().kid, kidOf(token));
  });

  it('rotate: old tokens still verify, new tokens use the new kid', async () => {
    const a = await open(new InMemoryKeyStore());
    const old = a.accessTokens.issue(INPUT, a.clock.now()).token;
    a.clock.advance(MINUTE);
    const newKid = await a.keys.rotate();
    assert.equal(a.accessTokens.verify(old, a.clock.now()).ok, true);
    const fresh = a.accessTokens.issue(INPUT, a.clock.now()).token;
    assert.equal(kidOf(fresh), newKid);
    assert.notEqual(kidOf(old), newKid);
  });

  it('retire: tokens issued before retiredAt verify; anything minted after does not', async () => {
    const store = new InMemoryKeyStore();
    const material = { kid: 'hs-known', secret: 'known-secret-of-at-least-32-bytes-long!' };
    // HS256 so the test can forge a token with the "leaked" retired secret.
    const a = await open(store, {
      algorithm: 'HS256',
      overrides: { generateIfMissing: false },
    }).catch(() => null);
    assert.equal(a, null, 'empty store and no generation must fail');
    const g = await open(store, { algorithm: 'HS256' });
    await g.keys.rotate(material);
    const before = g.accessTokens.issue(INPUT, g.clock.now()).token;
    g.clock.advance(MINUTE);
    await g.keys.rotate(); // retires hs-known now
    assert.equal(g.accessTokens.verify(before, g.clock.now()).ok, true, 'issued before retirement');

    g.clock.advance(MINUTE);
    const iat = Math.floor(g.clock.now() / 1000);
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const input = `${b64({ alg: 'HS256', typ: 'at+jwt', kid: 'hs-known' })}.${b64({
      iss: 'iss-1',
      aud: 'aud-1',
      sub: 'user-1',
      sid: 'sess-1',
      iat,
      exp: iat + 600,
      jti: 'x',
      sv: 0,
      typ: 'at+jwt',
    })}`;
    const minted = `${input}.${createHmac('sha256', material.secret).update(input).digest('base64url')}`;
    const r = g.accessTokens.verify(minted, g.clock.now());
    assert.equal(r.ok ? 'OK' : r.failure, 'unknown_key');
  });

  it('retire refuses a future retirement time', async () => {
    const a = await open(new InMemoryKeyStore());
    const kid = await a.keys.stage();
    assert.equal(await codeOf(() => a.keys.retire(kid, a.clock.now() + 1)), 'VALIDATION_FAILED');
    assert.equal(await a.keys.retire(kid), true);
  });

  it('a staged key verifies before it signs; activate switches the signer', async () => {
    const a = await open(new InMemoryKeyStore());
    const original = a.keys.getActiveKey().kid;
    const staged = await a.keys.stage();
    assert.equal(a.keys.getActiveKey().kid, original);
    assert.ok(a.keys.getKeyById(staged, a.clock.now()), 'pending keys verify');
    await a.keys.activate(staged);
    assert.equal(a.keys.getActiveKey().kid, staged);
    assert.deepEqual(
      a.keys
        .list()
        .map((k) => k.status)
        .sort(),
      ['active', 'retired'],
    );
  });

  it('remove invalidates a key at once; prune drops keys past their window', async () => {
    const a = await open(new InMemoryKeyStore());
    const old = a.accessTokens.issue(INPUT, a.clock.now()).token;
    const oldKid = kidOf(old);
    await a.keys.rotate();
    await a.keys.remove(oldKid);
    const r = a.accessTokens.verify(old, a.clock.now());
    assert.equal(r.ok ? 'OK' : r.failure, 'unknown_key');

    const b = await open(new InMemoryKeyStore());
    await b.keys.rotate();
    assert.equal(await b.keys.prune(), 0, 'still inside ttl + leeway');
    b.clock.advance(TTL);
    assert.equal(await b.keys.prune(), 1);
  });

  it('another instance learns a rotation: on an unseen kid and on refresh', async () => {
    const store = new InMemoryKeyStore();
    const a = await open(store);
    const b = await open(store);
    const newKid = await a.keys.rotate();
    const token = a.accessTokens.issue(INPUT, a.clock.now()).token;
    // B has not seen the new kid yet: rejected now, and a reload is triggered.
    assert.equal(b.accessTokens.verify(token, b.clock.now()).ok, false);
    await b.keys.refresh();
    assert.equal(b.accessTokens.verify(token, b.clock.now()).ok, true);
    assert.equal(b.keys.getActiveKey().kid, newKid, 'B now signs with the new key too');
  });

  it('with no active key, signing fails closed and login leaves no session behind', async () => {
    const store = new InMemoryKeyStore();
    const clock = new ManualClock(START);
    const ids = new SequentialIdGenerator('nk');
    const { accessTokens, keys } = await openJwtAccessTokens(config(store), {
      keyStore: store,
      clock,
      ids,
      env: { AEGIS_MASTER_KEY: MASTER_HEX },
      logger: captureLogger(),
    });
    const storage = createMemoryStorage();
    const auth = createAuth({
      storage,
      hasher: new ScryptHasher({ N: 1 << 12 }),
      accessTokens,
      clock,
      random: new CryptoRandom(),
      ids,
      catalog: testCatalog(),
      tokens: { accessTtlMs: TTL },
    });
    await auth.authn.register({
      identifier: 'ada@example.com',
      password: 'correct-horse-battery-staple',
    });
    await keys.retire(keys.getActiveKey().kid); // compromise response before a replacement exists
    assert.equal(
      await codeOf(() =>
        auth.authn.login({
          identifier: 'ada@example.com',
          password: 'correct-horse-battery-staple',
        }),
      ),
      'STORAGE_UNAVAILABLE',
    );
    const user = await storage.identifiers.findByNormalized('email', 'ada@example.com');
    assert.equal(await storage.sessions.countActive(user?.userId as string, clock.now()), 0);
  });

  it('strict revocation is unchanged: a valid persisted-key JWT is rejected after logout', async () => {
    const store = new InMemoryKeyStore();
    const clock = new ManualClock(START);
    const ids = new SequentialIdGenerator('sr');
    const { accessTokens } = await openJwtAccessTokens(config(store), {
      keyStore: store,
      clock,
      ids,
      env: { AEGIS_MASTER_KEY: MASTER_HEX },
      logger: captureLogger(),
    });
    const auth = createAuth({
      storage: createMemoryStorage(),
      hasher: new ScryptHasher({ N: 1 << 12 }),
      accessTokens,
      clock,
      random: new CryptoRandom(),
      ids,
      catalog: testCatalog(),
    });
    await auth.authn.register({
      identifier: 'ada@example.com',
      password: 'correct-horse-battery-staple',
    });
    const { credentials, principal } = await auth.authn.login({
      identifier: 'ada@example.com',
      password: 'correct-horse-battery-staple',
    });
    assert.ok(await auth.authn.resolve(credentials.accessToken));
    await auth.authn.logout({ principal });
    assert.equal(
      accessTokens.verify(credentials.accessToken, clock.now()).ok,
      true,
      'still a valid JWT',
    );
    assert.equal(
      await auth.authn.resolve(credentials.accessToken),
      null,
      'but the session decides',
    );
  });
});

// ---------------------------------------------------------------- encryption at rest

describe('encryption at rest', () => {
  it('with a master key, the file holds no plaintext private material', async () => {
    const path = freshFile();
    const a = await open(new FileKeyStore(path), { algorithm: 'HS256' });
    const secret = 'plain-secret-that-must-never-be-on-disk-xyz';
    await a.keys.stage({ kid: 'hs-secret', secret });
    const rsa = await open(new FileKeyStore(freshFile()));
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    await rsa.keys.stage({ kid: 'rsa-known', privateKey });

    const text = await readFile(path, 'utf8');
    assert.ok(!text.includes(secret));
    assert.ok(!text.includes(Buffer.from(secret).toString('base64')));
    const der = privateKey.export({ type: 'pkcs8', format: 'der' });
    const rsaFiles = await readFile(join(dir, `keys-${fileNo}.json`), 'utf8');
    assert.ok(!rsaFiles.includes(der.toString('base64').slice(40, 120)));
    // Every stored envelope is the encrypted kind.
    for (const k of JSON.parse(text).keys as { privateMaterial: string }[]) {
      assert.equal(Buffer.from(k.privateMaterial, 'base64').subarray(0, 4).toString(), 'AEK1');
    }
  });

  it('without a master key: an explicit warning, plaintext envelopes (file store, dev only)', async () => {
    const logger = captureLogger();
    const path = freshFile();
    await open(new FileKeyStore(path), { master: null, logger });
    assert.ok(
      logger.messages.some((m) => /AEGIS_MASTER_KEY is not set/.test(m) && /UNENCRYPTED/.test(m)),
    );
    const keys = JSON.parse(await readFile(path, 'utf8')).keys as { privateMaterial: string }[];
    assert.equal(
      Buffer.from(keys[0]?.privateMaterial as string, 'base64')
        .subarray(0, 4)
        .toString(),
      'AEK0',
    );
  });

  it('a wrong or missing master key fails startup instead of loading nothing', async () => {
    const path = freshFile();
    await open(new FileKeyStore(path));
    assert.ok(
      (await rulesOf(() => open(new FileKeyStore(path), { master: OTHER_MASTER_HEX }))).includes(
        'keys.decrypt',
      ),
    );
    assert.ok(
      (await rulesOf(() => open(new FileKeyStore(path), { master: null }))).includes(
        'keys.master_key_missing',
      ),
    );
    assert.ok(
      (await rulesOf(() => open(new FileKeyStore(path), { master: 'too-short' }))).includes(
        'keys.master_key',
      ),
    );
  });

  it('tampering is detected: swapped ciphertexts, or a public half that no longer matches', async () => {
    const path = freshFile();
    const a = await open(new FileKeyStore(path));
    await a.keys.stage();
    const data = JSON.parse(await readFile(path, 'utf8'));
    const [k1, k2] = data.keys as { privateMaterial: string; publicMaterial: { n: string } }[];
    [k1!.privateMaterial, k2!.privateMaterial] = [k2!.privateMaterial, k1!.privateMaterial];
    await writeFile(path, JSON.stringify(data));
    assert.ok((await rulesOf(() => open(new FileKeyStore(path)))).includes('keys.decrypt'));

    const path2 = freshFile();
    await open(new FileKeyStore(path2));
    const d2 = JSON.parse(await readFile(path2, 'utf8'));
    d2.keys[0].publicMaterial.n = d2.keys[0].publicMaterial.n.replace(/^./, (c: string) =>
      c === 'A' ? 'B' : 'A',
    );
    await writeFile(path2, JSON.stringify(d2));
    assert.ok(
      (await rulesOf(() => open(new FileKeyStore(path2)))).includes('keys.public_mismatch'),
    );
  });

  it('a key of the wrong type is refused', async () => {
    const store = new InMemoryKeyStore();
    await open(store, { algorithm: 'HS256' });
    assert.ok(
      (await rulesOf(() => open(store, { algorithm: 'RS256' }))).includes('keys.type_mismatch'),
    );
  });
});
