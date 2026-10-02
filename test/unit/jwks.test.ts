// JWKS endpoint (src/auth/jwt/jwks.ts): what is published, when, and that nothing private ever is.
import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync, verify as rsaVerify } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  buildJwks,
  createJwksHandler,
  createJwtAccessTokens,
  InMemoryKeyStore,
  isAuthError,
  ManualClock,
  openJwtAccessTokens,
  SequentialIdGenerator,
} from '../../src/index.js';
import { START } from '../support/fixtures.js';

const MINUTE = 60_000;
const TTL = 10 * MINUTE;
const MASTER_HEX = '8f1c2a7d4e9b0365aa17c3d2f8e46b9c0d1e2f3a4b5c6d7e8f90a1b2c3d4e5f6';
const INPUT = { subjectId: 'user-1', sessionId: 'sess-1', securityVersion: 0, ttlMs: TTL };
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'];

async function persistent(leewayMs = 0) {
  const clock = new ManualClock(START);
  const store = new InMemoryKeyStore();
  const opened = await openJwtAccessTokens(
    {
      tokens: { algorithm: 'RS256', issuer: 'iss-1', audience: 'aud-1', ttl: TTL, leewayMs },
      keys: {
        rotationEnabled: true,
        storage: 'memory',
        generateIfMissing: true,
        refreshIntervalMs: 0,
        jwks: { cacheTtlSec: 120 },
      },
    },
    {
      keyStore: store,
      clock,
      ids: new SequentialIdGenerator('jwks'),
      env: { AEGIS_MASTER_KEY: MASTER_HEX },
      logger: { warn: () => undefined },
    },
  );
  return { ...opened, clock, store };
}

const kidsOf = (body: string): string[] =>
  (JSON.parse(body) as { keys: { kid: string }[] }).keys.map((k) => k.kid).sort();

describe('JWKS endpoint', () => {
  it('serves the active key with exactly kty, kid, alg, use, n, e — and the right headers', async () => {
    const { jwks, keys } = await persistent();
    assert.ok(jwks);
    assert.equal(jwks.path, '/.well-known/jwks.json');
    const res = jwks.handle();
    assert.equal(res.status, 200);
    assert.equal(res.headers['content-type'], 'application/jwk-set+json; charset=utf-8');
    assert.equal(res.headers['cache-control'], 'public, max-age=120');
    const doc = JSON.parse(res.body) as { keys: Record<string, string>[] };
    assert.equal(doc.keys.length, 1);
    const [jwk] = doc.keys;
    assert.deepEqual(Object.keys(jwk ?? {}).sort(), ['alg', 'e', 'kid', 'kty', 'n', 'use']);
    assert.equal(jwk?.['kid'], keys.getActiveKey().kid);
    assert.equal(jwk?.['kty'], 'RSA');
    assert.equal(jwk?.['alg'], 'RS256');
    assert.equal(jwk?.['use'], 'sig');
  });

  it('a published key verifies this server’s tokens (interoperability)', async () => {
    const { jwks, accessTokens, clock } = await persistent();
    const token = accessTokens.issue(INPUT, clock.now()).token;
    const [h, p, s] = token.split('.') as [string, string, string];
    const kid = (JSON.parse(Buffer.from(h, 'base64url').toString()) as { kid: string }).kid;
    const jwk = (JSON.parse(jwks!.handle().body) as { keys: { kid: string }[] }).keys.find(
      (k) => k.kid === kid,
    );
    assert.ok(jwk);
    const publicKey = createPublicKey({ key: jwk as never, format: 'jwk' });
    assert.ok(
      rsaVerify('sha256', Buffer.from(`${h}.${p}`), publicKey, Buffer.from(s, 'base64url')),
    );
  });

  it('publishes exactly what this server would accept: active, pending, retired inside the window', async () => {
    const { jwks, keys, clock } = await persistent(5_000);
    const first = keys.getActiveKey().kid;
    const staged = await keys.stage();
    assert.deepEqual(
      kidsOf(jwks!.handle().body),
      [first, staged].sort(),
      'pending keys are published early',
    );

    await keys.activate(staged); // retires `first` now
    const retiredAt = clock.now();
    assert.deepEqual(
      kidsOf(jwks!.handle().body),
      [first, staged].sort(),
      'retired, still verifiable',
    );

    clock.set(retiredAt + TTL + 5_000 - 1);
    assert.ok(kidsOf(jwks!.handle().body).includes(first));
    clock.set(retiredAt + TTL + 5_000);
    assert.deepEqual(kidsOf(jwks!.handle().body), [staged], 'gone once no longer verifiable');

    const third = await keys.stage();
    await keys.remove(third);
    assert.ok(!kidsOf(jwks!.handle().body).includes(third), 'removed keys disappear at once');
  });

  it('never contains private material', async () => {
    const { jwks, keys } = await persistent();
    await keys.stage();
    await keys.rotate();
    const body = jwks!.handle().body;
    for (const k of (JSON.parse(body) as { keys: Record<string, unknown>[] }).keys) {
      for (const m of PRIVATE_MEMBERS) assert.ok(!Object.hasOwn(k, m), `member ${m} published`);
    }
    // And for a key whose private half we know: no fragment of its PKCS#8 encoding appears.
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const kid = await keys.stage({ kid: 'known-rsa', privateKey });
    const der = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64url');
    const after = jwks!.handle().body;
    assert.ok(kidsOf(after).includes(kid));
    assert.ok(!after.includes(der.slice(200, 260)));
    const d = privateKey.export({ format: 'jwk' }).d as string;
    assert.ok(!after.includes(d));
  });

  it('works for the static Phase 3 key provider as well', () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const clock = new ManualClock(START);
    const { keys } = createJwtAccessTokens(
      {
        tokens: { algorithm: 'RS256', issuer: 'i', audience: 'a' },
        keys: { rotationEnabled: true },
      },
      { keys: [{ kid: 'static-1', privateKey }], clock, ids: new SequentialIdGenerator('s') },
    );
    assert.deepEqual(
      buildJwks(keys, clock.now()).keys.map((k) => k.kid),
      ['static-1'],
    );
  });

  it('HS256 secrets are never published: building a JWKS for them is refused', async () => {
    const clock = new ManualClock(START);
    const { keys } = createJwtAccessTokens(
      {
        tokens: { algorithm: 'HS256', issuer: 'i', audience: 'a' },
        keys: { rotationEnabled: true },
      },
      {
        keys: [{ kid: 'hs', secret: 'a-secret-that-is-at-least-32-bytes-long' }],
        clock,
        ids: new SequentialIdGenerator('h'),
      },
    );
    assert.throws(
      () => createJwksHandler(keys, { clock }),
      (e: unknown) => isAuthError(e) && e.code === 'CONFIG_INVALID',
    );
    assert.throws(
      () => buildJwks(keys, clock.now()),
      (e: unknown) => isAuthError(e) && e.code === 'CONFIG_INVALID',
    );

    // Through the persistent wiring: no handler for HS256, and configuring one is an error.
    const store = new InMemoryKeyStore();
    const base = {
      tokens: { algorithm: 'HS256' as const, issuer: 'i', audience: 'a' },
      keys: {
        rotationEnabled: true,
        storage: 'memory' as const,
        generateIfMissing: true,
        refreshIntervalMs: 0,
      },
    };
    const deps = {
      keyStore: store,
      clock,
      ids: new SequentialIdGenerator('h2'),
      env: { AEGIS_MASTER_KEY: MASTER_HEX },
      logger: { warn: () => undefined },
    };
    assert.equal((await openJwtAccessTokens(base, deps)).jwks, null);
    await assert.rejects(
      openJwtAccessTokens({ ...base, keys: { ...base.keys, jwks: {} } }, deps),
      (e: unknown) => isAuthError(e) && e.code === 'CONFIG_INVALID',
    );
  });

  it('rejects an invalid path or cache TTL at construction', async () => {
    const { keys, clock } = await persistent();
    for (const opts of [
      { path: 'no-leading-slash' },
      { path: '/a b' },
      { cacheTtlSec: -1 },
      { cacheTtlSec: 1.5 },
      { cacheTtlSec: 90_000 },
    ]) {
      assert.throws(
        () => createJwksHandler(keys, { ...opts, clock }),
        (e: unknown) => isAuthError(e) && e.code === 'CONFIG_INVALID',
        JSON.stringify(opts),
      );
    }
  });
});
