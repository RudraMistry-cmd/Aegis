// Unit tests for the JWT access-token provider, key rotation and strict revocation
// (spec/auth/tokens.md §2, §2.5, §2.6, §6; spec/conformance.md TOK-ACC-*).
import assert from 'node:assert/strict';
import {
  createHmac,
  createPublicKey,
  generateKeyPairSync,
  sign as rsaSign,
  verify as rsaVerify,
  type KeyObject,
} from 'node:crypto';
import { describe, it } from 'node:test';
import { createTestSystem, MINUTE, START, testCatalog } from '../support/fixtures.js';
import {
  createAuth,
  createJwtAccessTokens,
  createMemoryStorage,
  CryptoRandom,
  isAuthError,
  ManualClock,
  resolveJwtConfig,
  ScryptHasher,
  SequentialIdGenerator,
  type JwtAlgorithm,
  type KeyMaterial,
} from '../../src/index.js';

// ---------------------------------------------------------------- fixtures

const SECRET_A = 'test-secret-value-of-at-least-32-bytes!!';
const SECRET_B = 'another-secret-value-with-32-bytes-or-more';
const SECRET_C = 'a-third-secret-value-also-32-bytes-or-more';
const rsa = (bits = 2048): KeyObject =>
  generateKeyPairSync('rsa', { modulusLength: bits }).privateKey;
const RSA_A = rsa();
const RSA_B = rsa();

const TTL = 10 * MINUTE;
const INPUT = { subjectId: 'user-1', sessionId: 'sess-1', securityVersion: 0, ttlMs: TTL };

function material(algorithm: JwtAlgorithm, kid: string, which: 'a' | 'b' | 'c' = 'a'): KeyMaterial {
  if (algorithm === 'HS256') {
    return { kid, secret: which === 'a' ? SECRET_A : which === 'b' ? SECRET_B : SECRET_C };
  }
  return { kid, privateKey: which === 'a' ? RSA_A : RSA_B };
}

function makeProvider(algorithm: JwtAlgorithm, leewayMs = 0, rotationEnabled = true) {
  const clock = new ManualClock(START);
  const { accessTokens, keys } = createJwtAccessTokens(
    {
      tokens: { algorithm, issuer: 'iss-1', audience: 'aud-1', ttl: TTL, leewayMs },
      keys: { rotationEnabled },
    },
    { keys: [material(algorithm, 'k1')], clock, ids: new SequentialIdGenerator('jti') },
  );
  return { clock, accessTokens, keys };
}

const b64 = (v: string | Buffer): string => Buffer.from(v).toString('base64url');

/** Signs an arbitrary header/payload (objects or raw JSON text) with a given key. */
function forge(
  header: object | string,
  payload: object | string,
  key: { alg: 'HS256'; secret: string } | { alg: 'RS256'; privateKey: KeyObject },
): string {
  const h = b64(typeof header === 'string' ? header : JSON.stringify(header));
  const p = b64(typeof payload === 'string' ? payload : JSON.stringify(payload));
  const input = `${h}.${p}`;
  const sig =
    key.alg === 'HS256'
      ? createHmac('sha256', key.secret).update(input).digest()
      : rsaSign('sha256', Buffer.from(input), key.privateKey);
  return `${input}.${b64(sig)}`;
}

/** A well-formed claim set for forged tokens; individual tests override one field. */
function claims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const iat = START / 1000;
  return {
    iss: 'iss-1',
    aud: 'aud-1',
    sub: 'user-1',
    sid: 'sess-1',
    iat,
    exp: iat + TTL / 1000,
    jti: 'jti-x',
    sv: 0,
    typ: 'at+jwt',
    ...overrides,
  };
}

const HEADER = { alg: 'HS256', typ: 'at+jwt', kid: 'k1' };
const HS_A = { alg: 'HS256' as const, secret: SECRET_A };

function failureOf(
  r: ReturnType<ReturnType<typeof makeProvider>['accessTokens']['verify']>,
): string {
  return r.ok ? 'OK' : r.failure;
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

function headerOf(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split('.')[0] as string, 'base64url').toString('utf8'));
}

// ---------------------------------------------------------------- JWT basics, both algorithms

for (const algorithm of ['HS256', 'RS256'] as const) {
  describe(`JWT tokens — ${algorithm}`, () => {
    it('a valid token passes and carries exactly the specified claims', () => {
      const { accessTokens, clock } = makeProvider(algorithm);
      const issued = accessTokens.issue(INPUT, clock.now());
      assert.deepEqual(headerOf(issued.token), { alg: algorithm, typ: 'at+jwt', kid: 'k1' });
      const r = accessTokens.verify(issued.token, clock.now());
      assert.ok(r.ok);
      assert.equal(r.token.subjectId, 'user-1');
      assert.equal(r.token.sessionId, 'sess-1');
      assert.equal(r.token.securityVersion, 0);
      assert.equal(r.token.expiresAt - r.token.issuedAt, TTL);
      const payload = JSON.parse(
        Buffer.from(issued.token.split('.')[1] as string, 'base64url').toString('utf8'),
      );
      assert.deepEqual(Object.keys(payload).sort(), [
        'aud',
        'exp',
        'iat',
        'iss',
        'jti',
        'sid',
        'sub',
        'sv',
        'typ',
      ]);
    });

    it('an expired token fails exactly at exp, and leeway is honoured', () => {
      const { accessTokens, clock } = makeProvider(algorithm);
      const issued = accessTokens.issue(INPUT, clock.now());
      assert.equal(failureOf(accessTokens.verify(issued.token, issued.expiresAt - 1)), 'OK');
      assert.equal(failureOf(accessTokens.verify(issued.token, issued.expiresAt)), 'expired');

      const lenient = makeProvider(algorithm, 30_000);
      const t2 = lenient.accessTokens.issue(INPUT, lenient.clock.now());
      assert.equal(failureOf(lenient.accessTokens.verify(t2.token, t2.expiresAt + 29_999)), 'OK');
      assert.equal(
        failureOf(lenient.accessTokens.verify(t2.token, t2.expiresAt + 30_000)),
        'expired',
      );
    });

    it('a wrong signature fails: other key under the same kid, or any altered byte', () => {
      const { accessTokens, clock } = makeProvider(algorithm);
      const impostor = makeProvider(algorithm);
      // Same kid "k1", different key material.
      const other = createJwtAccessTokens(
        {
          tokens: { algorithm, issuer: 'iss-1', audience: 'aud-1', ttl: TTL },
          keys: { rotationEnabled: true },
        },
        {
          keys: [material(algorithm, 'k1', 'b')],
          clock: impostor.clock,
          ids: new SequentialIdGenerator('x'),
        },
      ).accessTokens.issue(INPUT, START).token;
      assert.equal(failureOf(accessTokens.verify(other, clock.now())), 'bad_signature');

      const good = accessTokens.issue(INPUT, clock.now()).token;
      const [h, p, s] = good.split('.') as [string, string, string];
      const tamperedPayload = b64(
        JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url').toString()), sv: 99 }),
      );
      assert.equal(
        failureOf(accessTokens.verify(`${h}.${tamperedPayload}.${s}`, clock.now())),
        'bad_signature',
      );
      const flipped = s.slice(0, 10) + (s[10] === 'A' ? 'B' : 'A') + s.slice(11);
      assert.equal(
        failureOf(accessTokens.verify(`${h}.${p}.${flipped}`, clock.now())),
        'bad_signature',
      );
    });

    it('a wrong kid fails: unknown kid, or a known kid that did not sign it', () => {
      const { accessTokens, clock, keys } = makeProvider(algorithm);
      const token = accessTokens.issue(INPUT, clock.now()).token;
      const [, p, s] = token.split('.') as [string, string, string];
      const unknownKid = b64(JSON.stringify({ alg: algorithm, typ: 'at+jwt', kid: 'nope' }));
      assert.equal(
        failureOf(accessTokens.verify(`${unknownKid}.${p}.${s}`, clock.now())),
        'unknown_key',
      );

      keys.stage(material(algorithm, 'k2', 'b'));
      const swapped = b64(JSON.stringify({ alg: algorithm, typ: 'at+jwt', kid: 'k2' }));
      assert.equal(
        failureOf(accessTokens.verify(`${swapped}.${p}.${s}`, clock.now())),
        'bad_signature',
      );
    });
  });
}

// ---------------------------------------------------------------- header and claim hardening

describe('JWT hardening (TOK-ACC-04..09, 14)', () => {
  it('TOK-ACC-05: alg "none" and unsigned tokens are rejected', () => {
    const { accessTokens, clock } = makeProvider('HS256');
    const none = `${b64(JSON.stringify({ alg: 'none', typ: 'at+jwt', kid: 'k1' }))}.${b64(JSON.stringify(claims()))}`;
    assert.equal(failureOf(accessTokens.verify(`${none}.`, clock.now())), 'malformed');
    assert.equal(
      failureOf(accessTokens.verify(`${none}.AAAA`, clock.now())),
      'unsupported_algorithm',
    );
  });

  it('TOK-ACC-06: algorithm confusion — an HMAC over the RSA public key is rejected', () => {
    const { accessTokens, clock } = makeProvider('RS256');
    const publicPem = createPublicKey(RSA_A).export({ type: 'spki', format: 'pem' }).toString();
    const confused = forge({ alg: 'HS256', typ: 'at+jwt', kid: 'k1' }, claims(), {
      alg: 'HS256',
      secret: publicPem,
    });
    assert.equal(failureOf(accessTokens.verify(confused, clock.now())), 'unsupported_algorithm');
  });

  it('TOK-ACC-14: headers that would let a token choose its own key are rejected', () => {
    const { accessTokens, clock } = makeProvider('HS256');
    for (const extra of [
      { jku: 'https://evil.example/keys' },
      { jwk: { kty: 'oct' } },
      { x5u: 'https://x' },
      { crit: ['exp'] },
      { zip: 'DEF' },
    ]) {
      const t = forge({ ...HEADER, ...extra }, claims(), HS_A);
      assert.equal(
        failureOf(accessTokens.verify(t, clock.now())),
        'malformed',
        JSON.stringify(extra),
      );
    }
  });

  it('TOK-ACC-08/09/10: issuer, audience and type must match configuration', () => {
    const { accessTokens, clock } = makeProvider('HS256');
    const at = (c: Record<string, unknown>, h: object = HEADER) =>
      failureOf(accessTokens.verify(forge(h, c, HS_A), clock.now()));
    assert.equal(at(claims()), 'OK');
    assert.equal(at(claims({ iss: 'someone-else' })), 'wrong_issuer');
    assert.equal(at(claims({ aud: 'other-api' })), 'wrong_audience');
    assert.equal(at(claims({ aud: ['other-api', 'aud-1'] })), 'OK');
    assert.equal(at(claims({ typ: 'rt+jwt' })), 'wrong_type');
    assert.equal(at(claims(), { ...HEADER, typ: 'JWT' }), 'wrong_type');
  });

  it('times: lifetime longer than the TTL, future iat or nbf are rejected', () => {
    const { accessTokens, clock } = makeProvider('HS256');
    const iat = START / 1000;
    const at = (c: Record<string, unknown>) =>
      failureOf(accessTokens.verify(forge(HEADER, c, HS_A), clock.now()));
    assert.equal(
      at(claims({ exp: iat + TTL / 1000 + 1 })),
      'malformed',
      'longer than this server issues',
    );
    assert.equal(at(claims({ exp: iat })), 'malformed', 'exp must follow iat');
    assert.equal(at(claims({ iat: iat + 60, exp: iat + 60 + TTL / 1000 })), 'not_yet_valid');
    assert.equal(at(claims({ nbf: iat + 60 })), 'not_yet_valid');
    assert.equal(at(claims({ iat: 'yesterday' })), 'malformed');
    assert.equal(at(claims({ sv: -1 })), 'malformed');
    assert.equal(at(claims({ sub: 'has spaces' })), 'malformed');
  });

  it('duplicate security claims are rejected instead of last-one-wins', () => {
    const { accessTokens, clock } = makeProvider('HS256');
    const body = JSON.stringify(claims()).replace('"sub":"user-1"', '"sub":"user-1","sub":"admin"');
    assert.equal(
      failureOf(accessTokens.verify(forge(HEADER, body, HS_A), clock.now())),
      'malformed',
    );
    const header = '{"alg":"HS256","typ":"at+jwt","kid":"k1","kid":"k2"}';
    assert.equal(
      failureOf(accessTokens.verify(forge(header, claims(), HS_A), clock.now())),
      'malformed',
    );
  });

  it('TOK-ACC-04: non-canonical base64url is rejected (no two strings verify as one token)', () => {
    const { accessTokens, clock } = makeProvider('HS256');
    const token = accessTokens.issue(INPUT, clock.now()).token;
    const [h, p, s] = token.split('.') as [string, string, string];
    // HS256 signatures are 32 bytes = 43 base64url chars; the last char carries 2 unused bits.
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = alphabet.indexOf(s[s.length - 1] as string);
    const twin = s.slice(0, -1) + alphabet[last ^ 1];
    assert.deepEqual(
      Buffer.from(twin, 'base64url'),
      Buffer.from(s, 'base64url'),
      'decodes to the same bytes',
    );
    assert.equal(failureOf(accessTokens.verify(`${h}.${p}.${twin}`, clock.now())), 'malformed');
    assert.equal(failureOf(accessTokens.verify(`${h}.${p}.${s}=`, clock.now())), 'malformed');
    assert.equal(failureOf(accessTokens.verify(`${token}\u0000`, clock.now())), 'malformed');
  });

  it('verify never throws, whatever it is given', () => {
    const { accessTokens, clock } = makeProvider('RS256');
    for (const junk of [
      undefined,
      null,
      42,
      {},
      [],
      'a.b.c',
      '...',
      'x'.repeat(100_000),
      '\u0000.\u0000.\u0000',
    ]) {
      assert.doesNotThrow(() => accessTokens.verify(junk as unknown as string, clock.now()));
      assert.equal(accessTokens.verify(junk as unknown as string, clock.now()).ok, false);
    }
  });
});

// ---------------------------------------------------------------- strict revocation

describe('strict revocation: the JWT is never the authority', () => {
  it('a valid token is rejected once its session is revoked', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { accessToken, principal } = await sys.login('alice@example.com');
    assert.ok(await sys.auth.authn.resolve(accessToken));

    await sys.auth.authn.logout({ principal });

    // The token itself is still cryptographically valid and unexpired...
    assert.equal(sys.accessTokens.verify(accessToken, sys.clock.now()).ok, true);
    // ...but the session decides: rejected immediately.
    assert.equal(await sys.auth.authn.resolve(accessToken), null);
    assert.equal(await codeOf(() => sys.auth.authn.authenticate(accessToken)), 'TOKEN_INVALID');
  });

  it('a valid token is rejected when its securityVersion no longer matches the user', async () => {
    const sys = createTestSystem();
    const userId = await sys.createUser('alice@example.com');
    const { accessToken } = await sys.login('alice@example.com');
    // Bump without revoking the session, so only the sv check can catch it.
    await sys.storage.users.bumpSecurityVersion(userId, sys.clock.now());

    assert.equal(sys.accessTokens.verify(accessToken, sys.clock.now()).ok, true);
    assert.equal(await sys.auth.authn.resolve(accessToken), null);
    assert.equal(await codeOf(() => sys.auth.authn.authenticate(accessToken)), 'TOKEN_INVALID');
    assert.ok(sys.audit.ofType('auth.rejected').some((e) => e.reason === 'security_version'));
  });

  it('a valid token is rejected when its session has expired', async () => {
    const sys = createTestSystem({
      sessions: { idleTtlMs: 4 * MINUTE, absoluteTtlMs: 60 * MINUTE },
    });
    await sys.createUser('alice@example.com');
    const { accessToken } = await sys.login('alice@example.com');
    sys.clock.advance(4 * MINUTE); // session idle-expired, JWT (10 min) still unexpired
    assert.equal(sys.accessTokens.verify(accessToken, sys.clock.now()).ok, true);
    assert.equal(await sys.auth.authn.resolve(accessToken), null);
  });

  it('authenticate maps failures to UNAUTHENTICATED, TOKEN_EXPIRED and TOKEN_INVALID', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { accessToken, principal } = await sys.login('alice@example.com');
    assert.equal((await sys.auth.authn.authenticate(accessToken)).id, principal.id);
    assert.equal(await codeOf(() => sys.auth.authn.authenticate('')), 'UNAUTHENTICATED');
    assert.equal(await codeOf(() => sys.auth.authn.authenticate(undefined)), 'UNAUTHENTICATED');
    assert.equal(await codeOf(() => sys.auth.authn.authenticate('not.a.jwt')), 'TOKEN_INVALID');

    // Expiry is reported only for a genuine token: a forged, expired token is just invalid.
    const forgedExpired = forge(
      { alg: 'HS256', typ: 'at+jwt', kid: 'test-key-1' },
      {
        ...claims({
          iss: 'aegis-test',
          aud: 'aegis-test-api',
          sub: principal.id,
          sid: principal.sessionId,
        }),
      },
      { alg: 'HS256', secret: SECRET_B },
    );
    sys.clock.advance(TTL);
    assert.equal(await codeOf(() => sys.auth.authn.authenticate(forgedExpired)), 'TOKEN_INVALID');
    assert.equal(await codeOf(() => sys.auth.authn.authenticate(accessToken)), 'TOKEN_EXPIRED');
    assert.equal(await sys.auth.authn.resolve(accessToken), null);
  });

  it('no internal detail leaks through authenticate errors', async () => {
    const sys = createTestSystem();
    for (const token of ['', 'garbage', `${b64('{"alg":"none"}')}.e30.`]) {
      try {
        await sys.auth.authn.authenticate(token);
      } catch (e) {
        assert.ok(isAuthError(e));
        const wire = JSON.stringify(e.toJSON());
        assert.ok(!/malformed|signature|kid|alg/i.test(wire), wire);
      }
    }
  });
});

// ---------------------------------------------------------------- rotation

describe('key rotation', () => {
  it('old tokens stay valid after rotation, and new tokens use the new key', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const before = await sys.login('alice@example.com');
    assert.equal(headerOf(before.accessToken)['kid'], 'test-key-1');

    sys.keys.rotate({ kid: 'test-key-2', secret: SECRET_B });

    assert.ok(await sys.auth.authn.resolve(before.accessToken), 'old token still valid');
    const after = await sys.login('alice@example.com');
    assert.equal(headerOf(after.accessToken)['kid'], 'test-key-2');
    assert.ok(await sys.auth.authn.resolve(after.accessToken));
    assert.deepEqual(
      sys.keys.list().map((k) => `${k.kid}:${k.status}`),
      ['test-key-1:retired', 'test-key-2:active'],
    );
  });

  it('a retired key verifies for exactly ttl + leeway, then is gone', () => {
    const { keys, clock } = makeProvider('HS256', 5_000);
    keys.rotate(material('HS256', 'k2', 'b'));
    const retiredAt = clock.now();
    assert.ok(keys.getKeyById('k1', retiredAt + TTL + 5_000 - 1));
    assert.equal(keys.getKeyById('k1', retiredAt + TTL + 5_000), null);
    assert.equal(keys.prune(retiredAt + TTL), 0);
    assert.equal(keys.prune(retiredAt + TTL + 5_000), 1);
  });

  it('a retired key cannot vouch for a token issued after its retirement', () => {
    const { accessTokens, keys, clock } = makeProvider('HS256');
    const old = accessTokens.issue(INPUT, clock.now()).token;
    clock.advance(MINUTE);
    keys.rotate(material('HS256', 'k2', 'b'));
    clock.advance(MINUTE);
    // Someone holding the old secret mints a "fresh" token after rotation.
    const iat = Math.floor(clock.now() / 1000);
    const minted = forge(HEADER, claims({ iat, exp: iat + TTL / 1000 }), HS_A);
    assert.equal(failureOf(accessTokens.verify(minted, clock.now())), 'unknown_key');
    assert.equal(failureOf(accessTokens.verify(old, clock.now())), 'OK');
  });

  it('two-phase rotation: a staged key verifies before it signs', () => {
    const { accessTokens, keys, clock } = makeProvider('HS256');
    keys.stage(material('HS256', 'k2', 'b'));
    assert.equal(keys.getActiveKey().kid, 'k1', 'staging does not change the signer');
    // Another instance that already activated k2 issued this token: we can verify it.
    const fromPeer = forge({ ...HEADER, kid: 'k2' }, claims(), { alg: 'HS256', secret: SECRET_B });
    assert.equal(failureOf(accessTokens.verify(fromPeer, clock.now())), 'OK');
    keys.activate('k2');
    assert.equal(headerOf(accessTokens.issue(INPUT, clock.now()).token)['kid'], 'k2');
    assert.deepEqual(
      keys.list().map((k) => k.status),
      ['retired', 'active'],
    );
  });

  it('removing a compromised key invalidates its tokens at once; kids are never reused', () => {
    const { accessTokens, keys, clock } = makeProvider('HS256');
    const old = accessTokens.issue(INPUT, clock.now()).token;
    keys.rotate(material('HS256', 'k2', 'b'));
    keys.remove('k1');
    assert.equal(failureOf(accessTokens.verify(old, clock.now())), 'unknown_key');
    assert.throws(
      () => keys.remove('k2'),
      (e: unknown) => isAuthError(e) && e.code === 'VALIDATION_FAILED',
    );
    assert.throws(
      () => keys.stage(material('HS256', 'k1', 'c')),
      (e: unknown) => isAuthError(e) && e.code === 'VALIDATION_FAILED',
    );
  });

  it('rotation can be disabled', () => {
    const { keys } = makeProvider('HS256', 0, false);
    assert.throws(
      () => keys.rotate(material('HS256', 'k2', 'b')),
      (e: unknown) => isAuthError(e) && e.code === 'VALIDATION_FAILED',
    );
    assert.throws(
      () =>
        createJwtAccessTokens(
          {
            tokens: { algorithm: 'HS256', issuer: 'i', audience: 'a' },
            keys: { rotationEnabled: false },
          },
          {
            keys: [
              { ...material('HS256', 'k1'), status: 'active' },
              { ...material('HS256', 'k2', 'b'), status: 'retired' },
            ],
            clock: new ManualClock(START),
            ids: new SequentialIdGenerator('x'),
          },
        ),
      (e: unknown) => isAuthError(e) && e.code === 'CONFIG_INVALID',
    );
  });

  it('key material never appears in metadata or errors', () => {
    const { keys } = makeProvider('HS256');
    assert.ok(!JSON.stringify(keys.list()).includes(SECRET_A));
    try {
      createJwtAccessTokens(
        {
          tokens: { algorithm: 'HS256', issuer: 'i', audience: 'a' },
          keys: { rotationEnabled: true },
        },
        {
          keys: [{ kid: 'k1', secret: 'short-but-secret' }],
          clock: new ManualClock(START),
          ids: new SequentialIdGenerator('x'),
        },
      );
      assert.fail('expected CONFIG_INVALID');
    } catch (e) {
      assert.ok(isAuthError(e));
      assert.ok(!JSON.stringify(e.toJSON()).includes('short-but-secret'));
    }
  });
});

// ---------------------------------------------------------------- configuration

describe('JWT configuration', () => {
  const violationRules = (fn: () => unknown): string[] => {
    try {
      fn();
    } catch (e) {
      assert.ok(isAuthError(e) && e.code === 'CONFIG_INVALID', String(e));
      return ((e.details?.['violations'] ?? []) as { rule: string }[]).map((v) => v.rule);
    }
    return [];
  };

  it('rejects invalid settings, listing every violation', () => {
    const rules = violationRules(() =>
      resolveJwtConfig({
        tokens: {
          algorithm: 'HS512' as JwtAlgorithm,
          issuer: '',
          audience: '',
          ttl: 1500,
          leewayMs: 120_000,
        },
        keys: {} as { rotationEnabled: boolean },
      }),
    );
    for (const r of [
      'jwt.algorithm',
      'jwt.issuer',
      'jwt.audience',
      'jwt.ttl',
      'jwt.leeway',
      'keys.rotation',
    ]) {
      assert.ok(rules.includes(r), `missing ${r} in ${rules.join(',')}`);
    }
    assert.ok(
      violationRules(() =>
        resolveJwtConfig({
          tokens: { algorithm: 'HS256', issuer: 'i', audience: 'a', ttl: 61 * MINUTE },
          keys: { rotationEnabled: true },
        }),
      ).includes('jwt.ttl'),
    );
  });

  it('rejects weak, mismatched or inconsistent keys', () => {
    const build = (
      algorithm: JwtAlgorithm,
      keys: Parameters<typeof createJwtAccessTokens>[1]['keys'],
    ) =>
      violationRules(() =>
        createJwtAccessTokens(
          { tokens: { algorithm, issuer: 'i', audience: 'a' }, keys: { rotationEnabled: true } },
          { keys, clock: new ManualClock(START), ids: new SequentialIdGenerator('x') },
        ),
      );
    assert.ok(build('HS256', [{ kid: 'k', secret: 'too-short' }]).includes('key.min_length'));
    assert.ok(build('HS256', [{ kid: 'k', secret: 'a'.repeat(64) }]).includes('key.placeholder'));
    assert.ok(
      build('HS256', [{ kid: 'k', secret: 'changemechangemechangemechangeme' }]).includes(
        'key.placeholder',
      ),
    );
    assert.ok(build('RS256', [{ kid: 'k', privateKey: rsa(1024) }]).includes('key.min_length'));
    assert.ok(build('RS256', [{ kid: 'k', secret: SECRET_A }]).includes('key.algorithm_mismatch'));
    assert.ok(build('RS256', [{ kid: 'k', privateKey: 'not a pem' }]).includes('key.unreadable'));
    assert.ok(build('HS256', [{ kid: 'bad kid!', secret: SECRET_A }]).includes('key.kid'));
    assert.ok(build('HS256', []).includes('keys.required'));
    assert.ok(
      build('HS256', [
        { kid: 'k1', secret: SECRET_A, status: 'active' },
        { kid: 'k2', secret: SECRET_B, status: 'active' },
      ]).includes('keys.one_active'),
    );
    assert.ok(
      build('HS256', [
        { kid: 'k1', secret: SECRET_A, status: 'active' },
        { kid: 'k1', secret: SECRET_B, status: 'retired' },
      ]).includes('key.kid_unique'),
    );
  });

  it('createAuth requires the core access TTL to equal the provider TTL', () => {
    const clock = new ManualClock(START);
    const ids = new SequentialIdGenerator('c');
    const { accessTokens } = createJwtAccessTokens(
      {
        tokens: { algorithm: 'HS256', issuer: 'i', audience: 'a', ttl: 5 * MINUTE },
        keys: { rotationEnabled: true },
      },
      { keys: [material('HS256', 'k1')], clock, ids },
    );
    const base = {
      storage: createMemoryStorage(),
      hasher: new ScryptHasher({ N: 1 << 12 }),
      accessTokens,
      clock,
      random: new CryptoRandom(),
      ids,
      catalog: testCatalog(),
    };
    assert.throws(
      () => createAuth({ ...base, tokens: { accessTtlMs: 10 * MINUTE } }),
      (e: unknown) => isAuthError(e) && e.code === 'CONFIG_INVALID',
    );
    const adopted = createAuth(base).describe()['tokens'] as { accessTtlMs: number };
    assert.equal(adopted.accessTtlMs, 5 * MINUTE);
  });
});

// ---------------------------------------------------------------- RS256 end to end

describe('RS256 end to end', () => {
  it('login, resolve and refresh work, and tokens verify with any standard RS256 verifier', async () => {
    const clock = new ManualClock(START);
    const ids = new SequentialIdGenerator('e2e');
    const { accessTokens } = createJwtAccessTokens(
      {
        tokens: { algorithm: 'RS256', issuer: 'aegis', audience: 'api' },
        keys: { rotationEnabled: true },
      },
      { keys: [{ kid: 'rsa-1', privateKey: RSA_A }], clock, ids },
    );
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
    assert.equal((await auth.authn.authenticate(credentials.accessToken)).id, principal.id);
    const rotated = await auth.authn.refresh({ refreshToken: credentials.refreshToken });
    assert.ok(await auth.authn.resolve(rotated.credentials.accessToken));

    // Interoperability: plain node:crypto with only the public key accepts the signature.
    const [h, p, s] = credentials.accessToken.split('.') as [string, string, string];
    assert.ok(
      rsaVerify(
        'sha256',
        Buffer.from(`${h}.${p}`),
        createPublicKey(RSA_A),
        Buffer.from(s, 'base64url'),
      ),
    );
  });
});
