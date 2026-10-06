// Phase 1 hardening: identifier digests are keyed (HMAC), bearer-secret digests stay plain SHA-256,
// and the password hasher's default cost is production-grade.
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  createAuth,
  digest,
  identifierDigest,
  isAuthError,
  MemoryRateLimiter,
  ScryptHasher,
  type RateLimiter,
} from '../../src/index.js';
import { createTestSystem, TEST_DIGEST_KEY, TEST_PASSWORD } from '../support/fixtures.js';

const sha256 = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex');
const KEY_A = TEST_DIGEST_KEY;
const KEY_B = 'c4d3b2a1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0918f7e6d5c4b3a';

/** Records every key the login throttle touches. */
class RecordingLimiter extends MemoryRateLimiter implements RateLimiter {
  readonly keys = new Set<string>();
  override async peek(key: string, now: number) {
    this.keys.add(key);
    return super.peek(key, now);
  }
}

describe('keyed identifier digests', () => {
  it('identifierDigest is HMAC-SHA256: keyed, deterministic, not plain SHA-256', () => {
    const key = Buffer.from(KEY_A, 'hex');
    const d = identifierDigest('ada@example.com', key);
    assert.equal(d, createHmac('sha256', key).update('ada@example.com').digest('hex'));
    assert.equal(d, identifierDigest('ada@example.com', key), 'deterministic');
    assert.notEqual(
      d,
      identifierDigest('ada@example.com', Buffer.from(KEY_B, 'hex')),
      'key matters',
    );
    assert.notEqual(
      d,
      sha256('ada@example.com'),
      'a dictionary of plain SHA-256 hashes does not match',
    );
  });

  it('bearer-secret digests are unchanged plain SHA-256', () => {
    assert.equal(digest('refresh-secret'), sha256('refresh-secret'));
  });

  it('a failed login audits the keyed digest of the normalized identifier, never a plain hash', async () => {
    const sys = createTestSystem();
    await assert.rejects(
      sys.auth.authn.login({ identifier: ' Ada@Example.COM ', password: 'wrong-password-123' }),
      (e) => isAuthError(e) && e.code === 'INVALID_CREDENTIALS',
    );
    const ev = sys.audit.events().find((e) => e.type === 'login.failed');
    const logged = ev?.details?.['identifierDigest'];
    assert.equal(logged, identifierDigest('ada@example.com', Buffer.from(KEY_A, 'hex')));
    assert.notEqual(logged, sha256('ada@example.com'));
    assert.ok(!JSON.stringify(sys.audit.events()).includes('ada@example.com'), 'no raw identifier');
  });

  it('the rate-limit key is keyed too, and differs per key', async () => {
    const run = async (key: string): Promise<string[]> => {
      const sys = createTestSystem();
      const limiter = new RecordingLimiter();
      const auth = createAuth({
        storage: sys.storage,
        hasher: sys.hasher,
        accessTokens: sys.accessTokens,
        clock: sys.clock,
        random: { bytes: (n) => new Uint8Array(n).fill(7) },
        ids: { newId: () => 'x' },
        rateLimiter: limiter,
        catalog: sys.catalog,
        identifierDigestKey: key,
      });
      await auth.authn
        .login({ identifier: 'ada@example.com', password: TEST_PASSWORD })
        .catch(() => 0);
      return [...limiter.keys].filter((k) => k.startsWith('login:'));
    };
    const [a] = await run(KEY_A);
    const [b] = await run(KEY_B);
    assert.equal(a, `login:${identifierDigest('ada@example.com', Buffer.from(KEY_A, 'hex'))}`);
    assert.notEqual(a, b);
    assert.notEqual(a, `login:${sha256('ada@example.com')}`);
  });
});

describe('identifier digest key configuration', () => {
  const base = () => {
    const sys = createTestSystem();
    return {
      storage: sys.storage,
      hasher: sys.hasher,
      accessTokens: sys.accessTokens,
      clock: sys.clock,
      random: { bytes: (n: number) => new Uint8Array(n).fill(1) },
      ids: { newId: () => 'x' },
      catalog: sys.catalog,
    };
  };
  const violations = (e: unknown): string[] =>
    isAuthError(e)
      ? ((e.details?.['violations'] ?? []) as { rule: string }[]).map((v) => v.rule)
      : [];

  it('is REQUIRED in production: CONFIG_INVALID with a clear rule', () => {
    assert.throws(
      () => createAuth({ ...base(), env: { NODE_ENV: 'production' } }),
      (e: unknown) =>
        isAuthError(e) &&
        e.code === 'CONFIG_INVALID' &&
        violations(e).includes('identifier_digest.required'),
    );
  });

  it('is accepted from the option or from AEGIS_IDENTIFIER_DIGEST_KEY in production', () => {
    assert.doesNotThrow(() =>
      createAuth({ ...base(), env: { NODE_ENV: 'production' }, identifierDigestKey: KEY_A }),
    );
    assert.doesNotThrow(() =>
      createAuth({
        ...base(),
        env: { NODE_ENV: 'production', AEGIS_IDENTIFIER_DIGEST_KEY: KEY_A },
      }),
    );
    const b64 = Buffer.from(KEY_A, 'hex').toString('base64');
    assert.doesNotThrow(() => createAuth({ ...base(), identifierDigestKey: b64 }));
  });

  it('rejects short, non-key and placeholder values, in any environment', () => {
    for (const bad of ['short', 'z'.repeat(64), '00'.repeat(32), 'ab'.repeat(8), 'not a key!']) {
      assert.throws(
        () => createAuth({ ...base(), env: {}, identifierDigestKey: bad }),
        (e: unknown) =>
          isAuthError(e) &&
          e.code === 'CONFIG_INVALID' &&
          violations(e).includes('identifier_digest.key'),
        bad,
      );
    }
  });

  it('outside production a missing key falls back to a random one, with a warning', () => {
    const auth = createAuth({ ...base(), env: {} });
    assert.ok(
      auth
        .doctor()
        .some((f) => f.finding === 'insecure_option' && f.path === 'identifierDigestKey'),
    );
  });

  it('never exposes the key through describe(), doctor() or JSON', () => {
    const auth = createAuth({ ...base(), identifierDigestKey: KEY_A });
    const out = JSON.stringify([auth.describe(), auth.doctor()]);
    assert.ok(!out.includes(KEY_A));
    assert.ok(!out.includes(Buffer.from(KEY_A, 'hex').toString('base64')));
    assert.ok(!auth.doctor().some((f) => f.path === 'identifierDigestKey'), 'no warning when set');
  });
});

describe('ScryptHasher default cost', () => {
  it('defaults to N = 2^17, r = 8, p = 1 and still verifies cheaper hashes', async () => {
    const strong = new ScryptHasher();
    const encoded = await strong.hash('correct-horse-battery-staple');
    assert.match(encoded, /^\$scrypt\$ln=17,r=8,p=1\$/);
    assert.equal(await strong.verify('correct-horse-battery-staple', encoded), true);
    assert.equal(await strong.verify('wrong', encoded), false);
    assert.equal(strong.needsRehash(encoded), false);

    const cheap = await new ScryptHasher({ N: 1 << 12 }).hash('correct-horse-battery-staple');
    assert.equal(await strong.verify('correct-horse-battery-staple', cheap), true);
    assert.equal(strong.needsRehash(cheap), true, 'old, cheaper hashes are upgraded on next login');
  });
});
