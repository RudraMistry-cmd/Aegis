// Unit tests for refresh-token rotation and reuse detection (spec/flows/refresh.md).
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createTestSystem, DAY, MINUTE } from '../support/fixtures.js';
import { isAuthError } from '../../src/index.js';

async function codeOf(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (e) {
    assert.ok(isAuthError(e), `expected an AuthError, got ${String(e)}`);
    return e.code;
  }
  assert.fail('expected the call to fail');
}

describe('refresh rotation', () => {
  it('rotates on every use and keeps the session id stable', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const first = await sys.login('alice@example.com');

    let token = first.refreshToken;
    const seen = new Set([token]);
    for (let i = 0; i < 5; i++) {
      sys.clock.advance(MINUTE);
      const r = await sys.auth.authn.refresh({ refreshToken: token });
      assert.equal(r.principal.sessionId, first.principal.sessionId);
      // authenticatedAt must not advance (refresh.md §5.6).
      assert.equal(r.principal.authenticatedAt, first.principal.authenticatedAt);
      assert.ok(!seen.has(r.credentials.refreshToken), 'each successor must be new');
      seen.add(r.credentials.refreshToken);
      token = r.credentials.refreshToken;
    }
    assert.equal(await sys.storage.sessions.countActive(first.principal.id, sys.clock.now()), 1);
  });

  it('rejects the previous token after a rotation', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { refreshToken } = await sys.login('alice@example.com');
    await sys.auth.authn.refresh({ refreshToken });
    assert.equal(await codeOf(() => sys.auth.authn.refresh({ refreshToken })), 'TOKEN_INVALID');
  });

  it('stores only digests, never the raw refresh token', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { refreshToken } = await sys.login('alice@example.com');
    const dump = JSON.stringify([
      [...sys.storage.db.tables.refreshTokens.values()],
      [...sys.storage.db.tables.refreshTokenIndex.keys()],
      sys.audit.events(),
    ]);
    assert.ok(!dump.includes(refreshToken));
  });

  it('reports TOKEN_EXPIRED once the refresh token has expired', async () => {
    const sys = createTestSystem({ tokens: { refreshIdleTtlMs: 1000 } });
    await sys.createUser('alice@example.com');
    const { refreshToken } = await sys.login('alice@example.com');
    sys.clock.advance(1000);
    assert.equal(await codeOf(() => sys.auth.authn.refresh({ refreshToken })), 'TOKEN_EXPIRED');
  });

  it('never extends the absolute session lifetime', async () => {
    const sys = createTestSystem({
      sessions: { idleTtlMs: 10 * MINUTE, absoluteTtlMs: 30 * MINUTE },
    });
    await sys.createUser('alice@example.com');
    const first = await sys.login('alice@example.com');
    const session = await sys.storage.sessions.get(first.principal.sessionId as string);
    const absolute = session?.absoluteExpiresAt as number;

    let token = first.refreshToken;
    for (let i = 0; i < 3; i++) {
      sys.clock.advance(5 * MINUTE);
      token = (await sys.auth.authn.refresh({ refreshToken: token })).credentials.refreshToken;
    }
    const after = await sys.storage.sessions.get(first.principal.sessionId as string);
    assert.equal(after?.absoluteExpiresAt, absolute);

    sys.clock.set(absolute);
    assert.ok(
      ['TOKEN_INVALID', 'TOKEN_EXPIRED'].includes(
        await codeOf(() => sys.auth.authn.refresh({ refreshToken: token })),
      ),
    );
  });

  it('rejects malformed input without touching the store', async () => {
    const sys = createTestSystem();
    const before = sys.storage.db.tables.refreshTokens.size;
    for (const bad of ['', 'x'.repeat(513), null, undefined, 42]) {
      assert.equal(
        await codeOf(() => sys.auth.authn.refresh({ refreshToken: bad as unknown as string })),
        'TOKEN_INVALID',
      );
    }
    assert.equal(sys.storage.db.tables.refreshTokens.size, before);
  });

  it('refuses an access token presented as a refresh token', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { accessToken } = await sys.login('alice@example.com');
    assert.equal(
      await codeOf(() => sys.auth.authn.refresh({ refreshToken: accessToken })),
      'TOKEN_INVALID',
    );
  });
});

describe('refresh reuse attack', () => {
  it('revokes the family and the session when a used token is replayed', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const first = await sys.login('alice@example.com');
    const stolen = first.refreshToken;

    // The legitimate client rotates.
    const rotated = await sys.auth.authn.refresh({ refreshToken: stolen });

    // The attacker replays the old token.
    assert.equal(
      await codeOf(() => sys.auth.authn.refresh({ refreshToken: stolen })),
      'TOKEN_INVALID',
    );

    const session = await sys.storage.sessions.get(first.principal.sessionId as string);
    assert.equal(session?.revokedAt !== undefined, true);
    assert.equal(session?.revokedReason, 'refresh_reuse_detected');

    const alerts = sys.audit.ofType('refresh.reuse_detected');
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0]?.severity, 'high');
    assert.ok(!JSON.stringify(alerts).includes(stolen));

    // The legitimate successor is dead too (refresh.md §3 / conformance REF-05).
    assert.equal(
      await codeOf(() =>
        sys.auth.authn.refresh({ refreshToken: rotated.credentials.refreshToken }),
      ),
      'TOKEN_INVALID',
    );
  });

  it('answers reuse exactly like an unknown token', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { refreshToken } = await sys.login('alice@example.com');
    await sys.auth.authn.refresh({ refreshToken });

    const shapes: string[] = [];
    for (const token of [refreshToken, 'unknown-token-value']) {
      try {
        await sys.auth.authn.refresh({ refreshToken: token });
        assert.fail('should have failed');
      } catch (e) {
        assert.ok(isAuthError(e));
        shapes.push(JSON.stringify(e.toJSON()));
      }
    }
    assert.equal(new Set(shapes).size, 1, shapes.join(' / '));
  });

  it('serves exactly one winner for concurrent presentations of one token', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { refreshToken, principal } = await sys.login('alice@example.com');

    const results = await Promise.allSettled(
      Array.from({ length: 20 }, () => sys.auth.authn.refresh({ refreshToken })),
    );
    const winners = results.filter((r) => r.status === 'fulfilled');
    assert.equal(winners.length, 1, 'exactly one refresh may succeed');

    // With reuseGrace = 0 the losers trip reuse detection, so the session is revoked.
    const session = await sys.storage.sessions.get(principal.sessionId as string);
    assert.equal(session?.revokedReason, 'refresh_reuse_detected');
    const active = [...sys.storage.db.tables.refreshTokens.values()].filter(
      (t) => t.status === 'active',
    );
    assert.equal(active.length, 0);
  });

  it('replaces the successor instead of revoking when the grace window is enabled', async () => {
    const sys = createTestSystem({ tokens: { reuseGraceMs: 5000 } });
    await sys.createUser('alice@example.com');
    const first = await sys.login('alice@example.com');

    const rotated = await sys.auth.authn.refresh({ refreshToken: first.refreshToken });
    sys.clock.advance(1000);
    const replayed = await sys.auth.authn.refresh({ refreshToken: first.refreshToken });

    // The session survives and a fresh successor was issued.
    const session = await sys.storage.sessions.get(first.principal.sessionId as string);
    assert.equal(session?.revokedAt, undefined);
    assert.notEqual(replayed.credentials.refreshToken, rotated.credentials.refreshToken);

    // The superseded successor is rejected without escalating.
    assert.equal(
      await codeOf(() =>
        sys.auth.authn.refresh({ refreshToken: rotated.credentials.refreshToken }),
      ),
      'TOKEN_INVALID',
    );
    assert.equal(sys.audit.ofType('refresh.superseded_presented').length, 1);
    assert.equal(sys.audit.ofType('refresh.reuse_detected').length, 0);

    // Beyond the window the same replay revokes the family.
    sys.clock.advance(6000);
    assert.equal(
      await codeOf(() => sys.auth.authn.refresh({ refreshToken: first.refreshToken })),
      'TOKEN_INVALID',
    );
    const after = await sys.storage.sessions.get(first.principal.sessionId as string);
    assert.equal(after?.revokedReason, 'refresh_reuse_detected');
  });

  it('fails refresh for a restricted account and revokes the session', async () => {
    const sys = createTestSystem();
    const userId = await sys.createUser('alice@example.com');
    const { refreshToken } = await sys.login('alice@example.com');
    // A direct status change without revocation, so the refresh flow's own gate is exercised.
    const user = await sys.storage.users.getById(userId);
    await sys.storage.users.setStatus(
      userId,
      'suspended',
      user?.version as number,
      sys.clock.now(),
    );

    assert.equal(
      await codeOf(() => sys.auth.authn.refresh({ refreshToken })),
      'ACCOUNT_RESTRICTED',
    );
    assert.equal(await sys.storage.sessions.countActive(userId, sys.clock.now()), 0);
  });

  it('rejects refresh after the session was revoked', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { refreshToken, principal } = await sys.login('alice@example.com');
    await sys.auth.authn.logout({ principal });
    assert.equal(await codeOf(() => sys.auth.authn.refresh({ refreshToken })), 'TOKEN_INVALID');
    assert.equal(sys.clock.now() > 0 && DAY > 0, true);
  });
});
