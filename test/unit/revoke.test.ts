// Unit tests for revocation, logout and session invalidation (spec/flows/revoke.md).
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createTestSystem } from '../support/fixtures.js';
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

describe('session revocation', () => {
  it('revokes the session and its refresh family on logout', async () => {
    const sys = createTestSystem();
    const userId = await sys.createUser('alice@example.com');
    const { principal, refreshToken, accessToken } = await sys.login('alice@example.com');

    await sys.auth.authn.logout({ principal });

    const session = await sys.storage.sessions.get(principal.sessionId as string);
    assert.equal(session?.revokedReason, 'logout');
    const family = [...sys.storage.db.tables.refreshTokens.values()].filter(
      (t) => t.sessionId === principal.sessionId,
    );
    assert.ok(
      family.every((t) => t.status !== 'active'),
      'no family token may stay active',
    );
    assert.equal(await codeOf(() => sys.auth.authn.refresh({ refreshToken })), 'TOKEN_INVALID');
    assert.equal(await sys.auth.authn.resolve(accessToken), null);
    assert.equal(await sys.storage.sessions.countActive(userId, sys.clock.now()), 0);
  });

  it('is idempotent and audits each revocation exactly once', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { principal } = await sys.login('alice@example.com');

    await sys.auth.authn.logout({ principal });
    await sys.auth.authn.logout({ principal });
    await sys.auth.authn.logout({ principal });

    const revoked = sys.audit
      .ofType('session.revoked')
      .filter((e) => e.target.id === principal.sessionId);
    assert.equal(revoked.length, 1);
  });

  it('succeeds without effect for unknown, malformed or already-used credentials', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    await sys.auth.authn.logout({ refreshToken: 'not-a-real-token' });
    await sys.auth.authn.logout({ refreshToken: '' });
    await sys.auth.authn.logout({});
  });

  it('never resurrects a revoked session', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { principal, refreshToken } = await sys.login('alice@example.com');
    await sys.auth.authn.logout({ principal });

    // Touch, refresh and a second login must all leave the old session terminal.
    assert.equal(
      await sys.storage.sessions.touch(
        principal.sessionId as string,
        sys.clock.now(),
        sys.clock.now() + 1000,
      ),
      false,
    );
    await sys.auth.authn.refresh({ refreshToken }).catch(() => undefined);
    const second = await sys.login('alice@example.com');
    assert.notEqual(second.principal.sessionId, principal.sessionId);
    const old = await sys.storage.sessions.get(principal.sessionId as string);
    assert.ok(old?.revokedAt !== undefined);
  });

  it('logs out all other devices but keeps the current session', async () => {
    const sys = createTestSystem();
    const userId = await sys.createUser('alice@example.com');
    const a = await sys.login('alice@example.com');
    sys.clock.advance(1000);
    const b = await sys.login('alice@example.com');
    sys.clock.advance(1000);
    const c = await sys.login('alice@example.com');
    assert.equal(await sys.storage.sessions.countActive(userId, sys.clock.now()), 3);

    const revoked = await sys.auth.authn.logoutAll(c.principal);
    assert.equal(revoked, 2);
    assert.equal(await sys.storage.sessions.countActive(userId, sys.clock.now()), 1);
    assert.equal(
      await codeOf(() => sys.auth.authn.refresh({ refreshToken: a.refreshToken })),
      'TOKEN_INVALID',
    );
    assert.equal(
      await codeOf(() => sys.auth.authn.refresh({ refreshToken: b.refreshToken })),
      'TOKEN_INVALID',
    );

    // The caller's own session still works.
    const rotated = await sys.auth.authn.refresh({ refreshToken: c.refreshToken });
    assert.ok(rotated.credentials.accessToken.length > 0);

    // A second call revokes nothing and still succeeds.
    assert.equal(await sys.auth.authn.logoutAll(c.principal), 0);
  });

  it('hides sessions the caller may not act on', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    await sys.createUser('bob@example.com');
    const alice = await sys.login('alice@example.com');
    const bob = await sys.login('bob@example.com');

    // Bob is not authorized for Alice's session: indistinguishable from an unknown id.
    assert.equal(
      await codeOf(() =>
        sys.auth.authn.revokeSession(bob.principal, alice.principal.sessionId as string),
      ),
      'NOT_FOUND',
    );
    assert.equal(
      await codeOf(() => sys.auth.authn.revokeSession(bob.principal, 'no-such-session')),
      'NOT_FOUND',
    );
    const stillThere = await sys.storage.sessions.get(alice.principal.sessionId as string);
    assert.equal(stillThere?.revokedAt, undefined);
  });

  it('lets an authorized admin revoke another session', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    await sys.createUser('admin@example.com', ['admin']);
    const alice = await sys.login('alice@example.com');
    const admin = await sys.login('admin@example.com');

    await sys.auth.authn.revokeSession(admin.principal, alice.principal.sessionId as string);
    const session = await sys.storage.sessions.get(alice.principal.sessionId as string);
    assert.equal(session?.revokedReason, 'admin');
  });

  it('bumps securityVersion when credentials are invalidated', async () => {
    const sys = createTestSystem();
    const userId = await sys.createUser('alice@example.com');
    await sys.createUser('admin@example.com', ['admin']);
    const alice = await sys.login('alice@example.com');
    const admin = await sys.login('admin@example.com');
    const before = await sys.storage.users.getById(userId);

    await sys.auth.authn.invalidateCredentials(admin.principal, userId);

    const after = await sys.storage.users.getById(userId);
    assert.equal(after?.securityVersion, (before?.securityVersion as number) + 1);
    assert.equal(await sys.auth.authn.resolve(alice.accessToken), null);
  });

  it('enforces the session limit with eviction', async () => {
    const sys = createTestSystem({ sessions: { max: 2, onLimit: 'evict-oldest' } });
    const userId = await sys.createUser('alice@example.com');
    const first = await sys.login('alice@example.com');
    sys.clock.advance(1000);
    await sys.login('alice@example.com');
    sys.clock.advance(1000);
    await sys.login('alice@example.com');

    assert.equal(await sys.storage.sessions.countActive(userId, sys.clock.now()), 2);
    const evicted = await sys.storage.sessions.get(first.principal.sessionId as string);
    assert.equal(evicted?.revokedReason, 'evicted');
    // The evicted session's refresh token died with it (session.md §6.6).
    assert.equal(
      await codeOf(() => sys.auth.authn.refresh({ refreshToken: first.refreshToken })),
      'TOKEN_INVALID',
    );
  });

  it('rejects a new login when the limit policy is reject', async () => {
    const sys = createTestSystem({ sessions: { max: 1, onLimit: 'reject' } });
    const userId = await sys.createUser('alice@example.com');
    await sys.login('alice@example.com');
    assert.equal(await codeOf(() => sys.login('alice@example.com')), 'SESSION_LIMIT_REACHED');
    assert.equal(await sys.storage.sessions.countActive(userId, sys.clock.now()), 1);
  });
});
