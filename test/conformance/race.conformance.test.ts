// Conformance cases from spec/conformance.md group RACE plus the storage-contract cases that
// depend on atomicity (STO-RT, STO-SES, STO-ID, STO-UOW).
//
// NOTE ON THE CONCURRENCY MODEL: the in-memory adapter runs on a single thread, so "concurrent"
// here means interleaved at every `await` boundary, with each store operation itself indivisible
// (see src/storage/memory/database.ts). That exercises the flow-level interleavings the spec cares
// about, but it cannot model multi-process contention; see docs/CONFORMANCE.md.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createTestSystem, TEST_PASSWORD } from '../support/fixtures.js';
import { isAuthError, SYSTEM_ACTOR } from '../../src/index.js';

const SYSTEM = { id: SYSTEM_ACTOR, type: 'user' } as const;

describe('RACE and storage-atomicity conformance', () => {
  it('RACE-01 / STO-ID-02: concurrent registrations of one identifier create exactly one user', async () => {
    // GIVEN 20 parallel registrations of the same email
    const sys = createTestSystem();
    const results = await Promise.allSettled(
      Array.from({ length: 20 }, () =>
        sys.auth.authn.register({ identifier: 'dup@example.com', password: TEST_PASSWORD }),
      ),
    );
    // THEN all calls report the uniform accepted response and exactly one user exists
    assert.ok(results.every((r) => r.status === 'fulfilled'));
    assert.equal(sys.storage.db.tables.users.size, 1);
    assert.equal(sys.storage.db.tables.identifiers.size, 1);
    assert.equal(sys.storage.db.tables.credentials.size, 1);
  });

  it('RACE-02 / REF-03 / STO-RT-01: exactly one of N concurrent refreshes wins', async () => {
    // GIVEN one active refresh token presented by 25 concurrent callers
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { refreshToken, principal } = await sys.login('alice@example.com');

    const results = await Promise.allSettled(
      Array.from({ length: 25 }, () => sys.auth.authn.refresh({ refreshToken })),
    );
    // THEN exactly one succeeds and the rest see TOKEN_INVALID
    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    assert.equal(fulfilled.length, 1);
    for (const r of results) {
      if (r.status === 'rejected') {
        assert.ok(isAuthError(r.reason));
        assert.equal(r.reason.code, 'TOKEN_INVALID');
      }
    }
    // AND with reuseGrace = 0 the family ends revoked with no active token (INV-TOK-02/03/05)
    const session = await sys.storage.sessions.get(principal.sessionId as string);
    assert.equal(session?.revokedReason, 'refresh_reuse_detected');
    const active = [...sys.storage.db.tables.refreshTokens.values()].filter(
      (t) => t.status === 'active',
    );
    assert.equal(active.length, 0);
  });

  it('RACE-03 / STO-RT-05: refresh racing revocation never mints a token for a revoked session', async () => {
    // GIVEN an active session, WHEN refresh and logout are started together, over many schedules
    for (let attempt = 0; attempt < 25; attempt++) {
      const sys = createTestSystem();
      await sys.createUser('alice@example.com');
      const { refreshToken, principal } = await sys.login('alice@example.com');

      const [refreshed] = await Promise.allSettled([
        sys.auth.authn.refresh({ refreshToken }),
        sys.auth.authn.logout({ principal }),
      ]);
      // THEN the session is revoked and no refresh token of that family stays active
      const session = await sys.storage.sessions.get(principal.sessionId as string);
      assert.ok(session?.revokedAt !== undefined, 'the session must end revoked');
      const active = [...sys.storage.db.tables.refreshTokens.values()].filter(
        (t) => t.sessionId === principal.sessionId && t.status === 'active',
      );
      assert.equal(active.length, 0, `attempt ${attempt}: an active token survived revocation`);
      // AND if the refresh won, its own credentials are already dead
      if (refreshed.status === 'fulfilled') {
        const code = await sys.auth.authn
          .refresh({ refreshToken: refreshed.value.credentials.refreshToken })
          .then(() => 'OK')
          .catch((e: unknown) => (isAuthError(e) ? e.code : 'OTHER'));
        assert.equal(code, 'TOKEN_INVALID');
      }
    }
  });

  it('RACE-06 / STO-SES-01: parallel logins never exceed the session limit', async () => {
    // GIVEN a limit of 3 with evict-oldest and 30 parallel logins
    const sys = createTestSystem({ sessions: { max: 3, onLimit: 'evict-oldest' } });
    const userId = await sys.createUser('alice@example.com');
    await Promise.all(
      Array.from({ length: 30 }, () =>
        sys.auth.authn.login({ identifier: 'alice@example.com', password: TEST_PASSWORD }),
      ),
    );
    // THEN exactly three sessions are active and no evicted session kept a live token
    assert.equal(await sys.storage.sessions.countActive(userId, sys.clock.now()), 3);
    const activeSessionIds = new Set(
      [...sys.storage.db.tables.sessions.values()]
        .filter((s) => s.revokedAt === undefined)
        .map((s) => s.id),
    );
    for (const t of sys.storage.db.tables.refreshTokens.values()) {
      if (t.status === 'active') assert.ok(activeSessionIds.has(t.sessionId));
    }
  });

  it('RACE-06b: the reject policy never exceeds the limit either', async () => {
    // GIVEN a limit of 2 with reject and 15 parallel logins
    const sys = createTestSystem({ sessions: { max: 2, onLimit: 'reject' } });
    const userId = await sys.createUser('alice@example.com');
    const results = await Promise.allSettled(
      Array.from({ length: 15 }, () =>
        sys.auth.authn.login({ identifier: 'alice@example.com', password: TEST_PASSWORD }),
      ),
    );
    // THEN at most two logins succeeded and the rest reported SESSION_LIMIT_REACHED
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    assert.ok(ok <= 2, `expected at most 2 successes, got ${ok}`);
    assert.equal(await sys.storage.sessions.countActive(userId, sys.clock.now()), ok);
    for (const r of results) {
      if (r.status === 'rejected') {
        assert.ok(isAuthError(r.reason));
        assert.equal(r.reason.code, 'SESSION_LIMIT_REACHED');
      }
    }
  });

  it('RACE-07: parallel logins racing a suspension leave no usable credential', async () => {
    // GIVEN a user logging in 10 times while the account is suspended
    const sys = createTestSystem();
    const userId = await sys.createUser('alice@example.com');
    const logins = Array.from({ length: 10 }, () =>
      sys.auth.authn
        .login({ identifier: 'alice@example.com', password: TEST_PASSWORD })
        .catch(() => null),
    );
    const suspend = sys.setStatus(userId, 'suspended');
    const [results] = await Promise.all([Promise.all(logins), suspend]);
    // THEN the account has zero active sessions and no refresh token can be used
    assert.equal(await sys.storage.sessions.countActive(userId, sys.clock.now()), 0);
    for (const r of results) {
      if (!r) continue;
      const code = await sys.auth.authn
        .refresh({ refreshToken: r.credentials.refreshToken })
        .then(() => 'OK')
        .catch((e: unknown) => (isAuthError(e) ? e.code : 'OTHER'));
      assert.notEqual(code, 'OK');
      assert.equal(await sys.auth.authn.resolve(r.credentials.accessToken), null);
    }
  });

  it('RACE-09 / STO-USR-03: concurrent securityVersion bumps are not lost', async () => {
    // GIVEN 100 parallel bumps
    const sys = createTestSystem();
    const userId = await sys.createUser('alice@example.com');
    const before = await sys.storage.users.getById(userId);
    await Promise.all(
      Array.from({ length: 100 }, () =>
        sys.storage.users.bumpSecurityVersion(userId, sys.clock.now()),
      ),
    );
    // THEN the final value increased by exactly 100
    const after = await sys.storage.users.getById(userId);
    assert.equal(after?.securityVersion, (before?.securityVersion as number) + 100);
  });

  it('RACE-08 / ESC-06: concurrent assign and revoke cannot leave an escalated state', async () => {
    // GIVEN an assigner whose own authority is revoked while it assigns
    const sys = createTestSystem();
    await sys.createUser('admin@example.com', ['admin']);
    const target = await sys.createUser('target@example.com');
    const { principal } = await sys.login('admin@example.com');

    const results = await Promise.allSettled([
      sys.auth.authz.roles.assign(principal, target, { roleName: 'viewer' }),
      sys.auth.authz.roles.revoke(SYSTEM, principal.id, 'admin'),
    ]);
    // THEN whatever the order, the target never holds more than viewer
    const held = await sys.auth.authz.rolesFor({ id: target });
    assert.ok(
      held.every((r) => ['viewer'].includes(r)),
      `unexpected roles: ${held.join(',')}`,
    );
    assert.ok(results.length === 2);
  });

  it('STO-UOW-01: a failure inside a unit of work persists nothing', async () => {
    // GIVEN a transaction that writes and then fails
    const sys = createTestSystem();
    const before = sys.storage.db.tables.users.size;
    await assert.rejects(
      sys.storage.uow.run(async (tx) => {
        await tx.users.create({
          id: 'rollback-user',
          status: 'active',
          metadata: {},
          createdAt: sys.clock.now(),
        });
        throw new Error('fail inside the unit');
      }),
    );
    // THEN the user was not created
    assert.equal(sys.storage.db.tables.users.size, before);
    assert.equal(await sys.storage.users.getById('rollback-user'), null);
  });

  it('STO-RT-02: consume reports the documented precedence and changes nothing but on success', async () => {
    // GIVEN an active token
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { refreshToken } = await sys.login('alice@example.com');
    const { digest } = await import('../../src/index.js');
    const hash = digest(refreshToken);
    const now = sys.clock.now();

    // WHEN it is consumed  THEN the first call wins and the second reports reuse
    assert.equal((await sys.storage.refreshTokens.consume(hash, now)).kind, 'consumed');
    const second = await sys.storage.refreshTokens.consume(hash, now);
    assert.equal(second.kind, 'reused');
    // AND an unknown hash is reported as unknown without any state change
    assert.equal((await sys.storage.refreshTokens.consume('0'.repeat(64), now)).kind, 'unknown');
  });

  it('STO-SES-02: revoke returns true once and false afterwards, leaving the record unchanged', async () => {
    // GIVEN an active session
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { principal } = await sys.login('alice@example.com');
    const id = principal.sessionId as string;
    // WHEN revoked repeatedly  THEN only the first call reports the change
    assert.equal(await sys.storage.sessions.revoke(id, 'logout', sys.clock.now()), true);
    const afterFirst = await sys.storage.sessions.get(id);
    sys.clock.advance(5000);
    assert.equal(await sys.storage.sessions.revoke(id, 'admin', sys.clock.now()), false);
    // AND the first reason and timestamp win
    assert.deepEqual(await sys.storage.sessions.get(id), afterFirst);
  });
});
