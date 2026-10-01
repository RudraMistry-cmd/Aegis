// Conformance cases from spec/conformance.md, profiles P-AUTHN, P-TRANSPORT-TOKEN and P-STORE-FULL.
// Each case states its id and the GIVEN / WHEN / THEN of the specification.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createTestSystem, MINUTE, TEST_PASSWORD } from '../support/fixtures.js';
import { ERROR_CODES, isAuthError, messageFor, type ErrorCode } from '../../src/index.js';

async function codeOf(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (e) {
    assert.ok(isAuthError(e), `expected an AuthError, got ${String(e)}`);
    return e.code;
  }
  assert.fail('expected the call to fail');
}

describe('P-AUTHN conformance', () => {
  it('AUTH-01: a valid login yields credentials, one session and the audit trail', async () => {
    // GIVEN a registered active user  WHEN she logs in with the correct password
    const sys = createTestSystem();
    const userId = await sys.createUser('alice@example.com', ['editor']);
    const r = await sys.auth.authn.login({
      identifier: 'alice@example.com',
      password: TEST_PASSWORD,
    });
    // THEN exactly one active session exists and both audit events were emitted
    assert.equal(await sys.storage.sessions.countActive(userId, sys.clock.now()), 1);
    assert.equal(sys.audit.ofType('login.succeeded').length, 1);
    assert.equal(sys.audit.ofType('session.created').length, 1);
    assert.ok(r.credentials.accessToken && r.credentials.refreshToken);
  });

  it('AUTH-05: a second login creates an independent session', async () => {
    // GIVEN one active session  WHEN the user logs in again
    const sys = createTestSystem();
    const userId = await sys.createUser('alice@example.com');
    const a = await sys.login('alice@example.com');
    sys.clock.advance(1000);
    const b = await sys.login('alice@example.com');
    // THEN the sessions differ and revoking one leaves the other usable
    assert.notEqual(a.principal.sessionId, b.principal.sessionId);
    assert.equal(await sys.storage.sessions.countActive(userId, sys.clock.now()), 2);
    await sys.auth.authn.logout({ principal: a.principal });
    assert.ok(await sys.auth.authn.resolve(b.accessToken));
    assert.equal(await sys.auth.authn.resolve(a.accessToken), null);
  });

  it('AUTH-ENUM-01: unknown identifier and wrong password are indistinguishable', async () => {
    // GIVEN one existing user  WHEN four different credential failures occur
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const shapes = new Set<string>();
    for (const input of [
      { identifier: 'nobody@example.com', password: TEST_PASSWORD },
      { identifier: 'alice@example.com', password: 'wrong-password-value' },
      { identifier: '%%%', password: TEST_PASSWORD },
      { identifier: 'alice@example.com', password: 'x'.repeat(1025) },
    ]) {
      try {
        await sys.auth.authn.login(input);
        assert.fail('login should have failed');
      } catch (e) {
        assert.ok(isAuthError(e));
        shapes.add(JSON.stringify(e.toJSON()));
      }
    }
    // THEN every response is byte-identical
    assert.equal(shapes.size, 1, [...shapes].join(' / '));
  });

  it('AUTH-ENUM-05: a suspended account is revealed only after the correct password', async () => {
    // GIVEN a suspended account
    const sys = createTestSystem();
    const userId = await sys.createUser('alice@example.com');
    await sys.setStatus(userId, 'suspended');
    // WHEN the wrong password is supplied  THEN INVALID_CREDENTIALS (no state hint)
    assert.equal(
      await codeOf(() =>
        sys.auth.authn.login({ identifier: 'alice@example.com', password: 'nope-nope-nope' }),
      ),
      'INVALID_CREDENTIALS',
    );
    // WHEN the correct password is supplied  THEN ACCOUNT_RESTRICTED
    assert.equal(
      await codeOf(() =>
        sys.auth.authn.login({ identifier: 'alice@example.com', password: TEST_PASSWORD }),
      ),
      'ACCOUNT_RESTRICTED',
    );
  });

  it('AUTH-TIM-01: exactly one hasher operation runs per credential attempt', async () => {
    // GIVEN an instrumented hasher  WHEN each credential path is exercised
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const calls = (): number => sys.hasher.calls.verify + sys.hasher.calls.dummyVerify;

    let before = calls();
    await sys.auth.authn
      .login({ identifier: 'nobody@example.com', password: TEST_PASSWORD })
      .catch(() => 0);
    assert.equal(calls() - before, 1, 'unknown identifier');

    before = calls();
    await sys.auth.authn
      .login({ identifier: 'alice@example.com', password: 'wrong-password-value' })
      .catch(() => 0);
    assert.equal(calls() - before, 1, 'wrong password');

    before = calls();
    await sys.auth.authn.login({ identifier: '%%%', password: TEST_PASSWORD }).catch(() => 0);
    assert.equal(calls() - before, 1, 'malformed identifier');

    // THEN the oversize-password path alone performs no hashing at all
    before = calls();
    await sys.auth.authn
      .login({ identifier: 'alice@example.com', password: 'x'.repeat(1025) })
      .catch(() => 0);
    assert.equal(calls() - before, 0, 'oversize password');
  });

  it('AUTH-THR-01: a blocked identifier is rejected before any lookup or hashing', async () => {
    // GIVEN five failed attempts against one identifier
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    for (let i = 0; i < 5; i++) {
      await sys.auth.authn
        .login({ identifier: 'alice@example.com', password: 'wrong-password-value' })
        .catch(() => 0);
    }
    const before = { ...sys.hasher.calls };
    // WHEN the correct password is then supplied  THEN RATE_LIMITED and no hasher call
    assert.equal(
      await codeOf(() =>
        sys.auth.authn.login({ identifier: 'alice@example.com', password: TEST_PASSWORD }),
      ),
      'RATE_LIMITED',
    );
    assert.equal(sys.hasher.calls.verify, before.verify);
    assert.equal(sys.hasher.calls.dummyVerify, before.dummyVerify);
    // AND the block expires with the window (no permanent lockout)
    sys.clock.advance(15 * MINUTE + 1);
    const ok = await sys.auth.authn.login({
      identifier: 'alice@example.com',
      password: TEST_PASSWORD,
    });
    assert.ok(ok.principal.id);
  });

  it('AUTH-THR-03: throttle counters move identically for existing and unknown identifiers', async () => {
    // GIVEN one existing and one unknown identifier  WHEN each receives the same failures
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const codes: string[][] = [];
    for (const identifier of ['alice@example.com', 'ghost@example.com']) {
      const seen: string[] = [];
      for (let i = 0; i < 6; i++) {
        seen.push(
          await codeOf(() =>
            sys.auth.authn.login({ identifier, password: 'wrong-password-value' }),
          ),
        );
      }
      codes.push(seen);
      sys.clock.advance(15 * MINUTE + 1);
    }
    // THEN the sequence of outcomes is the same for both
    assert.deepEqual(codes[0], codes[1]);
    assert.equal(codes[0]?.[5], 'RATE_LIMITED');
  });

  it('PRN-02: a serialized Principal carries no secret', async () => {
    // GIVEN a logged-in user  WHEN the Principal is serialized
    const sys = createTestSystem();
    const userId = await sys.createUser('alice@example.com');
    const { principal, accessToken, refreshToken } = await sys.login('alice@example.com');
    const credential = await sys.storage.credentials.get(userId, 'password');
    const dump = JSON.stringify(principal);
    // THEN no password, hash or token appears in it
    assert.ok(!dump.includes(TEST_PASSWORD));
    assert.ok(!dump.includes(credential?.payload as string));
    assert.ok(!dump.includes(accessToken));
    assert.ok(!dump.includes(refreshToken));
  });

  it('PRN-04: resolve returns null for every credential problem', async () => {
    // GIVEN a user with a session, later revoked
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { principal, accessToken } = await sys.login('alice@example.com');
    // WHEN assorted bad credentials are resolved  THEN each yields null, never an error
    for (const bad of ['', 'garbage', 'at1.x.y', null, undefined]) {
      assert.equal(await sys.auth.authn.resolve(bad as string), null, String(bad));
    }
    await sys.auth.authn.logout({ principal });
    assert.equal(await sys.auth.authn.resolve(accessToken), null, 'revoked session');
  });

  it('TOK-ACC-10: a refresh token is never accepted as an access token, nor the reverse', async () => {
    // GIVEN both credential kinds for one session
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { accessToken, refreshToken } = await sys.login('alice@example.com');
    // WHEN each is presented in the other's place  THEN both are rejected
    assert.equal(await sys.auth.authn.resolve(refreshToken), null);
    assert.equal(
      await codeOf(() => sys.auth.authn.refresh({ refreshToken: accessToken })),
      'TOKEN_INVALID',
    );
  });

  it('TOK-ACC-11: the malformed-token battery never throws and always rejects', async () => {
    // GIVEN a valid token and a set of adversarial mutations
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { accessToken } = await sys.login('alice@example.com');
    const parts = accessToken.split('.');
    const battery = [
      '',
      'x'.repeat(9000),
      'a'.repeat(1024 * 1024),
      'one',
      'one.two',
      'one.two.three.four',
      'at1..',
      'at1.!!!.!!!',
      `at1.${Buffer.from('not json').toString('base64url')}.${parts[2]}`,
      `at1.${Buffer.from('[1,2,3]').toString('base64url')}.${parts[2]}`,
      `at1.${Buffer.from('{"sub":null,"exp":"soon"}').toString('base64url')}.${parts[2]}`,
      `${parts[0]}.${parts[1]}.tampered`,
      `rt1.${parts[1]}.${parts[2]}`,
      `${parts[0]}.${parts[1]}`,
      accessToken.replace('at1', 'AT1'),
      `${accessToken}\u0000`,
      ` ${accessToken} `,
    ];
    // WHEN each is resolved  THEN null is returned and nothing throws
    for (const token of battery) {
      const started = Date.now();
      assert.equal(await sys.auth.authn.resolve(token), null, token.slice(0, 24));
      assert.ok(Date.now() - started < 1000);
    }
  });

  it('TOK-ACC-12: an issued access token carries no roles, permissions or PII', async () => {
    // GIVEN an admin with roles  WHEN a token is issued
    const sys = createTestSystem();
    await sys.createUser('alice@example.com', ['admin']);
    const { accessToken } = await sys.login('alice@example.com');
    const payload = JSON.parse(
      Buffer.from(accessToken.split('.')[1] as string, 'base64url').toString('utf8'),
    );
    // THEN the claim set is exactly the specified one
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
    assert.ok(!JSON.stringify(payload).includes('alice@example.com'));
    assert.ok(!JSON.stringify(payload).includes('admin'));
  });

  it('TOK-REF-02: no raw refresh token exists anywhere in the stores or the audit log', async () => {
    // GIVEN a rotation chain
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const first = await sys.login('alice@example.com');
    const second = await sys.auth.authn.refresh({ refreshToken: first.refreshToken });
    // WHEN every stored byte is dumped  THEN no raw secret appears
    const dump = JSON.stringify({
      tables: {
        refreshTokens: [...sys.storage.db.tables.refreshTokens.values()],
        index: [...sys.storage.db.tables.refreshTokenIndex.keys()],
        sessions: [...sys.storage.db.tables.sessions.values()],
        credentials: [...sys.storage.db.tables.credentials.values()],
      },
      audit: sys.audit.events(),
    });
    assert.ok(!dump.includes(first.refreshToken));
    assert.ok(!dump.includes(second.credentials.refreshToken));
  });

  it('REF-04: replaying a used refresh token revokes the family and the session', async () => {
    // GIVEN a rotated chain T1 -> T2
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const first = await sys.login('alice@example.com');
    const second = await sys.auth.authn.refresh({ refreshToken: first.refreshToken });
    // WHEN T1 is presented again
    assert.equal(
      await codeOf(() => sys.auth.authn.refresh({ refreshToken: first.refreshToken })),
      'TOKEN_INVALID',
    );
    // THEN the session is revoked, a high-severity alert exists and T2 is dead too (REF-05)
    const session = await sys.storage.sessions.get(first.principal.sessionId as string);
    assert.equal(session?.revokedReason, 'refresh_reuse_detected');
    const alerts = sys.audit.ofType('refresh.reuse_detected');
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0]?.severity, 'high');
    assert.ok(!JSON.stringify(alerts).includes(first.refreshToken));
    assert.equal(
      await codeOf(() => sys.auth.authn.refresh({ refreshToken: second.credentials.refreshToken })),
      'TOKEN_INVALID',
    );
  });

  it('REF-06: an expired refresh token reports TOKEN_EXPIRED and does not revive the session', async () => {
    // GIVEN a refresh token with a 1 s idle lifetime
    const sys = createTestSystem({ tokens: { refreshIdleTtlMs: 1000 } });
    await sys.createUser('alice@example.com');
    const { refreshToken, principal } = await sys.login('alice@example.com');
    // WHEN the clock passes the expiry  THEN TOKEN_EXPIRED
    sys.clock.advance(1000);
    assert.equal(await codeOf(() => sys.auth.authn.refresh({ refreshToken })), 'TOKEN_EXPIRED');
    const session = await sys.storage.sessions.get(principal.sessionId as string);
    assert.equal(session?.revokedAt, undefined, 'the session itself is untouched');
  });

  it('REF-17: reuse, unknown and revoked tokens produce identical responses', async () => {
    // GIVEN a used token, an unknown token and a revoked family
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const a = await sys.login('alice@example.com');
    await sys.auth.authn.refresh({ refreshToken: a.refreshToken });
    const b = await sys.login('alice@example.com');
    await sys.auth.authn.logout({ principal: b.principal });
    // WHEN each is presented  THEN the responses are byte-identical
    const shapes = new Set<string>();
    for (const token of [a.refreshToken, 'totally-unknown-token', b.refreshToken]) {
      try {
        await sys.auth.authn.refresh({ refreshToken: token });
        assert.fail('should have failed');
      } catch (e) {
        assert.ok(isAuthError(e));
        shapes.add(JSON.stringify(e.toJSON()));
      }
    }
    assert.equal(shapes.size, 1, [...shapes].join(' / '));
  });

  it('REV-04: after revocation returns, refresh fails immediately', async () => {
    // GIVEN an active session  WHEN it is revoked
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { principal, refreshToken } = await sys.login('alice@example.com');
    await sys.auth.authn.logout({ principal });
    // THEN every subsequent refresh fails, with no clock advance needed
    assert.equal(await codeOf(() => sys.auth.authn.refresh({ refreshToken })), 'TOKEN_INVALID');
    assert.equal(await codeOf(() => sys.auth.authn.refresh({ refreshToken })), 'TOKEN_INVALID');
  });

  it('REV-05: revoking twice succeeds and audits once', async () => {
    // GIVEN a revoked session  WHEN the revocation is repeated
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const { principal } = await sys.login('alice@example.com');
    await sys.auth.authn.logout({ principal });
    const first = await sys.storage.sessions.get(principal.sessionId as string);
    await sys.auth.authn.logout({ principal });
    // THEN the record is unchanged and only one audit event exists
    const second = await sys.storage.sessions.get(principal.sessionId as string);
    assert.deepEqual(second, first);
    assert.equal(
      sys.audit.ofType('session.revoked').filter((e) => e.target.id === principal.sessionId).length,
      1,
    );
  });

  it('SESS-07: the oldest session is evicted when the limit is reached', async () => {
    // GIVEN a limit of 3 with evict-oldest and three active sessions
    const sys = createTestSystem({ sessions: { max: 3, onLimit: 'evict-oldest' } });
    const userId = await sys.createUser('alice@example.com');
    const sessions: Awaited<ReturnType<typeof sys.login>>[] = [];
    for (let i = 0; i < 3; i++) {
      sessions.push(await sys.login('alice@example.com'));
      sys.clock.advance(1000);
    }
    // WHEN a fourth login happens
    await sys.login('alice@example.com');
    // THEN the oldest was evicted together with its refresh token
    assert.equal(await sys.storage.sessions.countActive(userId, sys.clock.now()), 3);
    const evicted = await sys.storage.sessions.get(sessions[0]?.principal.sessionId as string);
    assert.equal(evicted?.revokedReason, 'evicted');
    assert.equal(
      await codeOf(() =>
        sys.auth.authn.refresh({ refreshToken: sessions[0]?.refreshToken as string }),
      ),
      'TOKEN_INVALID',
    );
    assert.equal(sys.audit.ofType('session.evicted').length, 1);
  });

  it('SESS-10: another user’s session id is indistinguishable from an unknown one', async () => {
    // GIVEN two users with sessions
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    await sys.createUser('bob@example.com');
    const alice = await sys.login('alice@example.com');
    const bob = await sys.login('bob@example.com');
    // WHEN bob tries to revoke alice's session and an unknown id  THEN both answer identically
    const shapes = new Set<string>();
    for (const id of [alice.principal.sessionId as string, 'no-such-session-id']) {
      try {
        await sys.auth.authn.revokeSession(bob.principal, id);
        assert.fail('should have failed');
      } catch (e) {
        assert.ok(isAuthError(e));
        shapes.add(JSON.stringify(e.toJSON()));
      }
    }
    assert.equal(shapes.size, 1);
  });

  it('TIME-01: expiry boundaries are inclusive of the instant', async () => {
    // GIVEN a session with a 10-minute idle and 30-minute absolute lifetime
    const sys = createTestSystem({
      sessions: { idleTtlMs: 10 * MINUTE, absoluteTtlMs: 30 * MINUTE },
    });
    await sys.createUser('alice@example.com');
    const { accessToken, principal } = await sys.login('alice@example.com');
    const session = await sys.storage.sessions.get(principal.sessionId as string);
    // WHEN the clock is set to one millisecond before and then at the idle expiry
    sys.clock.set((session?.idleExpiresAt as number) - 1);
    assert.ok(await sys.auth.authn.resolve(accessToken), 'valid one ms before');
    sys.clock.set(session?.idleExpiresAt as number);
    // THEN the session is expired exactly at the instant, with no housekeeping run
    assert.equal(await sys.auth.authn.resolve(accessToken), null);
  });

  it('ERR-01: every error code carries its fixed message and no variable data', async () => {
    // GIVEN the error catalog  WHEN messages are produced
    for (const code of ERROR_CODES) {
      const message = messageFor(code as ErrorCode);
      // THEN each is a fixed sentence with no interpolation
      assert.ok(message.length > 0);
      assert.ok(!/[{}$]/.test(message), code);
    }
    // AND a live failure uses exactly that text
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    try {
      await sys.auth.authn.login({
        identifier: 'alice@example.com',
        password: 'wrong-password-value',
      });
      assert.fail('should have failed');
    } catch (e) {
      assert.ok(isAuthError(e));
      assert.equal(e.message, messageFor('INVALID_CREDENTIALS'));
      assert.equal(JSON.stringify(e.toJSON()).includes('alice@example.com'), false);
    }
  });

  it('ERR-02: the internal cause is never part of the serialized error', async () => {
    // GIVEN a storage failure injected into the user store
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const original = sys.storage.users.getById.bind(sys.storage.users);
    sys.storage.users.getById = async () => {
      throw new Error('driver exploded: secret-connection-string');
    };
    // WHEN a login is attempted  THEN the error is STORAGE_UNAVAILABLE without the driver text
    try {
      await sys.auth.authn.login({ identifier: 'alice@example.com', password: TEST_PASSWORD });
      assert.fail('should have failed');
    } catch (e) {
      assert.ok(isAuthError(e));
      assert.equal(e.code, 'STORAGE_UNAVAILABLE');
      const serialized = JSON.stringify(e.toJSON());
      assert.ok(!serialized.includes('driver exploded'));
      assert.ok(!serialized.includes('secret-connection-string'));
    } finally {
      sys.storage.users.getById = original;
    }
  });
});
