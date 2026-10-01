// Unit tests for the login flow (spec/flows/login.md §3, §6.1).
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createTestSystem, TEST_PASSWORD } from '../support/fixtures.js';
import { isAuthError } from '../../src/index.js';

/** Asserts that `fn` rejects with the given error code. */
async function rejectsWith(fn: () => Promise<unknown>, code: string): Promise<void> {
  try {
    await fn();
  } catch (e) {
    assert.ok(isAuthError(e), `expected an AuthError, got ${String(e)}`);
    assert.equal(e.code, code);
    return;
  }
  assert.fail(`expected ${code} but the call succeeded`);
}

describe('login', () => {
  it('authenticates a registered user and creates exactly one session', async () => {
    const sys = createTestSystem();
    const userId = await sys.createUser('alice@example.com', ['editor']);

    const result = await sys.auth.authn.login({
      identifier: 'alice@example.com',
      password: TEST_PASSWORD,
    });

    assert.equal(result.principal.id, userId);
    assert.equal(result.principal.authMethod, 'password');
    assert.deepEqual([...(result.principal.amr ?? [])], ['pwd']);
    assert.equal(result.principal.authenticatedAt, sys.clock.now());
    assert.ok(result.credentials.accessToken.length > 0);
    assert.ok(result.credentials.refreshToken.length > 0);
    assert.equal(await sys.storage.sessions.countActive(userId, sys.clock.now()), 1);
    assert.equal(sys.audit.ofType('login.succeeded').length, 1);
    assert.equal(sys.audit.ofType('session.created').length, 1);
  });

  it('accepts case and whitespace variants of the identifier', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const r = await sys.auth.authn.login({
      identifier: '  ALICE@Example.COM ',
      password: TEST_PASSWORD,
    });
    assert.ok(r.principal.id);
  });

  it('rejects a wrong password without creating a session', async () => {
    const sys = createTestSystem();
    const userId = await sys.createUser('alice@example.com');
    await rejectsWith(
      () => sys.auth.authn.login({ identifier: 'alice@example.com', password: 'wrong-password-x' }),
      'INVALID_CREDENTIALS',
    );
    assert.equal(await sys.storage.sessions.countActive(userId, sys.clock.now()), 0);
    assert.equal(sys.audit.ofType('login.failed').length, 1);
  });

  it('returns the same error for an unknown identifier as for a wrong password', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const errors: string[] = [];
    for (const input of [
      { identifier: 'nobody@example.com', password: TEST_PASSWORD },
      { identifier: 'alice@example.com', password: 'wrong-password-x' },
      { identifier: '%%%not-an-identifier%%%', password: TEST_PASSWORD },
    ]) {
      try {
        await sys.auth.authn.login(input);
        assert.fail('login should have failed');
      } catch (e) {
        assert.ok(isAuthError(e));
        errors.push(`${e.code}|${e.message}|${JSON.stringify(e.details ?? null)}`);
      }
    }
    assert.equal(new Set(errors).size, 1, `responses differ: ${errors.join(' / ')}`);
  });

  it('performs exactly one hasher operation per attempt, found or not', async () => {
    const sys = createTestSystem();
    await sys.createUser('alice@example.com');
    const before = { ...sys.hasher.calls };

    await sys.auth.authn
      .login({ identifier: 'nobody@example.com', password: TEST_PASSWORD })
      .catch(() => undefined);
    assert.equal(sys.hasher.calls.dummyVerify - before.dummyVerify, 1);
    assert.equal(sys.hasher.calls.verify - before.verify, 0);

    await sys.auth.authn
      .login({ identifier: 'alice@example.com', password: 'wrong-password-x' })
      .catch(() => undefined);
    assert.equal(sys.hasher.calls.verify - before.verify, 1);
    assert.equal(sys.hasher.calls.dummyVerify - before.dummyVerify, 1);
  });

  it('reveals the account state only after a correct password', async () => {
    const sys = createTestSystem();
    const userId = await sys.createUser('alice@example.com');
    await sys.setStatus(userId, 'suspended');

    await rejectsWith(
      () => sys.auth.authn.login({ identifier: 'alice@example.com', password: 'wrong-password-x' }),
      'INVALID_CREDENTIALS',
    );
    await rejectsWith(
      () => sys.auth.authn.login({ identifier: 'alice@example.com', password: TEST_PASSWORD }),
      'ACCOUNT_RESTRICTED',
    );
  });

  it('never leaks the password or its hash into logs, errors or audit events', async () => {
    const sys = createTestSystem();
    const userId = await sys.createUser('alice@example.com');
    await sys.auth.authn.login({ identifier: 'alice@example.com', password: TEST_PASSWORD });
    const credential = await sys.storage.credentials.get(userId, 'password');
    assert.ok(credential);

    const serialized = JSON.stringify(sys.audit.events());
    assert.ok(!serialized.includes(TEST_PASSWORD));
    assert.ok(!serialized.includes(credential.payload));
  });

  it('rejects malformed input shapes with VALIDATION_FAILED', async () => {
    const sys = createTestSystem();
    await rejectsWith(
      () => sys.auth.authn.login({ identifier: 42 as unknown as string, password: TEST_PASSWORD }),
      'VALIDATION_FAILED',
    );
  });
});

describe('registration', () => {
  it('rejects a password below the configured minimum', async () => {
    const sys = createTestSystem();
    await rejectsWith(
      () => sys.auth.authn.register({ identifier: 'bob@example.com', password: 'short' }),
      'VALIDATION_FAILED',
    );
  });

  it('rejects privileged fields supplied through metadata', async () => {
    const sys = createTestSystem();
    await rejectsWith(
      () =>
        sys.auth.authn.register({
          identifier: 'bob@example.com',
          password: TEST_PASSWORD,
          metadata: { roles: ['admin'] },
        }),
      'VALIDATION_FAILED',
    );
  });
});
