// End-to-end Aegis flows over PostgreSQL: the Phase 1 conformance cases that exercise storage,
// re-run through createAuth with the PostgreSQL adapter and audit events persisted to the database.
// Domain logic is unchanged; only the storage behind it is real.
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { isAuthError, SYSTEM_ACTOR } from '../../src/index.js';
import { PostgresAuditSink } from '../../src/storage/postgres/index.js';
import { createPgSystem, TEST_PASSWORD, type PgSystem } from './harness.js';

const SYSTEM = { id: SYSTEM_ACTOR, type: 'user' } as const;
const MINUTE = 60_000;
let n = 0;
const email = (p: string): string => `${p}-${++n}@example.com`;

async function codeOf(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (e) {
    assert.ok(isAuthError(e), `expected an AuthError, got ${String(e)}`);
    return e.code;
  }
  return 'OK';
}

describe('Aegis flows on PostgreSQL', () => {
  let sys: PgSystem;

  before(async () => {
    sys = await createPgSystem({
      pgAudit: true,
      sessions: {
        max: 3,
        onLimit: 'evict-oldest',
        idleTtlMs: 10 * MINUTE,
        absoluteTtlMs: 60 * MINUTE,
      },
    });
  });
  after(async () => sys.dispose());

  /** Audit rows of one type, after flushing the asynchronous sink. */
  const auditRows = async (
    type: string,
  ): Promise<{ severity: string; target_id: string | null; details: unknown }[]> => {
    await (sys.audit as PostgresAuditSink).flush();
    const r = await sys.storage.client.query<{
      severity: string;
      target_id: string | null;
      details: unknown;
    }>('SELECT severity, target_id, details FROM aegis.audit_events WHERE type = $1', [type]);
    return r.rows;
  };

  it('AUTH-01: login creates one session, one active token and the audit trail', async () => {
    const e = email('alice');
    const id = await sys.createUser(e, ['editor']);
    const { principal } = await sys.login(e);
    assert.equal(principal.id, id);
    assert.equal(await sys.storage.sessions.countActive(id, sys.clock.now()), 1);
    const tokens = await sys.storage.client.query(
      "SELECT count(*)::int AS n FROM aegis.refresh_tokens WHERE session_id = $1 AND status = 'active'",
      [principal.sessionId],
    );
    assert.equal((tokens.rows[0] as { n: number }).n, 1);
    assert.ok((await auditRows('login.succeeded')).length >= 1);
  });

  it('AUTH-ENUM-01: unknown identifier and wrong password are indistinguishable', async () => {
    const e = email('enum');
    await sys.createUser(e);
    const shapes = new Set<string>();
    for (const input of [
      { identifier: email('nobody'), password: TEST_PASSWORD },
      { identifier: e, password: 'wrong-password-value' },
    ]) {
      try {
        await sys.auth.authn.login(input);
      } catch (err) {
        assert.ok(isAuthError(err));
        shapes.add(JSON.stringify(err.toJSON()));
      }
    }
    assert.equal(shapes.size, 1);
  });

  it('REF-01: a rotation chain keeps the session, and every predecessor is spent', async () => {
    const e = email('rot');
    await sys.createUser(e);
    const first = await sys.login(e);
    const chain = [first.refreshToken];
    for (let i = 0; i < 4; i++) {
      sys.clock.advance(MINUTE);
      const r = await sys.auth.authn.refresh({ refreshToken: chain[chain.length - 1] as string });
      assert.equal(r.principal.sessionId, first.principal.sessionId);
      assert.equal(r.principal.authenticatedAt, first.principal.authenticatedAt);
      chain.push(r.credentials.refreshToken);
    }
    assert.equal(new Set(chain).size, chain.length, 'every successor is new');
    // Exactly one token of the family is active — the newest. All predecessors are `used`.
    const states = await sys.storage.client.query<{ status: string; n: number }>(
      `SELECT status, count(*)::int AS n FROM aegis.refresh_tokens
        WHERE session_id = $1 GROUP BY status ORDER BY status`,
      [first.principal.sessionId],
    );
    assert.deepEqual(states.rows, [
      { status: 'active', n: 1 },
      { status: 'used', n: 4 },
    ]);
    // Presenting any predecessor is a reuse.
    assert.equal(
      await codeOf(() => sys.auth.authn.refresh({ refreshToken: chain[1] as string })),
      'TOKEN_INVALID',
    );
  });

  it('REF-04/05: replaying a used token revokes the family, alerts high, kills the successor', async () => {
    const e = email('reuse');
    await sys.createUser(e);
    const first = await sys.login(e);
    const second = await sys.auth.authn.refresh({ refreshToken: first.refreshToken });
    assert.equal(
      await codeOf(() => sys.auth.authn.refresh({ refreshToken: first.refreshToken })),
      'TOKEN_INVALID',
    );
    const s = await sys.storage.sessions.get(first.principal.sessionId as string);
    assert.equal(s?.revokedReason, 'refresh_reuse_detected');
    assert.equal(
      await codeOf(() => sys.auth.authn.refresh({ refreshToken: second.credentials.refreshToken })),
      'TOKEN_INVALID',
    );
    const alerts = (await auditRows('refresh.reuse_detected')).filter(
      (r) => r.target_id === first.principal.sessionId,
    );
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0]?.severity, 'high');
    // Raw tokens never reach the database, not even the audit log.
    const dump = await sys.storage.client.query(
      "SELECT string_agg(details::text || context::text, '') AS all FROM aegis.audit_events",
    );
    assert.ok(!String((dump.rows[0] as { all: string }).all).includes(first.refreshToken));
  });

  it('REV-04/05: after logout, refresh and resolve fail immediately; repeats change nothing', async () => {
    const e = email('rev');
    await sys.createUser(e);
    const { principal, refreshToken, accessToken } = await sys.login(e);
    await sys.auth.authn.logout({ principal });
    const once = await sys.storage.sessions.get(principal.sessionId as string);
    await sys.auth.authn.logout({ principal });
    assert.deepEqual(await sys.storage.sessions.get(principal.sessionId as string), once);
    assert.equal(await codeOf(() => sys.auth.authn.refresh({ refreshToken })), 'TOKEN_INVALID');
    assert.equal(await sys.auth.authn.resolve(accessToken), null);
  });

  it('SESS-07: the fourth login evicts the oldest session and its token', async () => {
    const e = email('evict');
    const id = await sys.createUser(e);
    const sessions = [];
    for (let i = 0; i < 3; i++) {
      sessions.push(await sys.login(e));
      sys.clock.advance(1000);
    }
    await sys.login(e);
    assert.equal(await sys.storage.sessions.countActive(id, sys.clock.now()), 3);
    const oldest = sessions[0];
    assert.equal(
      (await sys.storage.sessions.get(oldest?.principal.sessionId as string))?.revokedReason,
      'evicted',
    );
    assert.equal(
      await codeOf(() => sys.auth.authn.refresh({ refreshToken: oldest?.refreshToken as string })),
      'TOKEN_INVALID',
    );
  });

  it('REV logoutAll: revokes the other sessions and keeps the current one', async () => {
    const e = email('all');
    const id = await sys.createUser(e);
    await sys.login(e);
    sys.clock.advance(1000);
    const current = await sys.login(e);
    assert.equal(await sys.auth.authn.logoutAll(current.principal), 1);
    assert.equal(await sys.storage.sessions.countActive(id, sys.clock.now()), 1);
    assert.ok(await sys.auth.authn.resolve(current.accessToken));
  });

  it('MID-01/02: role changes take effect mid-session on the same token', async () => {
    const e = email('mid');
    const id = await sys.createUser(e);
    const { accessToken } = await sys.login(e);
    const before = await sys.auth.authn.resolve(accessToken);
    assert.equal(await sys.auth.authz.can(before, 'read', 'post'), false);
    await sys.auth.authz.roles.assign(SYSTEM, id, { roleName: 'viewer' });
    assert.equal(
      await sys.auth.authz.can(await sys.auth.authn.resolve(accessToken), 'read', 'post'),
      true,
    );
    await sys.auth.authz.roles.revoke(SYSTEM, id, 'viewer');
    const after = await sys.auth.authn.resolve(accessToken);
    assert.ok(after, 'the token itself stays valid');
    assert.equal(await sys.auth.authz.can(after, 'read', 'post'), false);
  });

  it('ESC-03/09: escalation guards hold with assignments persisted in PostgreSQL', async () => {
    const adminEmail = email('admin');
    const admin = await sys.createUser(adminEmail, ['admin']);
    const target = await sys.createUser(email('tgt'));
    const { principal } = await sys.login(adminEmail);
    assert.equal(
      await codeOf(() => sys.auth.authz.roles.assign(principal, admin, { roleName: 'viewer' })),
      'ESCALATION_DENIED',
    );
    assert.equal(
      await codeOf(() => sys.auth.authz.roles.assign(principal, target, { roleName: 'root' })),
      'ESCALATION_DENIED',
    );
    assert.equal(
      await sys.auth.authz.roles.assign(principal, target, { roleName: 'editor' }),
      'created',
    );
    // grantedBy is derived from the actor and persisted.
    const [row] = await sys.storage.assignments.listActive(target, sys.clock.now());
    assert.equal(row?.grantedBy, admin);
    assert.ok((await auditRows('role.assigned')).length >= 1);
  });

  it('TIME-01: the idle expiry boundary is exact to the millisecond', async () => {
    const e = email('time');
    await sys.createUser(e);
    const { accessToken, principal } = await sys.login(e);
    const s = await sys.storage.sessions.get(principal.sessionId as string);
    const saved = sys.clock.now();
    sys.clock.set((s?.idleExpiresAt as number) - 1);
    assert.ok(await sys.auth.authn.resolve(accessToken));
    // The resolve above touched the session (sliding expiry); re-read the new boundary.
    const touched = await sys.storage.sessions.get(principal.sessionId as string);
    sys.clock.set(touched?.idleExpiresAt as number);
    assert.equal(await sys.auth.authn.resolve(accessToken), null);
    sys.clock.set(saved);
  });

  it('INV-CRED-01: no password or hash in any audit row', async () => {
    const e = email('secret');
    const id = await sys.createUser(e);
    await sys.login(e);
    const cred = await sys.storage.credentials.get(id, 'password');
    await (sys.audit as PostgresAuditSink).flush();
    const dump = await sys.storage.client.query(
      "SELECT string_agg(details::text || context::text || coalesce(reason, ''), '') AS all FROM aegis.audit_events",
    );
    const all = String((dump.rows[0] as { all: string }).all);
    assert.ok(!all.includes(TEST_PASSWORD));
    assert.ok(!all.includes(cred?.payload as string));
  });
});
