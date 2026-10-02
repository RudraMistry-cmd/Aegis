// Concurrency on a real PostgreSQL server: every case releases N operations at the same instant
// across separate pooled connections, then checks the invariant on the committed state.
//
// The whole suite runs twice: under the default READ COMMITTED (row locks in a fixed order) and
// under SERIALIZABLE (same locks, plus SSI with retry). Both must uphold every invariant; the retry
// counters printed at the end show what each mode costs.
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import {
  digest,
  isAuthError,
  SYSTEM_ACTOR,
  type AuthError,
  type NewSession,
} from '../../src/index.js';
import {
  createPgStorage,
  createPgSystem,
  inParallel,
  START,
  type Isolation,
  type PgStorageHandle,
  type PgSystem,
} from './harness.js';

const DAY = 86_400_000;
const SYSTEM = { id: SYSTEM_ACTOR, type: 'user' } as const;

function codes(results: readonly PromiseSettledResult<unknown>[]): string[] {
  return results.map((r) =>
    r.status === 'fulfilled'
      ? 'OK'
      : isAuthError(r.reason)
        ? (r.reason as AuthError).code
        : `RAW:${String(r.reason)}`,
  );
}

function count(xs: readonly string[], x: string): number {
  return xs.filter((y) => y === x).length;
}

let n = 0;
const uid = (p: string): string => `${p}-${++n}`;

function session(id: string, userId: string): NewSession {
  return {
    id,
    userId,
    subjectType: 'user',
    authMethod: 'password',
    amr: ['pwd'],
    authenticatedAt: START,
    createdAt: START,
    lastSeenAt: START,
    idleExpiresAt: START + DAY,
    absoluteExpiresAt: START + 2 * DAY,
    securityVersionAtIssue: 0,
  };
}

const MODES: readonly Isolation[] = ['read committed', 'serializable'];

for (const isolation of MODES) {
  describe(`concurrency — ${isolation}`, () => {
    let store: PgStorageHandle;
    let sys: PgSystem;

    before(async () => {
      // AEGIS_PG_ATTEMPTS lets the retry budget be varied when measuring SERIALIZABLE (docs/POSTGRES.md).
      const maxTransactionAttempts = Number(process.env['AEGIS_PG_ATTEMPTS'] ?? 40);
      store = await createPgStorage({ isolation, maxTransactionAttempts });
      sys = await createPgSystem({ isolation, maxTransactionAttempts });
    });
    after(async () => {
      console.log(
        `    [${isolation}] transaction retries: store-level ${store.storage.runner.retries}, ` +
          `flow-level ${sys.storage.runner.retries}`,
      );
      await store.dispose();
      await sys.dispose();
    });

    const user = async (): Promise<string> => {
      const id = uid('u');
      await store.storage.users.create({ id, status: 'active', metadata: {}, createdAt: START });
      return id;
    };

    // ---------------------------------------------------------------- refresh consume

    it('CONSUME: of 50 concurrent consumes of one token, exactly one wins', async () => {
      const s = store.storage;
      const id = await user();
      const sid = uid('s');
      await s.sessions.createWithLimit(session(sid, id), null, 'reject', START);
      const hash = digest(`token-${sid}`);
      await s.refreshTokens.insert({
        id: uid('rt'),
        hash,
        sessionId: sid,
        userId: id,
        createdAt: START,
        expiresAt: START + DAY,
      });

      const results = await inParallel(50, () => s.refreshTokens.consume(hash, START + 1));
      const kinds = results.map((r) => (r.status === 'fulfilled' ? r.value.kind : 'error'));
      assert.equal(count(kinds, 'consumed'), 1, `kinds: ${kinds.join(',')}`);
      assert.equal(count(kinds, 'reused'), 49);
    });

    it('REF-03: of 25 concurrent refreshes, exactly one returns credentials', async () => {
      const email = `${uid('alice')}@example.com`;
      await sys.createUser(email);
      const { refreshToken, principal } = await sys.login(email);

      const results = await inParallel(25, () => sys.auth.authn.refresh({ refreshToken }));
      const c = codes(results);
      assert.equal(count(c, 'OK'), 1, `outcomes: ${c.join(',')}`);
      assert.equal(count(c, 'TOKEN_INVALID'), 24, `outcomes: ${c.join(',')}`);

      // reuseGrace = 0: the losers trip reuse detection, so the family ends revoked.
      const s = await sys.storage.sessions.get(principal.sessionId as string);
      assert.equal(s?.revokedReason, 'refresh_reuse_detected');
      const active = await sys.storage.client.query(
        "SELECT count(*)::int AS n FROM aegis.refresh_tokens WHERE session_id = $1 AND status = 'active'",
        [principal.sessionId],
      );
      assert.equal((active.rows[0] as { n: number }).n, 0);
    });

    // ---------------------------------------------------------------- session limit

    it('RACE-06: 40 parallel logins never exceed a limit of 3 (evict-oldest)', async () => {
      const s = store.storage;
      const id = await user();
      const results = await inParallel(40, () =>
        s.sessions.createWithLimit(session(uid('s'), id), 3, 'evict-oldest', START),
      );
      assert.deepEqual(
        codes(results).filter((c) => c !== 'OK'),
        [],
      );
      assert.equal(await s.sessions.countActive(id, START), 3);
      const live = await s.client.query(
        'SELECT count(*)::int AS n FROM aegis.sessions WHERE user_id = $1 AND revoked_at_ms IS NULL',
        [id],
      );
      assert.equal((live.rows[0] as { n: number }).n, 3, 'revoked rows are the only overflow');
    });

    it('RACE-06b: 30 parallel logins against reject admit exactly the limit', async () => {
      const s = store.storage;
      const id = await user();
      const results = await inParallel(30, () =>
        s.sessions.createWithLimit(session(uid('s'), id), 3, 'reject', START),
      );
      const kinds = results.map((r) => (r.status === 'fulfilled' ? r.value.kind : 'error'));
      assert.equal(count(kinds, 'created'), 3, kinds.join(','));
      assert.equal(count(kinds, 'limit_reached'), 27);
      assert.equal(await s.sessions.countActive(id, START), 3);
    });

    it('RACE-06c: full login flow — 20 parallel logins, default limit 10, no live token for an evicted session', async () => {
      const email = `${uid('bob')}@example.com`;
      const userId = await sys.createUser(email);
      const results = await inParallel(20, () => sys.login(email));
      assert.deepEqual(
        codes(results).filter((c) => c !== 'OK'),
        [],
      );
      assert.equal(await sys.storage.sessions.countActive(userId, sys.clock.now()), 10);
      const orphanTokens = await sys.storage.client.query(
        `SELECT count(*)::int AS n FROM aegis.refresh_tokens t JOIN aegis.sessions s ON s.id = t.session_id
          WHERE t.user_id = $1 AND t.status = 'active' AND s.revoked_at_ms IS NOT NULL`,
        [userId],
      );
      assert.equal((orphanTokens.rows[0] as { n: number }).n, 0);
    });

    // ---------------------------------------------------------------- revoke vs refresh

    it('RACE-03: refresh racing logout never leaves a usable token (40 rounds)', async () => {
      const email = `${uid('carol')}@example.com`;
      await sys.createUser(email);
      for (let round = 0; round < 40; round++) {
        const { refreshToken, principal } = await sys.login(email);
        const [refreshed, loggedOut] = await inParallel(2, (i) =>
          i === 0
            ? sys.auth.authn.refresh({ refreshToken }).then((r) => r.credentials.refreshToken)
            : sys.auth.authn.logout({ principal }).then(() => 'logged-out'),
        );
        assert.equal(loggedOut?.status, 'fulfilled', `round ${round}: logout failed`);
        // The refresh either won (and its new token is now dead) or lost with TOKEN_INVALID —
        // never PRECONDITION_FAILED or STORAGE_UNAVAILABLE.
        const outcome = codes([refreshed as PromiseSettledResult<unknown>])[0];
        assert.ok(outcome === 'OK' || outcome === 'TOKEN_INVALID', `round ${round}: ${outcome}`);

        const s = await sys.storage.sessions.get(principal.sessionId as string);
        assert.ok(s?.revokedAt !== undefined, `round ${round}: session not revoked`);
        const active = await sys.storage.client.query(
          "SELECT count(*)::int AS n FROM aegis.refresh_tokens WHERE session_id = $1 AND status = 'active'",
          [principal.sessionId],
        );
        assert.equal(
          (active.rows[0] as { n: number }).n,
          0,
          `round ${round}: active token survived`,
        );
        if (refreshed?.status === 'fulfilled') {
          const again = await sys.auth.authn.refresh({ refreshToken: refreshed.value }).then(
            () => 'OK',
            (e: unknown) => (isAuthError(e) ? e.code : 'RAW'),
          );
          assert.equal(again, 'TOKEN_INVALID', `round ${round}`);
        }
      }
    });

    it('RACE-07: logins racing a suspension leave no active session or token', async () => {
      const email = `${uid('dan')}@example.com`;
      const userId = await sys.createUser(email);
      const results = await inParallel(13, async (i) => {
        if (i === 6) {
          // The account-state change of principal.md §6.2: status + revoke-all + securityVersion,
          // in one unit.
          await sys.storage.uow.run(async (tx) => {
            const u = await tx.users.getById(userId);
            await tx.users.setStatus(userId, 'suspended', u?.version as number, START);
            await tx.sessions.revokeAllForUser(userId, null, 'account_state', START);
            await tx.users.bumpSecurityVersion(userId, START);
          });
          return 'suspended';
        }
        return sys.login(email).then(() => 'login');
      });
      assert.equal(results[6]?.status, 'fulfilled');
      for (const c of codes(results)) assert.ok(c === 'OK' || c === 'ACCOUNT_RESTRICTED', c);
      assert.equal(await sys.storage.sessions.countActive(userId, sys.clock.now()), 0);
      const active = await sys.storage.client.query(
        "SELECT count(*)::int AS n FROM aegis.refresh_tokens WHERE user_id = $1 AND status = 'active'",
        [userId],
      );
      assert.equal((active.rows[0] as { n: number }).n, 0);
    });

    // ---------------------------------------------------------------- identity and RBAC races

    it('RACE-01: 20 concurrent registrations of one email create exactly one user', async () => {
      const email = `${uid('dup')}@example.com`;
      const results = await inParallel(20, () =>
        sys.auth.authn.register({ identifier: email, password: 'correct-horse-battery-staple' }),
      );
      assert.deepEqual(
        codes(results).filter((c) => c !== 'OK'),
        [],
      );
      const users = await sys.storage.client.query(
        "SELECT count(*)::int AS n FROM aegis.identifiers WHERE type = 'email' AND normalized = $1",
        [email],
      );
      assert.equal((users.rows[0] as { n: number }).n, 1);
    });

    it('ESC-09 race: concurrent removal of the last two superusers leaves exactly one', async () => {
      const a = await sys.createUser(`${uid('root')}@example.com`);
      const b = await sys.createUser(`${uid('root')}@example.com`);
      // Remove any root holders left by earlier cases so exactly two exist.
      const existing = await sys.storage.assignments.listSubjectsByRole(
        'root',
        { limit: 1000 },
        START,
      );
      for (const x of existing.items) await sys.storage.assignments.unassign(x, 'root', null);
      await sys.auth.authz.roles.assign(SYSTEM, a, { roleName: 'root' });
      await sys.auth.authz.roles.assign(SYSTEM, b, { roleName: 'root' });

      const results = await inParallel(2, (i) =>
        sys.auth.authz.roles.revoke(SYSTEM, i === 0 ? a : b, 'root'),
      );
      const c = codes(results);
      assert.equal(count(c, 'OK'), 1, c.join(','));
      assert.equal(count(c, 'ESCALATION_DENIED'), 1, c.join(','));
      const left = await sys.storage.assignments.listSubjectsByRole('root', { limit: 1000 }, START);
      assert.equal(left.items.length, 1);
    });

    it('RACE-08: an assigner losing its own authority mid-flight cannot escalate', async () => {
      const assigner = await sys.createUser(`${uid('admin')}@example.com`, ['admin']);
      const target = await sys.createUser(`${uid('target')}@example.com`);
      const { principal } = await sys.login(
        (await sys.storage.identifiers.listByUser(assigner))[0]?.normalized as string,
      );
      await inParallel(2, (i) =>
        i === 0
          ? sys.auth.authz.roles.assign(principal, target, { roleName: 'editor' }).then(() => true)
          : sys.auth.authz.roles.revoke(SYSTEM, assigner, 'admin'),
      );
      const held = await sys.auth.authz.rolesFor({ id: target });
      assert.ok(
        held.every((r) => r === 'editor' || r === 'viewer'),
        held.join(','),
      );
    });

    it('STO-ASG-01 race: 30 identical concurrent assigns create one row', async () => {
      const subj = uid('subj');
      const results = await inParallel(30, () =>
        store.storage.assignments.assign(
          { subjectId: subj, roleName: 'viewer', scope: null, grantedBy: 'x', grantedAt: START },
          START,
        ),
      );
      const outcomes = results.map((r) => (r.status === 'fulfilled' ? r.value : 'error'));
      assert.equal(count(outcomes, 'created'), 1, outcomes.join(','));
      assert.equal(count(outcomes, 'unchanged'), 29);
    });

    it('RACE-09: 100 concurrent securityVersion bumps lose nothing', async () => {
      const id = await user();
      await inParallel(100, () => store.storage.users.bumpSecurityVersion(id, START));
      assert.equal((await store.storage.users.getById(id))?.securityVersion, 100);
    });

    it('STO-USR-02 race: of 20 setStatus calls with one expected version, exactly one applies', async () => {
      const id = await user();
      const results = await inParallel(20, () =>
        store.storage.users.setStatus(id, 'suspended', 0, START),
      );
      const c = codes(results);
      assert.equal(count(c, 'OK'), 1, c.join(','));
      assert.equal(count(c, 'PRECONDITION_FAILED'), 19);
    });
  });
}
