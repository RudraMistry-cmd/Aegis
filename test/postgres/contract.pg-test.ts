// Storage-contract cases of spec/storage/interfaces.md, run identically against BOTH adapters:
// the in-memory reference (Phase 1) and PostgreSQL. Any difference in observable behaviour between
// the two is a conformance bug in one of them.
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import {
  createMemoryStorage,
  digest,
  isAuthError,
  SequentialIdGenerator,
  type NewRefreshToken,
  type NewSession,
  type Storage,
} from '../../src/index.js';
import { createPgStorage, START } from './harness.js';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

interface Adapter {
  readonly name: string;
  make(): Promise<{ storage: Storage; dispose(): Promise<void> }>;
}

const ADAPTERS: readonly Adapter[] = [
  {
    name: 'memory',
    make: async () => ({
      storage: createMemoryStorage(new SequentialIdGenerator('m')),
      dispose: async () => undefined,
    }),
  },
  {
    name: 'postgres',
    make: async () => {
      const h = await createPgStorage();
      return { storage: h.storage, dispose: h.dispose };
    },
  },
];

async function codeOf(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (e) {
    assert.ok(isAuthError(e), `expected an AuthError, got ${String(e)}`);
    return e.code;
  }
  return 'OK';
}

let counter = 0;
const uid = (prefix: string): string => `${prefix}-${++counter}`;

function session(
  id: string,
  userId: string,
  createdAt: number,
  overrides: Partial<NewSession> = {},
): NewSession {
  return {
    id,
    userId,
    subjectType: 'user',
    authMethod: 'password',
    amr: ['pwd'],
    authenticatedAt: createdAt,
    createdAt,
    lastSeenAt: createdAt,
    idleExpiresAt: createdAt + HOUR,
    absoluteExpiresAt: createdAt + DAY,
    securityVersionAtIssue: 0,
    ...overrides,
  };
}

function token(
  sessionId: string,
  userId: string,
  overrides: Partial<NewRefreshToken> = {},
): NewRefreshToken {
  const id = uid('rt');
  return {
    id,
    hash: digest(`secret-${id}`),
    sessionId,
    userId,
    createdAt: START,
    expiresAt: START + DAY,
    ...overrides,
  };
}

for (const adapter of ADAPTERS) {
  describe(`storage contract — ${adapter.name}`, () => {
    let s: Storage;
    let dispose: () => Promise<void>;

    before(async () => {
      const made = await adapter.make();
      s = made.storage;
      dispose = made.dispose;
    });
    after(async () => dispose());

    const user = async (): Promise<string> => {
      const id = uid('u');
      await s.users.create({ id, status: 'active', metadata: {}, createdAt: START });
      return id;
    };

    // ------------------------------------------------------------ §2 UserStore

    it('STO-USR-01: create starts versions at zero and rejects a duplicate id', async () => {
      const id = uid('u');
      const u = await s.users.create({
        id,
        status: 'active',
        metadata: { a: 1 },
        createdAt: START,
      });
      assert.equal(u.version, 0);
      assert.equal(u.securityVersion, 0);
      assert.deepEqual({ ...u.metadata }, { a: 1 });
      assert.equal(
        await codeOf(() =>
          s.users.create({ id, status: 'active', metadata: {}, createdAt: START }),
        ),
        'CONFLICT',
      );
    });

    it('STO-USR-02: setStatus is a compare-and-set on version', async () => {
      const id = await user();
      const u1 = await s.users.setStatus(id, 'suspended', 0, START + 1);
      assert.equal(u1.status, 'suspended');
      assert.equal(u1.version, 1);
      assert.equal(
        await codeOf(() => s.users.setStatus(id, 'active', 0, START + 2)),
        'PRECONDITION_FAILED',
      );
      assert.equal(
        await codeOf(() => s.users.setStatus('no-such-user', 'active', 0, START)),
        'NOT_FOUND',
      );
    });

    it('STO-USR-04: every mutation increments version; metadata merges shallowly', async () => {
      const id = await user();
      assert.equal(await s.users.bumpSecurityVersion(id, START + 1), 1);
      const u = await s.users.updateMetadata(id, { theme: 'dark' }, undefined, START + 2);
      assert.equal(u.version, 2);
      assert.equal(u.securityVersion, 1);
      assert.equal(u.updatedAt, START + 2);
      assert.deepEqual({ ...u.metadata }, { theme: 'dark' });
      assert.equal(
        await codeOf(() => s.users.updateMetadata(id, { x: 1 }, 0, START)),
        'PRECONDITION_FAILED',
      );
    });

    it('STO-DATA-03: delete cascades to identifiers, credentials, sessions, tokens and assignments', async () => {
      const id = await user();
      await s.identifiers.add(
        id,
        'email',
        'X@example.com',
        uid('x') + '@example.com',
        false,
        START,
      );
      await s.credentials.put(id, 'password', 'hash', START);
      const sid = uid('sess');
      await s.sessions.createWithLimit(session(sid, id, START), null, 'evict-oldest', START);
      const t = token(sid, id);
      await s.refreshTokens.insert(t);
      await s.assignments.assign(
        { subjectId: id, roleName: 'viewer', scope: null, grantedBy: 'system', grantedAt: START },
        START,
      );

      await s.users.delete(id);
      await s.users.delete(id); // idempotent

      assert.equal(await s.users.getById(id), null);
      assert.deepEqual([...(await s.identifiers.listByUser(id))], []);
      assert.equal(await s.credentials.get(id, 'password'), null);
      assert.equal(await s.sessions.get(sid), null);
      assert.equal(await s.refreshTokens.getById(t.id), null);
      assert.deepEqual([...(await s.assignments.listActive(id, START))], []);
    });

    // ------------------------------------------------------------ §3 IdentifierStore, §4 CredentialStore

    it('STO-ID-01/03: identifiers are unique on (type, normalized) and need an existing user', async () => {
      const id = await user();
      const normalized = `${uid('alice')}@example.com`;
      const row = await s.identifiers.add(
        id,
        'email',
        'Alice@Example.com',
        normalized,
        false,
        START,
      );
      assert.equal(row.value, 'Alice@Example.com');
      assert.equal((await s.identifiers.findByNormalized('email', normalized))?.userId, id);
      // Exact, case-sensitive match: normalization is the core's job.
      assert.equal(await s.identifiers.findByNormalized('email', normalized.toUpperCase()), null);
      const other = await user();
      assert.equal(
        await codeOf(() => s.identifiers.add(other, 'email', 'x', normalized, false, START)),
        'CONFLICT',
      );
      // The same text under another type does not collide.
      await s.identifiers.add(other, 'username', 'x', normalized, false, START);
      await s.identifiers.markVerified(row.id, START);
      assert.equal((await s.identifiers.findByNormalized('email', normalized))?.verified, true);
      assert.equal(
        await codeOf(() => s.identifiers.markVerified('no-such-identifier', START)),
        'NOT_FOUND',
      );
    });

    it('STO-CRED-01: put replaces atomically and keeps the credential id', async () => {
      const id = await user();
      const first = await s.credentials.put(id, 'password', 'hash-1', START);
      const second = await s.credentials.put(id, 'password', 'hash-2', START + 5);
      assert.equal(second.id, first.id);
      assert.equal(second.createdAt, START);
      assert.equal((await s.credentials.get(id, 'password'))?.payload, 'hash-2');
    });

    // ------------------------------------------------------------ §5 SessionStore

    it('STO-SES-01: createWithLimit evicts the oldest and revokes its family', async () => {
      const id = await user();
      const ids = [uid('s'), uid('s'), uid('s')];
      for (let i = 0; i < 3; i++) {
        await s.sessions.createWithLimit(
          session(ids[i] as string, id, START + i),
          3,
          'evict-oldest',
          START + i,
        );
      }
      const t = token(ids[0] as string, id);
      await s.refreshTokens.insert(t);
      const r = await s.sessions.createWithLimit(
        session(uid('s'), id, START + 10),
        3,
        'evict-oldest',
        START + 10,
      );
      assert.equal(r.kind, 'created');
      assert.deepEqual(r.kind === 'created' ? [...r.evicted] : [], [ids[0]]);
      assert.equal((await s.sessions.get(ids[0] as string))?.revokedReason, 'evicted');
      assert.equal((await s.refreshTokens.getById(t.id))?.status, 'revoked');
      assert.equal(await s.sessions.countActive(id, START + 10), 3);
    });

    it('STO-SES-01b: reject leaves everything unchanged; a duplicate id is a conflict', async () => {
      const id = await user();
      const first = uid('s');
      await s.sessions.createWithLimit(session(first, id, START), 1, 'reject', START);
      const r = await s.sessions.createWithLimit(
        session(uid('s'), id, START + 1),
        1,
        'reject',
        START + 1,
      );
      assert.equal(r.kind, 'limit_reached');
      assert.equal(await s.sessions.countActive(id, START + 1), 1);
      assert.equal(
        await codeOf(() =>
          s.sessions.createWithLimit(session(first, id, START + 2), null, 'reject', START + 2),
        ),
        'CONFLICT',
      );
    });

    it('STO-SES-01c: expired sessions do not count toward the limit', async () => {
      const id = await user();
      await s.sessions.createWithLimit(
        session(uid('s'), id, START, { idleExpiresAt: START + 10 }),
        1,
        'reject',
        START,
      );
      const r = await s.sessions.createWithLimit(
        session(uid('s'), id, START + 10),
        1,
        'reject',
        START + 10,
      );
      assert.equal(r.kind, 'created');
    });

    it('STO-SES-02: revoke is true once, the first reason wins, and the family goes with it', async () => {
      const id = await user();
      const sid = uid('s');
      await s.sessions.createWithLimit(session(sid, id, START), null, 'reject', START);
      const t = token(sid, id);
      await s.refreshTokens.insert(t);
      assert.equal(await s.sessions.revoke(sid, 'logout', START + 1), true);
      const first = await s.sessions.get(sid);
      assert.equal(await s.sessions.revoke(sid, 'admin', START + 2), false);
      assert.deepEqual(await s.sessions.get(sid), first);
      assert.equal(first?.revokedReason, 'logout');
      assert.equal((await s.refreshTokens.getById(t.id))?.status, 'revoked');
      assert.equal(await s.sessions.revoke('no-such-session', 'logout', START), false);
    });

    it('STO-SES-03: revokeAllForUser spares only the excepted session', async () => {
      const id = await user();
      const [a, b, c] = [uid('s'), uid('s'), uid('s')];
      for (const x of [a, b, c])
        await s.sessions.createWithLimit(session(x, id, START), null, 'reject', START);
      assert.equal(await s.sessions.revokeAllForUser(id, b, 'logout_all', START + 1), 2);
      assert.equal(await s.sessions.revokeAllForUser(id, b, 'logout_all', START + 2), 0);
      assert.equal((await s.sessions.get(b))?.revokedAt, undefined);
      assert.equal((await s.sessions.get(a))?.revokedReason, 'logout_all');
    });

    it('STO-SES-04: touch extends idle expiry only for a live session and within bounds', async () => {
      const id = await user();
      const sid = uid('s');
      await s.sessions.createWithLimit(session(sid, id, START), null, 'reject', START);
      assert.equal(await s.sessions.touch(sid, START + 1, START + 2 * HOUR), true);
      assert.equal((await s.sessions.get(sid))?.lastSeenAt, START + 1);
      assert.equal(await s.sessions.touch(sid, START + 2, START + HOUR), false, 'may not shrink');
      assert.equal(
        await s.sessions.touch(sid, START + 3, START + 2 * DAY),
        false,
        'may not pass absolute',
      );
      // Idle-expired: a touch must not resurrect it (INV-SESS-02).
      assert.equal(
        await s.sessions.touch(sid, START + 2 * HOUR, START + 3 * HOUR),
        false,
        'expired',
      );
      await s.sessions.revoke(sid, 'logout', START + 4);
      assert.equal(await s.sessions.touch(sid, START + 5, START + 3 * HOUR), false, 'revoked');
    });

    it('STO-SES-07: listActiveByUser pages newest first, completely, without duplicates', async () => {
      const id = await user();
      const created: string[] = [];
      for (let i = 0; i < 7; i++) {
        const sid = uid('s');
        created.push(sid);
        await s.sessions.createWithLimit(session(sid, id, START + i), null, 'reject', START + i);
      }
      await s.sessions.revoke(created[3] as string, 'logout', START + 20);
      const seen: string[] = [];
      let cursor: string | undefined;
      do {
        const page = await s.sessions.listActiveByUser(
          id,
          { limit: 2, ...(cursor ? { cursor } : {}) },
          START + 20,
        );
        seen.push(...page.items.map((x) => x.id));
        cursor = page.nextCursor;
      } while (cursor);
      const expected = created.filter((_, i) => i !== 3).reverse();
      assert.deepEqual(seen, expected);
    });

    // ------------------------------------------------------------ §6 RefreshTokenStore

    it('STO-RT-02: consume follows the documented precedence', async () => {
      const id = await user();
      const sid = uid('s');
      await s.sessions.createWithLimit(session(sid, id, START), null, 'reject', START);
      const active = token(sid, id);
      await s.refreshTokens.insert(active);

      assert.equal((await s.refreshTokens.consume(digest('never-issued'), START)).kind, 'unknown');
      const c = await s.refreshTokens.consume(active.hash, START + 1);
      assert.equal(c.kind, 'consumed');
      assert.equal(c.kind === 'consumed' ? c.token.usedAt : 0, START + 1);
      assert.equal((await s.refreshTokens.consume(active.hash, START + 2)).kind, 'reused');
      // used AND expired still reports reuse (status before expiry).
      assert.equal((await s.refreshTokens.consume(active.hash, START + 2 * DAY)).kind, 'reused');

      const sid2 = uid('s');
      await s.sessions.createWithLimit(session(sid2, id, START), null, 'reject', START);
      const expiring = token(sid2, id, { expiresAt: START + 10 });
      await s.refreshTokens.insert(expiring);
      assert.equal((await s.refreshTokens.consume(expiring.hash, START + 10)).kind, 'expired');
      assert.equal((await s.refreshTokens.getById(expiring.id))?.status, 'active', 'unchanged');
      await s.refreshTokens.revokeFamily(sid2, 'family_revoked');
      assert.equal((await s.refreshTokens.consume(expiring.hash, START)).kind, 'revoked');
    });

    it('STO-RT-03: rotate needs a used parent without successor and links both ways', async () => {
      const id = await user();
      const sid = uid('s');
      await s.sessions.createWithLimit(session(sid, id, START), null, 'reject', START);
      const parent = token(sid, id);
      await s.refreshTokens.insert(parent);
      const early = token(sid, id, { parentId: parent.id });
      assert.equal(
        await codeOf(() => s.refreshTokens.rotate(parent.id, early)),
        'PRECONDITION_FAILED',
        'parent still active',
      );
      await s.refreshTokens.consume(parent.hash, START + 1);
      const child = token(sid, id, { parentId: parent.id });
      await s.refreshTokens.rotate(parent.id, child);
      assert.equal((await s.refreshTokens.getById(parent.id))?.successorId, child.id);
      assert.equal((await s.refreshTokens.getById(child.id))?.status, 'active');
      assert.equal(
        await codeOf(() =>
          s.refreshTokens.rotate(parent.id, token(sid, id, { parentId: parent.id })),
        ),
        'PRECONDITION_FAILED',
        'second rotation of one parent',
      );
    });

    it('STO-RT-05: no token is minted for a revoked session', async () => {
      const id = await user();
      const sid = uid('s');
      await s.sessions.createWithLimit(session(sid, id, START), null, 'reject', START);
      const parent = token(sid, id);
      await s.refreshTokens.insert(parent);
      await s.refreshTokens.consume(parent.hash, START + 1);
      await s.sessions.revoke(sid, 'logout', START + 2);
      assert.equal(
        await codeOf(() =>
          s.refreshTokens.rotate(parent.id, token(sid, id, { parentId: parent.id })),
        ),
        'PRECONDITION_FAILED',
      );
      assert.equal(
        await codeOf(() => s.refreshTokens.insert(token(sid, id))),
        'PRECONDITION_FAILED',
      );
    });

    it('STO-RT-04: replaceActiveSuccessor supersedes only an active successor', async () => {
      const id = await user();
      const sid = uid('s');
      await s.sessions.createWithLimit(session(sid, id, START), null, 'reject', START);
      const parent = token(sid, id);
      await s.refreshTokens.insert(parent);
      await s.refreshTokens.consume(parent.hash, START + 1);
      const child = token(sid, id, { parentId: parent.id });
      await s.refreshTokens.rotate(parent.id, child);

      const replacement = token(sid, id, { parentId: parent.id });
      assert.equal(
        await s.refreshTokens.replaceActiveSuccessor(child.id, replacement, parent.id),
        'replaced',
      );
      const old = await s.refreshTokens.getById(child.id);
      assert.equal(old?.status, 'revoked');
      assert.equal(old?.revokedReason, 'superseded');
      assert.equal((await s.refreshTokens.getById(parent.id))?.successorId, replacement.id);
      assert.equal(
        await s.refreshTokens.replaceActiveSuccessor(child.id, token(sid, id), parent.id),
        'not_active',
      );
    });

    it('STO-RT-06: revokeFamily is idempotent and counts changes', async () => {
      const id = await user();
      const sid = uid('s');
      await s.sessions.createWithLimit(session(sid, id, START), null, 'reject', START);
      await s.refreshTokens.insert(token(sid, id));
      assert.equal(await s.refreshTokens.revokeFamily(sid, 'family_revoked'), 1);
      assert.equal(await s.refreshTokens.revokeFamily(sid, 'family_revoked'), 0);
      assert.equal(await s.refreshTokens.revokeFamily('no-such-session', 'family_revoked'), 0);
    });

    it('STO-RT: a duplicate token digest is a conflict', async () => {
      const id = await user();
      const sid = uid('s');
      await s.sessions.createWithLimit(session(sid, id, START), null, 'reject', START);
      const t = token(sid, id);
      await s.refreshTokens.insert(t);
      const sid2 = uid('s');
      await s.sessions.createWithLimit(session(sid2, id, START), null, 'reject', START);
      assert.equal(
        await codeOf(() => s.refreshTokens.insert(token(sid2, id, { hash: t.hash }))),
        'CONFLICT',
      );
    });

    // ------------------------------------------------------------ §8 assignments and roles

    it('STO-ASG-01: assign reports created / unchanged / updated and preserves the grant', async () => {
      const subj = uid('subj');
      const base = {
        subjectId: subj,
        roleName: 'viewer',
        scope: null,
        grantedBy: 'alice',
        grantedAt: START,
      };
      assert.equal(await s.assignments.assign(base, START), 'created');
      assert.equal(
        await s.assignments.assign({ ...base, grantedBy: 'mallory' }, START),
        'unchanged',
      );
      assert.equal(
        await s.assignments.assign({ ...base, expiresAt: START + HOUR }, START),
        'updated',
      );
      assert.equal(
        await s.assignments.assign({ ...base, expiresAt: START + HOUR }, START),
        'unchanged',
      );
      const [row] = await s.assignments.listActive(subj, START);
      assert.equal(row?.grantedBy, 'alice');
      assert.equal(row?.expiresAt, START + HOUR);
      assert.equal(await s.assignments.unassign(subj, 'viewer', null), true);
      assert.equal(await s.assignments.unassign(subj, 'viewer', null), false);
    });

    it('STO-ASG-02: listActive applies the expiry boundary in the query', async () => {
      const subj = uid('subj');
      await s.assignments.assign(
        {
          subjectId: subj,
          roleName: 'viewer',
          scope: null,
          expiresAt: START + 100,
          grantedBy: 'x',
          grantedAt: START,
        },
        START,
      );
      assert.equal((await s.assignments.listActive(subj, START + 99)).length, 1);
      assert.equal((await s.assignments.listActive(subj, START + 100)).length, 0);
    });

    it('STO-ASG-03: listSubjectsByRole pages in subject order, completely', async () => {
      const role = 'auditor';
      const subjects = Array.from({ length: 5 }, () => uid('zz-holder'));
      for (const x of subjects) {
        await s.assignments.assign(
          { subjectId: x, roleName: role, scope: null, grantedBy: 'x', grantedAt: START },
          START,
        );
      }
      const seen: string[] = [];
      let cursor: string | undefined;
      do {
        const page = await s.assignments.listSubjectsByRole(
          role,
          { limit: 2, ...(cursor ? { cursor } : {}) },
          START,
        );
        seen.push(...page.items);
        cursor = page.nextCursor;
      } while (cursor);
      assert.deepEqual(
        seen.filter((x) => subjects.includes(x)),
        [...subjects].sort(),
      );
    });

    it('STO-CAT-01: catalog sync is idempotent', async () => {
      assert.equal(await s.roles.getCatalogVersion(), null);
      const snap = { version: 'v1', roles: ['viewer', 'editor'], permissions: ['post:read'] };
      await s.roles.sync(snap, START);
      await s.roles.sync(snap, START + 1);
      assert.equal(await s.roles.getCatalogVersion(), 'v1');
      await s.roles.sync(
        { version: 'v2', roles: ['viewer'], permissions: ['post:read'] },
        START + 2,
      );
      assert.equal(await s.roles.getCatalogVersion(), 'v2');
    });

    // ------------------------------------------------------------ §11 UnitOfWork

    it('STO-UOW-01: a failure inside a unit persists nothing', async () => {
      const id = uid('u');
      await assert.rejects(
        s.uow.run(async (tx) => {
          await tx.users.create({ id, status: 'active', metadata: {}, createdAt: START });
          await tx.identifiers.add(id, 'email', 'x', `${id}@example.com`, false, START);
          throw new Error('fail inside the unit');
        }),
        // The unit's own error propagates unchanged; it is never relabeled as a storage failure.
        /fail inside the unit/,
      );
      assert.equal(await s.users.getById(id), null);
      assert.equal(await s.identifiers.findByNormalized('email', `${id}@example.com`), null);
    });

    it('STO-UOW-03: a nested unit joins the outer one and shares its fate', async () => {
      const outer = uid('u');
      const inner = uid('u');
      await assert.rejects(
        s.uow.run(async (tx) => {
          await tx.users.create({ id: outer, status: 'active', metadata: {}, createdAt: START });
          await s.uow.run(async (tx2) => {
            // The inner unit sees the outer unit's uncommitted write.
            assert.ok(await tx2.users.getById(outer));
            await tx2.users.create({ id: inner, status: 'active', metadata: {}, createdAt: START });
          });
          throw new Error('outer fails after inner succeeded');
        }),
        /outer fails after inner succeeded/,
      );
      assert.equal(await s.users.getById(outer), null);
      assert.equal(await s.users.getById(inner), null);
    });
  });
}
