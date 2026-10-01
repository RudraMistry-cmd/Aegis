// Unit tests for RBAC resolution, inheritance and deny precedence (spec/rbac/*).
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createTestSystem, testCatalog } from '../support/fixtures.js';
import { defineCatalog, isAuthError, SYSTEM_ACTOR } from '../../src/index.js';

const SYSTEM = { id: SYSTEM_ACTOR, type: 'user' } as const;

describe('role and permission resolution', () => {
  it('grants exactly the permissions of a flat role', async () => {
    const sys = createTestSystem();
    const carol = await sys.createUser('carol@example.com', ['viewer']);
    const subject = { id: carol, type: 'user' };

    assert.deepEqual(
      [...(await sys.auth.authz.permissionsFor(subject))],
      ['post:read', 'project:read'],
    );
    assert.equal(await sys.auth.authz.can(subject, 'read', 'post'), true);
    assert.equal(await sys.auth.authz.can(subject, 'update', 'post'), false);
  });

  it('denies everything for a subject with no assignments', async () => {
    const sys = createTestSystem();
    const dave = await sys.createUser('dave@example.com');
    const subject = { id: dave, type: 'user' };

    assert.deepEqual([...(await sys.auth.authz.permissionsFor(subject))], []);
    for (const p of sys.catalog.permissions) {
      const [resource, action] = p.split(':') as [string, string];
      assert.equal(await sys.auth.authz.can(subject, action, resource), false, p);
    }
  });

  it('unions the permissions of several roles', async () => {
    const sys = createTestSystem();
    const gina = await sys.createUser('gina@example.com', ['editor', 'viewer']);
    const perms = await sys.auth.authz.permissionsFor({ id: gina, type: 'user' });
    assert.deepEqual([...perms], ['post:read', 'post:update', 'project:read', 'project:update']);
  });

  it('resolves inheritance transitively', async () => {
    const sys = createTestSystem();
    const alice = await sys.createUser('alice@example.com', ['admin']);
    const subject = { id: alice, type: 'user' };

    // admin -> editor -> viewer
    assert.equal(await sys.auth.authz.can(subject, 'read', 'post'), true);
    assert.equal(await sys.auth.authz.can(subject, 'update', 'post'), true);
    assert.equal(await sys.auth.authz.can(subject, 'delete', 'post'), true);
    assert.deepEqual([...(await sys.auth.authz.rolesFor(subject))], ['admin', 'editor', 'viewer']);
  });

  it('counts a diamond ancestor once and does not change the result', () => {
    const catalog = defineCatalog({
      permissions: ['a:read', 'b:read', 'c:read', 'd:read'],
      features: { hierarchy: true },
      roles: {
        a: { permissions: ['a:read'] },
        b: { inherits: ['a'], permissions: ['b:read'] },
        c: { inherits: ['a'], permissions: ['c:read'] },
        d: { inherits: ['b', 'c'], permissions: ['d:read'] },
      },
    });
    const d = catalog.role('d');
    assert.deepEqual([...(d?.closure ?? [])].sort(), ['a', 'b', 'c', 'd']);
    assert.deepEqual([...(d?.grants ?? [])].sort(), ['a:read', 'b:read', 'c:read', 'd:read']);
  });

  it('expands wildcards only over registered permissions', async () => {
    const sys = createTestSystem();
    const alice = await sys.createUser('alice@example.com', ['admin']);
    const subject = { id: alice, type: 'user' };

    for (const action of ['read', 'update', 'delete']) {
      assert.equal(await sys.auth.authz.can(subject, action, 'user'), true, `user:${action}`);
    }
    // Not registered: unknown_permission, never an accidental allow.
    const decision = await sys.auth.authz.authorize(subject, 'read', 'users');
    assert.equal(decision.effect, 'deny');
    assert.equal(decision.reason, 'unknown_permission');
  });

  it('treats an orphaned assignment as contributing nothing', async () => {
    const sys = createTestSystem();
    const dave = await sys.createUser('dave@example.com', ['viewer']);
    // Insert an assignment for a role that is not in the catalog.
    await sys.storage.assignments.assign(
      {
        subjectId: dave,
        roleName: 'ghost',
        scope: null,
        grantedBy: SYSTEM_ACTOR,
        grantedAt: sys.clock.now(),
      },
      sys.clock.now(),
    );
    const perms = await sys.auth.authz.permissionsFor({ id: dave, type: 'user' });
    assert.deepEqual([...perms], ['post:read', 'project:read']);
  });

  it('ignores an expired assignment at the exact expiry instant', async () => {
    const sys = createTestSystem();
    const dave = await sys.createUser('dave@example.com');
    const expiresAt = sys.clock.now() + 60_000;
    await sys.auth.authz.roles.assign(SYSTEM, dave, { roleName: 'viewer', expiresAt });
    const subject = { id: dave, type: 'user' };

    sys.clock.set(expiresAt - 1);
    assert.equal(await sys.auth.authz.can(subject, 'read', 'post'), true);
    sys.clock.set(expiresAt);
    assert.equal(await sys.auth.authz.can(subject, 'read', 'post'), false);
  });

  it('keeps every entry point in agreement', async () => {
    const sys = createTestSystem();
    const users = [
      { id: await sys.createUser('a@example.com', ['viewer']), type: 'user' },
      { id: await sys.createUser('b@example.com', ['editor']), type: 'user' },
      { id: await sys.createUser('c@example.com', ['contractor']), type: 'user' },
      { id: await sys.createUser('d@example.com', ['root']), type: 'user' },
    ];
    for (const subject of users) {
      const permissions = new Set(await sys.auth.authz.permissionsFor(subject));
      for (const p of sys.catalog.permissions) {
        const [resource, action] = p.split(':') as [string, string];
        const decision = await sys.auth.authz.authorize(subject, action, resource);
        const can = await sys.auth.authz.can(subject, action, resource);
        const allowed = decision.effect === 'allow';
        assert.equal(can, allowed, `can/authorize disagree on ${p}`);
        assert.equal(permissions.has(p), allowed, `permissionsFor disagrees on ${p}`);
        let threw = false;
        await sys.auth.authz.assert(subject, action, resource).catch(() => {
          threw = true;
        });
        assert.equal(threw, !allowed, `assert disagrees on ${p}`);
      }
    }
  });
});

describe('deny precedence', () => {
  it('lets a deny override an inherited allow', async () => {
    const sys = createTestSystem();
    const erin = await sys.createUser('erin@example.com', ['contractor']);
    const subject = { id: erin, type: 'user' };

    assert.equal(await sys.auth.authz.can(subject, 'update', 'post'), true);
    const decision = await sys.auth.authz.authorize(subject, 'delete', 'post');
    assert.equal(decision.effect, 'deny');
    assert.equal(decision.reason, 'rbac_explicit_deny');
    // A coarse role check still passes, but it never bypasses the deny.
    assert.equal(await sys.auth.authz.hasRole(subject, 'editor'), true);
  });

  it('overrides a superuser wildcard', async () => {
    const catalog = defineCatalog({
      permissions: ['user:read', 'user:delete'],
      features: { hierarchy: true, deny: true, wildcards: true },
      roles: {
        root: { permissions: ['*:*'], superuser: true },
        no_delete: { deny: ['user:delete'] },
      },
    });
    const sys = createTestSystem({ catalog });
    const frank = await sys.createUser('frank@example.com', ['root', 'no_delete']);
    const subject = { id: frank, type: 'user' };

    assert.equal(await sys.auth.authz.can(subject, 'read', 'user'), true);
    assert.equal(await sys.auth.authz.can(subject, 'delete', 'user'), false);
  });

  it('applies a deny regardless of assignment order', async () => {
    const catalog = defineCatalog({
      permissions: ['post:delete'],
      features: { deny: true },
      roles: { allow_del: { permissions: ['post:delete'] }, deny_del: { deny: ['post:delete'] } },
    });
    for (const order of [
      ['allow_del', 'deny_del'],
      ['deny_del', 'allow_del'],
    ]) {
      const sys = createTestSystem({ catalog });
      const u = await sys.createUser('x@example.com', order);
      assert.equal(await sys.auth.authz.can({ id: u, type: 'user' }, 'delete', 'post'), false);
    }
  });
});

describe('catalog validation', () => {
  it('reports every violation at once', () => {
    try {
      defineCatalog({
        permissions: ['post:read', 'Post:Read'],
        features: { hierarchy: true, wildcards: true },
        roles: {
          a: { permissions: ['post:write'], inherits: ['missing'] },
          b: { permissions: ['nothing:*'] },
          c: { inherits: ['d'] },
          d: { inherits: ['c'] },
        },
      });
      assert.fail('expected CONFIG_INVALID');
    } catch (e) {
      assert.ok(isAuthError(e));
      assert.equal(e.code, 'CONFIG_INVALID');
      const violations = (e.details?.['violations'] ?? []) as { rule: string }[];
      const rules = new Set(violations.map((v) => v.rule));
      assert.ok(rules.has('permission.grammar'));
      assert.ok(rules.has('permission.undefined'));
      assert.ok(rules.has('role.unknown_inherited'));
      assert.ok(rules.has('permission.unmatched_pattern'));
      assert.ok(rules.has('role.cycle'));
      assert.ok(violations.length >= 5, `expected several violations, got ${violations.length}`);
    }
  });

  it('rejects features that are not enabled', () => {
    assert.throws(
      () => defineCatalog({ permissions: ['a:read'], roles: { x: { permissions: ['a:*'] } } }),
      (e: unknown) => isAuthError(e) && e.code === 'CONFIG_INVALID',
    );
    assert.throws(
      () => defineCatalog({ permissions: ['a:read'], roles: { x: { deny: ['a:read'] } } }),
      (e: unknown) => isAuthError(e) && e.code === 'CONFIG_INVALID',
    );
  });

  it('derives a declaration-order-independent version', () => {
    const a = testCatalog();
    const b = defineCatalog({
      permissions: [...a.permissions].reverse(),
      features: { hierarchy: true, deny: true, wildcards: true },
      roles: {
        auditor: { permissions: ['role:read', 'user:read'] },
        root: { permissions: ['*:*'], superuser: true },
        contractor: { inherits: ['editor'], deny: ['project:delete', 'post:delete'] },
        admin: {
          inherits: ['editor'],
          permissions: [
            'account:setstatus',
            'session:revoke',
            'session:read',
            'role:read',
            'role:revoke',
            'role:assign',
            'project:delete',
            'post:delete',
            'user:*',
          ],
        },
        editor: { inherits: ['viewer'], permissions: ['project:update', 'post:update'] },
        viewer: { permissions: ['project:read', 'post:read'] },
      },
    });
    assert.equal(a.version, b.version);
  });
});
