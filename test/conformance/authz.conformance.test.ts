// Conformance cases from spec/conformance.md, profile P-AUTHZ.
// Each case states its id and the GIVEN / WHEN / THEN of the specification.
// Fixtures F-CAT, F-USERS and F-POL live in test/support/fixtures.ts.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createTestSystem, postPolicy, tenantWall } from '../support/fixtures.js';
import {
  defineCatalog,
  definePolicy,
  evaluateExpr,
  isAuthError,
  SYSTEM_ACTOR,
} from '../../src/index.js';

const SYSTEM = { id: SYSTEM_ACTOR, type: 'user' } as const;

describe('P-AUTHZ conformance', () => {
  it('AZ-RBAC-01: viewer holds exactly post:read and project:read', async () => {
    // GIVEN F-CAT and carol = viewer
    const sys = createTestSystem();
    const carol = await sys.createUser('carol@example.com', ['viewer']);
    const subject = { id: carol, type: 'user' };
    // WHEN every registered permission is tested
    const allowed: string[] = [];
    for (const p of sys.catalog.permissions) {
      const [r, a] = p.split(':') as [string, string];
      if (await sys.auth.authz.can(subject, a, r)) allowed.push(p);
    }
    // THEN only the two viewer permissions are allowed
    assert.deepEqual(allowed.sort(), ['post:read', 'project:read']);
  });

  it('AZ-RBAC-02: a subject with no assignments is denied every permission', async () => {
    // GIVEN dave with no role assignments
    const sys = createTestSystem();
    const dave = await sys.createUser('dave@example.com');
    const subject = { id: dave, type: 'user' };
    // WHEN each registered permission is tested  THEN all are denied and permissionsFor is empty
    for (const p of sys.catalog.permissions) {
      const [r, a] = p.split(':') as [string, string];
      assert.equal(await sys.auth.authz.can(subject, a, r), false, p);
    }
    assert.deepEqual([...(await sys.auth.authz.permissionsFor(subject))], []);
  });

  it('AZ-RBAC-04: admin reaches viewer permissions through the hierarchy', async () => {
    // GIVEN admin inherits editor which inherits viewer
    const sys = createTestSystem();
    const alice = await sys.createUser('alice@example.com', ['admin']);
    const subject = { id: alice, type: 'user' };
    // WHEN post:read and post:update are tested  THEN both are allowed
    assert.equal(await sys.auth.authz.can(subject, 'read', 'post'), true);
    assert.equal(await sys.auth.authz.can(subject, 'update', 'post'), true);
  });

  it('AZ-RBAC-07: user:* covers the registered user actions but not an unregistered resource', async () => {
    // GIVEN admin holds the wildcard user:*
    const sys = createTestSystem();
    const alice = await sys.createUser('alice@example.com', ['admin']);
    const subject = { id: alice, type: 'user' };
    // WHEN registered user actions are tested  THEN they are allowed
    for (const action of ['read', 'update', 'delete']) {
      assert.equal(await sys.auth.authz.can(subject, action, 'user'), true, action);
    }
    // AND an unregistered resource is denied with unknown_permission
    const d = await sys.auth.authz.authorize(subject, 'read', 'users');
    assert.equal(d.effect, 'deny');
    assert.equal(d.reason, 'unknown_permission');
  });

  it('AZ-RBAC-11: permission strings are never normalized', async () => {
    // GIVEN an admin who holds post:read
    const sys = createTestSystem();
    const alice = await sys.createUser('alice@example.com', ['admin']);
    const subject = { id: alice, type: 'user' };
    // WHEN case or whitespace variants are requested  THEN each is invalid_permission
    for (const [action, resource] of [
      ['Read', 'post'],
      ['read', 'Post'],
      [' read', 'post'],
    ]) {
      const d = await sys.auth.authz.authorize(subject, action as string, resource as string);
      assert.equal(d.effect, 'deny');
      assert.equal(d.reason, 'invalid_permission');
    }
  });

  it('AZ-RBAC-12: an assignment to an unknown role contributes nothing', async () => {
    // GIVEN dave holds viewer plus an assignment to a role absent from the catalog
    const sys = createTestSystem();
    const dave = await sys.createUser('dave@example.com', ['viewer']);
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
    // WHEN permissions are resolved  THEN only the valid role counts
    assert.deepEqual(
      [...(await sys.auth.authz.permissionsFor({ id: dave, type: 'user' }))],
      ['post:read', 'project:read'],
    );
  });

  it('AZ-RBAC-20: can, authorize, assert and permissionsFor agree for every user and permission', async () => {
    // GIVEN the fixture users  WHEN the full product is evaluated  THEN all entry points agree
    const sys = createTestSystem();
    const subjects = [
      { id: await sys.createUser('carol@example.com', ['viewer']), type: 'user' },
      { id: await sys.createUser('erin@example.com', ['contractor']), type: 'user' },
      { id: await sys.createUser('frank@example.com', ['root']), type: 'user' },
    ];
    for (const subject of subjects) {
      const held = new Set(await sys.auth.authz.permissionsFor(subject));
      for (const p of sys.catalog.permissions) {
        const [r, a] = p.split(':') as [string, string];
        const allowed = (await sys.auth.authz.authorize(subject, a, r)).effect === 'allow';
        assert.equal(await sys.auth.authz.can(subject, a, r), allowed, p);
        assert.equal(held.has(p), allowed, p);
      }
    }
  });

  it('AZ-DENY-01: a deny overrides a wildcard allow for that permission only', async () => {
    // GIVEN a role granting project:* and a role denying project:delete
    const catalog = defineCatalog({
      permissions: ['project:read', 'project:update', 'project:delete'],
      features: { deny: true, wildcards: true },
      roles: { broad: { permissions: ['project:*'] }, nodel: { deny: ['project:delete'] } },
    });
    const sys = createTestSystem({ catalog });
    const u = await sys.createUser('u@example.com', ['broad', 'nodel']);
    const subject = { id: u, type: 'user' };
    // WHEN each action is tested  THEN delete is denied and the others allowed
    assert.equal(
      (await sys.auth.authz.authorize(subject, 'delete', 'project')).reason,
      'rbac_explicit_deny',
    );
    assert.equal(await sys.auth.authz.can(subject, 'read', 'project'), true);
    assert.equal(await sys.auth.authz.can(subject, 'update', 'project'), true);
  });

  it('AZ-DENY-03: a superuser is not exempt from an explicit deny', async () => {
    // GIVEN frank holds root (*:*) and a role denying user:delete
    const catalog = defineCatalog({
      permissions: ['user:read', 'user:delete'],
      features: { deny: true, wildcards: true },
      roles: { root: { permissions: ['*:*'], superuser: true }, nodel: { deny: ['user:delete'] } },
    });
    const sys = createTestSystem({ catalog });
    const frank = await sys.createUser('frank@example.com', ['root', 'nodel']);
    const subject = { id: frank, type: 'user' };
    // WHEN user:delete is tested  THEN it is denied; everything else stays allowed
    assert.equal(await sys.auth.authz.can(subject, 'delete', 'user'), false);
    assert.equal(await sys.auth.authz.can(subject, 'read', 'user'), true);
  });

  it('AZ-DEF-01: an unregistered permission denies with unknown_permission and is audited', async () => {
    // GIVEN an admin  WHEN an unregistered permission is requested
    const sys = createTestSystem();
    const alice = await sys.createUser('alice@example.com', ['admin']);
    const d = await sys.auth.authz.authorize({ id: alice, type: 'user' }, 'frobnicate', 'post');
    // THEN the decision is deny/unknown_permission and authz.denied was emitted
    assert.equal(d.effect, 'deny');
    assert.equal(d.reason, 'unknown_permission');
    assert.ok(sys.audit.ofType('authz.denied').length >= 1);
  });

  it('AZ-DEF-02: an invalid action never throws from can/authorize but does from assert', async () => {
    // GIVEN an admin  WHEN malformed actions are requested
    const sys = createTestSystem();
    const alice = await sys.createUser('alice@example.com', ['admin']);
    const subject = { id: alice, type: 'user' };
    for (const action of ['', 'a:b', 'x'.repeat(49), 'Ünicode']) {
      // THEN the decision is a value, not an exception
      const d = await sys.auth.authz.authorize(subject, action, 'post');
      assert.equal(d.effect, 'deny');
      assert.equal(await sys.auth.authz.can(subject, action, 'post'), false);
      // AND assert throws FORBIDDEN
      let code = '';
      await sys.auth.authz.assert(subject, action, 'post').catch((e: unknown) => {
        code = isAuthError(e) ? e.code : 'OTHER';
      });
      assert.equal(code, 'FORBIDDEN', action);
    }
  });

  it('AZ-DET-01: identical inputs and state yield an identical effect and reason', async () => {
    // GIVEN a policy-protected resource  WHEN the same request is evaluated many times
    const sys = createTestSystem({ policies: [postPolicy()] });
    const bob = await sys.createUser('bob@example.com', ['editor']);
    const subject = { id: bob, type: 'user' };
    const resource = { type: 'post', authorId: 'someone-else' };
    const results = await Promise.all(
      Array.from({ length: 50 }, () => sys.auth.authz.authorize(subject, 'update', resource)),
    );
    // THEN every decision is identical
    const shapes = new Set(results.map((r) => `${r.effect}|${r.reason}|${r.permission}`));
    assert.equal(shapes.size, 1);
    assert.equal([...shapes][0], 'deny|policy_denied|post:update');
  });

  it('POL-01: the ownership rule allows the owner and denies everyone else', async () => {
    // GIVEN F-POL and bob = editor
    const sys = createTestSystem({ policies: [postPolicy()] });
    const bob = await sys.createUser('bob@example.com', ['editor']);
    const subject = { id: bob, type: 'user' };
    // WHEN bob updates his own and another author's post
    // THEN only his own is allowed
    assert.equal(
      (await sys.auth.authz.authorize(subject, 'update', { type: 'post', authorId: bob })).effect,
      'allow',
    );
    assert.equal(
      (await sys.auth.authz.authorize(subject, 'update', { type: 'post', authorId: 'x' })).effect,
      'deny',
    );
  });

  it('POL-ERR-02: a rule returning undefined denies with policy_error', async () => {
    // GIVEN a policy whose rule returns undefined
    const policy = definePolicy({
      name: 'broken',
      resource: 'post',
      rules: { read: () => undefined as unknown as boolean },
    });
    const sys = createTestSystem({ policies: [policy] });
    const u = await sys.createUser('u@example.com', ['viewer']);
    // WHEN the action is authorized  THEN the decision is deny/policy_error
    const d = await sys.auth.authz.authorize({ id: u, type: 'user' }, 'read', { type: 'post' });
    assert.equal(d.effect, 'deny');
    assert.equal(d.reason, 'policy_error');
    assert.equal(sys.audit.ofType('authz.policy_error').length, 1);
  });

  it('POL-WALL-01: a wall denies even when the resource policy mode is rbacOrPolicy', async () => {
    // GIVEN a tenant wall and a post policy in rbacOrPolicy mode that would allow
    const permissive = definePolicy({
      name: 'post-or',
      resource: 'post',
      mode: 'rbacOrPolicy',
      rules: { read: () => true },
    });
    const sys = createTestSystem({ policies: [tenantWall(), permissive] });
    const alice = await sys.createUser('alice@example.com', ['admin']);
    sys.attributes.byUser.set(alice, { tenantId: 't1', attributes: {} });
    const { principal } = await sys.login('alice@example.com');
    // WHEN a resource of another tenant is read  THEN the wall denies
    const d = await sys.auth.authz.authorize(principal, 'read', { type: 'post', tenantId: 't2' });
    assert.equal(d.effect, 'deny');
    assert.equal(d.reason, 'policy_denied');
  });

  it('SCP-01: the scope admits exactly the resources authorize allows', async () => {
    // GIVEN F-POL's update scope and 60 generated resources
    const sys = createTestSystem({ policies: [postPolicy()] });
    const bob = await sys.createUser('bob@example.com', ['editor']);
    const subject = { id: bob, type: 'user' };
    const scope = await sys.auth.authz.authorizeScope(subject, 'update', 'post');
    assert.equal(scope.kind, 'constraint');
    const rows = Array.from({ length: 60 }, (_, i) => {
      if (i % 3 === 0) return { type: 'post', id: String(i), authorId: bob };
      if (i % 3 === 1) return { type: 'post', id: String(i), authorId: `other-${i}` };
      return { type: 'post', id: String(i) };
    });
    // WHEN each resource is evaluated both ways  THEN soundness and completeness hold
    for (const row of rows) {
      const allowed = (await sys.auth.authz.authorize(subject, 'update', row)).effect === 'allow';
      const inScope: boolean = scope.kind === 'constraint' ? evaluateExpr(scope.expr, row) : false;
      assert.equal(inScope, allowed, `row ${row.id}`);
    }
  });

  it('SCP-08: an absent field makes eq false and not(eq) true', () => {
    // GIVEN constraints over a field that the resource does not carry
    const present = { authorId: 'u1' };
    const absent = {};
    // WHEN evaluated  THEN the documented two-valued semantics hold
    assert.equal(evaluateExpr({ op: 'eq', field: 'authorId', value: 'u1' }, present), true);
    assert.equal(evaluateExpr({ op: 'eq', field: 'authorId', value: 'u1' }, absent), false);
    assert.equal(
      evaluateExpr({ op: 'not', arg: { op: 'eq', field: 'authorId', value: 'u1' } }, absent),
      true,
    );
    assert.equal(evaluateExpr({ op: 'eq', field: 'authorId', value: null }, absent), false);
    assert.equal(evaluateExpr({ op: 'in', field: 'authorId', values: [] }, present), false);
    // Strict typing: "1" never equals 1
    assert.equal(evaluateExpr({ op: 'eq', field: 'n', value: 1 }, { n: '1' }), false);
  });

  it('ASG-01: assigning twice reports unchanged and audits once', async () => {
    // GIVEN a user and an assigning system actor
    const sys = createTestSystem();
    const dave = await sys.createUser('dave@example.com');
    // WHEN the same role is assigned twice
    assert.equal(
      await sys.auth.authz.roles.assign(SYSTEM, dave, { roleName: 'viewer' }),
      'created',
    );
    assert.equal(
      await sys.auth.authz.roles.assign(SYSTEM, dave, { roleName: 'viewer' }),
      'unchanged',
    );
    // THEN exactly one audit event exists, and unassign is idempotent
    assert.equal(sys.audit.ofType('role.assigned').length, 1);
    assert.equal(await sys.auth.authz.roles.revoke(SYSTEM, dave, 'viewer'), true);
    assert.equal(await sys.auth.authz.roles.revoke(SYSTEM, dave, 'viewer'), false);
  });

  it('ASG-04: an assignment is inactive at the exact expiry instant', async () => {
    // GIVEN an assignment expiring at T
    const sys = createTestSystem();
    const dave = await sys.createUser('dave@example.com');
    const T = sys.clock.now() + 60_000;
    await sys.auth.authz.roles.assign(SYSTEM, dave, { roleName: 'viewer', expiresAt: T });
    const subject = { id: dave, type: 'user' };
    // WHEN the clock is set to T-1 and then T  THEN the decision flips at T
    sys.clock.set(T - 1);
    assert.equal(await sys.auth.authz.can(subject, 'read', 'post'), true);
    sys.clock.set(T);
    assert.equal(await sys.auth.authz.can(subject, 'read', 'post'), false);
    // AND an expiry in the past is rejected at assignment time
    let code = '';
    await sys.auth.authz.roles
      .assign(SYSTEM, dave, { roleName: 'viewer', expiresAt: sys.clock.now() - 1 })
      .catch((e: unknown) => {
        code = isAuthError(e) ? e.code : 'OTHER';
      });
    assert.equal(code, 'VALIDATION_FAILED');
  });

  it('ESC-02: an actor with role:assign may not assign any role to itself', async () => {
    // GIVEN alice = admin (holds role:assign)
    const sys = createTestSystem();
    const alice = await sys.createUser('alice@example.com', ['admin']);
    const { principal } = await sys.login('alice@example.com');
    // WHEN she assigns a role to herself  THEN ESCALATION_DENIED (self_assign)
    try {
      await sys.auth.authz.roles.assign(principal, alice, { roleName: 'viewer' });
      assert.fail('expected ESCALATION_DENIED');
    } catch (e) {
      assert.ok(isAuthError(e));
      assert.equal(e.code, 'ESCALATION_DENIED');
      assert.equal(e.details?.['rule'], 'self_assign');
    }
  });

  it('ESC-03: the grant ceiling blocks assigning a role beyond the actor’s own grants', async () => {
    // GIVEN a weak assigner that holds role:assign but not the admin permissions
    const catalog = defineCatalog({
      permissions: ['post:read', 'post:delete', 'role:assign', 'role:revoke'],
      roles: {
        weak_assigner: { permissions: ['role:assign', 'role:revoke', 'post:read'] },
        strong: { permissions: ['post:delete'] },
        reader: { permissions: ['post:read'] },
      },
    });
    const sys = createTestSystem({ catalog });
    await sys.createUser('weak@example.com', ['weak_assigner']);
    const target = await sys.createUser('target@example.com');
    const { principal } = await sys.login('weak@example.com');
    // WHEN a role conferring more than the actor holds is assigned  THEN ESCALATION_DENIED
    try {
      await sys.auth.authz.roles.assign(principal, target, { roleName: 'strong' });
      assert.fail('expected ESCALATION_DENIED');
    } catch (e) {
      assert.ok(isAuthError(e));
      assert.equal(e.code, 'ESCALATION_DENIED');
      assert.equal(e.details?.['rule'], 'grant_ceiling');
    }
    // AND a role within the ceiling succeeds
    assert.equal(
      await sys.auth.authz.roles.assign(principal, target, { roleName: 'reader' }),
      'created',
    );
  });

  it('ESC-09: the last superuser cannot be removed', async () => {
    // GIVEN exactly one holder of the superuser role
    const sys = createTestSystem();
    const frank = await sys.createUser('frank@example.com', ['root']);
    // WHEN the assignment is revoked  THEN ESCALATION_DENIED (last_superuser)
    try {
      await sys.auth.authz.roles.revoke(SYSTEM, frank, 'root');
      assert.fail('expected ESCALATION_DENIED');
    } catch (e) {
      assert.ok(isAuthError(e));
      assert.equal(e.details?.['rule'], 'last_superuser');
    }
    // AND with a second holder the removal succeeds
    const gina = await sys.createUser('gina@example.com', ['root']);
    assert.equal(await sys.auth.authz.roles.revoke(SYSTEM, gina, 'root'), true);
  });

  it('ESC-12: forged role claims in a token change no decision', async () => {
    // GIVEN carol = viewer with a valid session
    const sys = createTestSystem();
    await sys.createUser('carol@example.com', ['viewer']);
    const { principal } = await sys.login('carol@example.com');
    // WHEN a caller passes a subject carrying forged authorization data
    const forged = {
      ...principal,
      roles: ['admin'],
      permissions: ['*:*'],
      attributes: { admin: true },
    };
    // THEN the decision follows the stored assignments only
    assert.equal(await sys.auth.authz.can(forged, 'delete', 'post'), false);
    assert.equal(await sys.auth.authz.can(forged, 'read', 'post'), true);
    assert.deepEqual(
      [...(await sys.auth.authz.permissionsFor(forged))],
      ['post:read', 'project:read'],
    );
  });

  it('MID-01: a role added mid-session takes effect on the next decision', async () => {
    // GIVEN dave is logged in with no roles
    const sys = createTestSystem();
    const dave = await sys.createUser('dave@example.com');
    const { principal, accessToken } = await sys.login('dave@example.com');
    assert.equal(await sys.auth.authz.can(principal, 'read', 'post'), false);
    // WHEN viewer is assigned without re-login
    await sys.auth.authz.roles.assign(SYSTEM, dave, { roleName: 'viewer' });
    // THEN the same session and token observe the new permission
    const resolved = await sys.auth.authn.resolve(accessToken);
    assert.ok(resolved);
    assert.equal(resolved.sessionId, principal.sessionId);
    assert.equal(await sys.auth.authz.can(resolved, 'read', 'post'), true);
  });

  it('MID-02: a role removed mid-session is denied immediately although the token is valid', async () => {
    // GIVEN carol = viewer with a valid unexpired access token
    const sys = createTestSystem();
    const carol = await sys.createUser('carol@example.com', ['viewer']);
    const { accessToken } = await sys.login('carol@example.com');
    const before = await sys.auth.authn.resolve(accessToken);
    assert.equal(await sys.auth.authz.can(before, 'read', 'post'), true);
    // WHEN the role is revoked
    await sys.auth.authz.roles.revoke(SYSTEM, carol, 'viewer');
    // THEN the next decision denies, with the token still valid
    const after = await sys.auth.authn.resolve(accessToken);
    assert.ok(after, 'the token itself stays valid');
    assert.equal(await sys.auth.authz.can(after, 'read', 'post'), false);
  });

  it('CFG-01: an invalid configuration reports every violation at once', () => {
    // GIVEN a catalog with four independent violations  WHEN it is defined
    try {
      defineCatalog({
        permissions: ['post:read', 'BAD:Perm'],
        features: { hierarchy: true, wildcards: true },
        roles: {
          a: { permissions: ['post:write'] },
          b: { permissions: ['ghost:*'] },
          c: { inherits: ['nope'] },
        },
      });
      assert.fail('expected CONFIG_INVALID');
    } catch (e) {
      // THEN one CONFIG_INVALID carries all of them, each with a path and a rule
      assert.ok(isAuthError(e));
      assert.equal(e.code, 'CONFIG_INVALID');
      const violations = e.details?.['violations'] as { path: string; rule: string }[];
      assert.ok(violations.length >= 4, `expected >= 4 violations, got ${violations.length}`);
      assert.ok(violations.every((v) => typeof v.path === 'string' && typeof v.rule === 'string'));
    }
  });
});
