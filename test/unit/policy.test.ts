// Unit tests for the policy pipeline, permission denial and scope (spec/policy/*).
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createTestSystem, postPolicy, tenantWall } from '../support/fixtures.js';
import {
  applyScope,
  definePolicy,
  evaluateExpr,
  isAuthError,
  type Policy,
} from '../../src/index.js';

describe('policy evaluation', () => {
  it('requires both the permission and the policy by default', async () => {
    const sys = createTestSystem({ policies: [postPolicy()] });
    const bob = await sys.createUser('bob@example.com', ['editor']);
    const subject = { id: bob, type: 'user' };

    const own = await sys.auth.authz.authorize(subject, 'update', { type: 'post', authorId: bob });
    assert.equal(own.effect, 'allow');
    assert.equal(own.reason, 'allowed');

    const other = await sys.auth.authz.authorize(subject, 'update', {
      type: 'post',
      authorId: 'someone-else',
    });
    assert.equal(other.effect, 'deny');
    assert.equal(other.reason, 'policy_denied');
  });

  it('reports rbac_denied when the permission is missing, before consulting the policy', async () => {
    const sys = createTestSystem({ policies: [postPolicy()] });
    const carol = await sys.createUser('carol@example.com', ['viewer']);
    const decision = await sys.auth.authz.authorize({ id: carol, type: 'user' }, 'update', {
      type: 'post',
      authorId: carol,
    });
    assert.equal(decision.effect, 'deny');
    assert.equal(decision.reason, 'rbac_denied');
  });

  it('uses subject attributes for a contextual allow', async () => {
    const sys = createTestSystem({ policies: [postPolicy()] });
    const mod = await sys.createUser('mod@example.com', ['admin']);
    sys.attributes.byUser.set(mod, { attributes: { moderator: true } });
    const { principal } = await sys.login('mod@example.com');

    const decision = await sys.auth.authz.authorize(principal, 'delete', {
      type: 'post',
      authorId: 'another-user',
    });
    assert.equal(decision.effect, 'allow');
  });

  it('lets a wall deny even when RBAC and the resource policy allow', async () => {
    const sys = createTestSystem({ policies: [tenantWall(), postPolicy()] });
    const alice = await sys.createUser('alice@example.com', ['admin']);
    sys.attributes.byUser.set(alice, { tenantId: 't1', attributes: {} });
    const { principal } = await sys.login('alice@example.com');

    assert.equal(principal.tenantId, 't1');
    const inside = await sys.auth.authz.authorize(principal, 'update', {
      type: 'post',
      authorId: alice,
      tenantId: 't1',
    });
    assert.equal(inside.effect, 'allow');

    const outside = await sys.auth.authz.authorize(principal, 'update', {
      type: 'post',
      authorId: alice,
      tenantId: 't2',
    });
    assert.equal(outside.effect, 'deny');
    assert.equal(outside.reason, 'policy_denied');
  });

  it('denies when a rule throws, times out or returns a non-boolean', async () => {
    const cases: { name: string; policy: Policy }[] = [
      {
        name: 'throws',
        policy: definePolicy({
          name: 'p',
          resource: 'post',
          rules: {
            read: () => {
              throw new Error('boom');
            },
          },
        }),
      },
      {
        name: 'undefined',
        policy: definePolicy({
          name: 'p',
          resource: 'post',
          rules: { read: () => undefined as unknown as boolean },
        }),
      },
      {
        name: 'truthy-number',
        policy: definePolicy({
          name: 'p',
          resource: 'post',
          rules: { read: () => 1 as unknown as boolean },
        }),
      },
      {
        name: 'timeout',
        policy: definePolicy({
          name: 'p',
          resource: 'post',
          timeoutMs: 5,
          rules: { read: () => new Promise<boolean>((r) => setTimeout(() => r(true), 200)) },
        }),
      },
    ];
    for (const c of cases) {
      const sys = createTestSystem({ policies: [c.policy] });
      const u = await sys.createUser('u@example.com', ['viewer']);
      const decision = await sys.auth.authz.authorize({ id: u, type: 'user' }, 'read', {
        type: 'post',
      });
      assert.equal(decision.effect, 'deny', c.name);
      assert.equal(decision.reason, 'policy_error', c.name);
      assert.equal(sys.audit.ofType('authz.policy_error').length, 1, c.name);
    }
  });

  it('denies an invalid subject, action or resource type', async () => {
    const sys = createTestSystem({ policies: [postPolicy()] });
    const u = await sys.createUser('u@example.com', ['admin']);
    const subject = { id: u, type: 'user' };

    assert.equal((await sys.auth.authz.authorize(null, 'read', 'post')).reason, 'invalid_subject');
    assert.equal(
      (await sys.auth.authz.authorize(subject, 'Read', 'post')).reason,
      'invalid_permission',
    );
    assert.equal(
      (await sys.auth.authz.authorize(subject, 'read', '')).reason,
      'invalid_permission',
    );
    assert.equal((await sys.auth.authz.authorize(subject, 'read')).reason, 'invalid_permission');
    assert.equal(
      (await sys.auth.authz.authorize(subject, 'read', { type: 'post', id: 'x' })).effect,
      'allow',
    );
  });

  it('denies a resource type with no policy under strictPolicies', async () => {
    const sys = createTestSystem({ policies: [postPolicy()], strictPolicies: true });
    const u = await sys.createUser('u@example.com', ['admin']);
    const decision = await sys.auth.authz.authorize({ id: u, type: 'user' }, 'read', {
      type: 'project',
      id: 'p1',
    });
    assert.equal(decision.effect, 'deny');
    assert.equal(decision.reason, 'policy_missing');
  });

  it('produces a trace only when explain is requested', async () => {
    const sys = createTestSystem({ policies: [postPolicy()] });
    const u = await sys.createUser('u@example.com', ['editor']);
    const subject = { id: u, type: 'user' };
    const plain = await sys.auth.authz.authorize(subject, 'update', { type: 'post', authorId: u });
    assert.equal(plain.trace, undefined);
    const explained = await sys.auth.authz.authorize(
      subject,
      'update',
      { type: 'post', authorId: u },
      { explain: true },
    );
    assert.ok((explained.trace?.length ?? 0) > 0);
    assert.deepEqual(
      explained.trace?.map((t) => t.stage),
      ['validate', 'rbac_deny', 'rbac_allow', 'policy'],
    );
  });

  it('throws FORBIDDEN from assert and audits the denial', async () => {
    const sys = createTestSystem({ policies: [postPolicy()] });
    const carol = await sys.createUser('carol@example.com', ['viewer']);
    try {
      await sys.auth.authz.assert({ id: carol, type: 'user' }, 'delete', { type: 'post' });
      assert.fail('expected FORBIDDEN');
    } catch (e) {
      assert.ok(isAuthError(e));
      assert.equal(e.code, 'FORBIDDEN');
      assert.equal(e.message, 'You do not have permission to perform this action.');
    }
    assert.ok(sys.audit.ofType('authz.denied').length >= 1);
  });

  it('rejects conflicting policy modes for one resource at construction', async () => {
    const a = definePolicy({
      name: 'a',
      resource: 'post',
      mode: 'rbacAndPolicy',
      rules: { read: () => true },
    });
    const b = definePolicy({
      name: 'b',
      resource: 'post',
      mode: 'policyOnly',
      rules: { read: () => true },
    });
    assert.throws(
      () => createTestSystem({ policies: [a, b] }),
      (e: unknown) => isAuthError(e) && e.code === 'CONFIG_INVALID',
    );
  });
});

describe('authorizeScope', () => {
  it('returns a constraint that agrees with authorize', async () => {
    const sys = createTestSystem({ policies: [postPolicy()] });
    const bob = await sys.createUser('bob@example.com', ['editor']);
    const subject = { id: bob, type: 'user' };

    const scope = await sys.auth.authz.authorizeScope(subject, 'update', 'post');
    assert.equal(scope.kind, 'constraint');

    const rows = [
      { type: 'post', id: '1', authorId: bob },
      { type: 'post', id: '2', authorId: 'other' },
      { type: 'post', id: '3' },
    ];
    for (const row of rows) {
      const allowed = (await sys.auth.authz.authorize(subject, 'update', row)).effect === 'allow';
      const inScope: boolean = scope.kind === 'constraint' ? evaluateExpr(scope.expr, row) : false;
      assert.equal(inScope, allowed, `row ${row.id}`);
    }
    assert.deepEqual(
      applyScope(scope, rows).map((r) => r.id),
      ['1'],
    );
  });

  it('returns none when RBAC denies and unsupported when a scope function is missing', async () => {
    const sys = createTestSystem({ policies: [postPolicy()] });
    const carol = await sys.createUser('carol@example.com', ['viewer']);
    const editor = await sys.createUser('ed@example.com', ['editor']);

    assert.equal(
      (await sys.auth.authz.authorizeScope({ id: carol, type: 'user' }, 'update', 'post')).kind,
      'none',
    );
    // `delete` has a rule but no scope function.
    const unsupported = await sys.auth.authz.authorizeScope(
      { id: editor, type: 'user' },
      'delete',
      'post',
    );
    assert.equal(unsupported.kind, 'none'); // RBAC denies first for an editor
    const admin = await sys.createUser('adm@example.com', ['admin']);
    assert.equal(
      (await sys.auth.authz.authorizeScope({ id: admin, type: 'user' }, 'delete', 'post')).kind,
      'unsupported',
    );
  });

  it('returns none for an unregistered permission', async () => {
    const sys = createTestSystem({ policies: [postPolicy()] });
    const admin = await sys.createUser('adm@example.com', ['admin']);
    assert.equal(
      (await sys.auth.authz.authorizeScope({ id: admin, type: 'user' }, 'read', 'unknownthing'))
        .kind,
      'none',
    );
  });
});
