// Implements spec/policy/policy.md §5-§8 (decision engine) and spec/policy/scope.md §5 (scope).
import { makePermission, projectSubject, type Subject, type Timestamp } from '../domain/index.js';
import { authError, isAuthError, configInvalid, type ConfigViolation } from '../errors/index.js';
import type { AuditEvent, AuditSink, Clock, IdGenerator } from '../ports/index.js';
import { CryptoIdGenerator } from '../ports/defaults.js';
import type { Rbac, RbacResolution } from '../rbac/resolver.js';
import { parsePermission } from '../domain/permission.js';
import {
  all as allExpr,
  FALSE,
  toAuthScope,
  TRUE,
  validateExpr,
  type AuthScope,
  type Expr,
} from './scope.js';
import type {
  Decision,
  DecisionReason,
  Mode,
  Policy,
  PolicyContext,
  PolicyInput,
  PolicyResult,
  Resource,
  RuleFn,
  TraceStep,
} from './types.js';

export interface AuthorizerOptions {
  readonly rbac: Rbac;
  readonly clock: Clock;
  readonly policies?: readonly Policy[];
  readonly audit?: AuditSink;
  readonly ids?: IdGenerator;
  /** policy.md §6.4: deny when a resource type has no applicable policy rule. Default false. */
  readonly strictPolicies?: boolean;
  /** policy.md §4.1.3: project-configured resource-type resolver. */
  readonly resolveType?: (resource: Resource) => string | undefined;
  /** policy.md §7.2. Default 'none'. */
  readonly auditAllows?: 'none' | 'all';
}

export interface AuthorizeOptions {
  /** policy.md §3.3: a trace is produced only on request. */
  readonly explain?: boolean;
  readonly request?: PolicyContext['request'];
  readonly now?: Timestamp;
}

type ResourceArg = Resource | string | null | undefined;

interface StageOutcome {
  readonly effect: 'allow' | 'deny';
  readonly reason?: DecisionReason;
  readonly matchedBy: readonly string[];
}

/**
 * The authorization decision engine. RBAC is the gate, policies refine it; the pipeline is
 * deny-by-default and fails closed at every step (INV-AUTHZ-02, INV-AUTHZ-05).
 */
export class Authorizer {
  private readonly rbac: Rbac;
  private readonly clock: Clock;
  private readonly audit?: AuditSink;
  private readonly ids: IdGenerator;
  private readonly strictPolicies: boolean;
  private readonly auditAllows: 'none' | 'all';
  private readonly resolveTypeFn?: (resource: Resource) => string | undefined;
  /** Walls: policies with resource `*` (policy.md §6.2). */
  private readonly walls: readonly Policy[];
  private readonly byResource: ReadonlyMap<string, readonly Policy[]>;

  constructor(opts: AuthorizerOptions) {
    this.rbac = opts.rbac;
    this.clock = opts.clock;
    this.audit = opts.audit;
    this.ids = opts.ids ?? new CryptoIdGenerator();
    this.strictPolicies = opts.strictPolicies ?? false;
    this.auditAllows = opts.auditAllows ?? 'none';
    this.resolveTypeFn = opts.resolveType;

    const policies = opts.policies ?? [];
    const v: ConfigViolation[] = [];
    const names = new Set<string>();
    const byResource = new Map<string, Policy[]>();
    for (const p of policies) {
      if (names.has(p.name)) {
        v.push({
          path: `policies.${p.name}`,
          rule: 'policy.unique',
          message: 'duplicate policy name',
        });
      }
      names.add(p.name);
      const list = byResource.get(p.resource) ?? [];
      list.push(p);
      byResource.set(p.resource, list);
    }
    for (const [resource, list] of byResource) {
      if (resource === '*') continue;
      // policy.md §4.2.2: all policies for one resource must agree on the mode.
      const modes = new Set(list.map((p) => p.mode));
      if (modes.size > 1) {
        v.push({
          path: `policies.${resource}`,
          rule: 'policy.mode_conflict',
          message: `conflicting modes: ${[...modes].join(', ')}`,
        });
      }
      // policy.md §4.2.1: each concrete action key must exist in the registry for that resource.
      for (const p of list) {
        for (const key of Object.keys(p.rules)) {
          if (key === '*') continue;
          const perm = makePermission(resource, key);
          if (!perm || !this.rbac.catalog.hasPermission(perm)) {
            v.push({
              path: `policies.${p.name}.rules.${key}`,
              rule: 'policy.action_key_unregistered',
              message: `no registered permission ${resource}:${key}`,
            });
          }
        }
      }
    }
    if (v.length > 0) throw configInvalid(v);

    this.walls = Object.freeze(byResource.get('*') ?? []);
    const frozen = new Map<string, readonly Policy[]>();
    for (const [k, list] of byResource) if (k !== '*') frozen.set(k, Object.freeze(list));
    this.byResource = frozen;
  }

  /** Lint findings contributed by the policy layer (roles.md §8: `or_mode_policy`). */
  lint(): readonly {
    finding: string;
    severity: 'warning' | 'info';
    path: string;
    message: string;
  }[] {
    const out: { finding: string; severity: 'warning' | 'info'; path: string; message: string }[] =
      [];
    for (const list of this.byResource.values()) {
      for (const p of list) {
        if (p.mode === 'rbacOrPolicy') {
          out.push({
            finding: 'or_mode_policy',
            severity: 'warning',
            path: `policies.${p.name}`,
            message: 'rbacOrPolicy lets a policy allow without the RBAC permission',
          });
        }
        if (p.mode === 'policyOnly') {
          out.push({
            finding: 'rbac_bypass',
            severity: 'info',
            path: `policies.${p.name}`,
            message: 'policyOnly ignores RBAC for this resource',
          });
        }
        if (p.mode === 'rbacOnly') {
          out.push({
            finding: 'policy_bypass',
            severity: 'info',
            path: `policies.${p.name}`,
            message: 'rbacOnly ignores the policy rules for this resource',
          });
        }
      }
    }
    return out;
  }

  /** `can` ≡ `authorize(...).effect === 'allow'` (policy.md §3.4). */
  async can(subject: unknown, action: string, resource?: ResourceArg): Promise<boolean> {
    const d = await this.authorize(subject, action, resource);
    return d.effect === 'allow';
  }

  /** Throws FORBIDDEN on deny (policy.md §3.4, errors.md §4.1). */
  async assert(subject: unknown, action: string, resource?: ResourceArg): Promise<void> {
    const d = await this.authorize(subject, action, resource);
    if (d.effect === 'deny') {
      throw authError('FORBIDDEN', {
        ...(d.permission !== undefined ? { details: { permission: d.permission } } : {}),
      });
    }
  }

  /** Full decision with reason (policy.md §5). Never throws for a denial. */
  async authorize(
    subject: unknown,
    action: string,
    resource?: ResourceArg,
    options: AuthorizeOptions = {},
  ): Promise<Decision> {
    const now = options.now ?? this.clock.now();
    const trace: TraceStep[] = [];
    const explain = options.explain === true;
    const push = (s: TraceStep): void => {
      if (explain) trace.push(s);
    };
    const finish = async (
      effect: 'allow' | 'deny',
      reason: DecisionReason,
      permission: string | undefined,
      matchedBy: readonly string[],
      subjectId: string | undefined,
      resourceType: string | undefined,
      resourceId: string | undefined,
    ): Promise<Decision> => {
      const decision: Decision = {
        effect,
        reason,
        ...(permission !== undefined ? { permission } : {}),
        ...(matchedBy.length > 0 ? { matchedBy } : {}),
        ...(explain ? { trace } : {}),
      };
      await this.emitDecision(decision, now, subjectId, resourceType, resourceId);
      return decision;
    };

    // ---- Stage 0: validate (policy.md §5 Stage 0)
    const s = projectSubject(subject);
    if (!s) {
      push({ stage: 'validate', name: 'subject', effect: 'deny' });
      return finish('deny', 'invalid_subject', undefined, [], undefined, undefined, undefined);
    }
    const resolved = this.resolveResource(resource);
    if (!resolved.ok) {
      push({ stage: 'validate', name: 'resource_type', effect: 'deny', note: resolved.reason });
      return finish('deny', 'invalid_permission', undefined, [], s.id, undefined, undefined);
    }
    const { resourceType, resourceObject } = resolved;
    const permission = makePermission(resourceType, action);
    if (!permission) {
      push({ stage: 'validate', name: 'permission', effect: 'deny', note: 'grammar' });
      return finish(
        'deny',
        'invalid_permission',
        undefined,
        [],
        s.id,
        resourceType,
        resourceObject.id,
      );
    }
    if (!this.rbac.catalog.hasPermission(permission)) {
      push({ stage: 'validate', name: 'permission', effect: 'deny', note: 'unregistered' });
      return finish(
        'deny',
        'unknown_permission',
        permission,
        [],
        s.id,
        resourceType,
        resourceObject.id,
      );
    }
    push({ stage: 'validate', name: 'permission', effect: 'allow', note: permission });

    // ---- RBAC resolution (fails closed: policy.md §5.5.3)
    let resolution: RbacResolution;
    try {
      resolution = await this.rbac.resolve(s, now);
    } catch (e) {
      push({ stage: 'rbac_allow', name: 'resolve', effect: 'deny', note: 'unavailable' });
      void e;
      return finish('deny', 'unavailable', permission, [], s.id, resourceType, resourceObject.id);
    }

    // ---- Stage 1: explicit RBAC deny — final, not overridable (INV-AUTHZ-01)
    if (this.rbac.deniedExplicitly(resolution, permission)) {
      push({ stage: 'rbac_deny', name: 'deny_rule', effect: 'deny' });
      return finish(
        'deny',
        'rbac_explicit_deny',
        permission,
        [],
        s.id,
        resourceType,
        resourceObject.id,
      );
    }
    push({ stage: 'rbac_deny', name: 'deny_rule', effect: 'allow' });

    // ---- Stage 2: RBAC allow
    const rbacAllowed = this.rbac.allows(resolution, permission);
    push({ stage: 'rbac_allow', name: 'grants', effect: rbacAllowed ? 'allow' : 'deny' });

    const ctx: PolicyContext = {
      now,
      ...(options.request !== undefined ? { request: options.request } : {}),
    };
    const input: PolicyInput = { subject: s, action, resource: resourceObject, ctx };

    // ---- Stage 3: walls — no mode may bypass them (INV-AUTHZ-04)
    const wall = await this.runStage(this.walls, action, input, 'wall', push);
    if (wall.effect === 'deny') {
      return finish(
        'deny',
        wall.reason ?? 'policy_denied',
        permission,
        wall.matchedBy,
        s.id,
        resourceType,
        resourceObject.id,
      );
    }

    // ---- Stage 4: resource policies
    const list = this.byResource.get(resourceType) ?? [];
    const applicable = this.applicableRules(list, action);
    const mode: Mode = list.length > 0 ? (list[0] as Policy).mode : 'rbacAndPolicy';
    const policyApplicable = applicable.length > 0;
    let policyAllowed = false;
    let policyReason: DecisionReason | undefined;
    let policyMatched: readonly string[] = [];
    if (policyApplicable) {
      const stage = await this.runStage(list, action, input, 'policy', push);
      policyAllowed = stage.effect === 'allow';
      policyReason = stage.reason;
      policyMatched = stage.matchedBy;
    } else {
      push({ stage: 'policy', name: resourceType, effect: 'skip', note: 'no applicable rule' });
    }

    // ---- Stage 5: combine (policy.md §6.1)
    const combined = this.combine(mode, rbacAllowed, policyApplicable, policyAllowed);
    if (combined === 'allow') {
      const matchedBy = [...wall.matchedBy, ...policyMatched];
      return finish(
        'allow',
        'allowed',
        permission,
        matchedBy,
        s.id,
        resourceType,
        resourceObject.id,
      );
    }
    // policy.md §6.5: deterministic reason selection.
    let reason: DecisionReason;
    if (mode === 'policyOnly' && !policyApplicable) reason = 'policy_missing';
    else if (this.strictPolicies && !policyApplicable && mode !== 'rbacOnly')
      reason = 'policy_missing';
    else if (
      !rbacAllowed &&
      (mode === 'rbacAndPolicy' || mode === 'rbacOnly' || mode === 'rbacOrPolicy')
    )
      reason = 'rbac_denied';
    else reason = policyReason ?? 'policy_denied';
    return finish('deny', reason, permission, policyMatched, s.id, resourceType, resourceObject.id);
  }

  /**
   * Scope for list/search authorization (scope.md §5). Fail-closed: never returns `all` because of
   * an error (INV-AUTHZ-10).
   */
  async authorizeScope(
    subject: unknown,
    action: string,
    resourceType: string,
    options: AuthorizeOptions = {},
  ): Promise<AuthScope> {
    const now = options.now ?? this.clock.now();
    const s = projectSubject(subject);
    if (!s) return { kind: 'none' };
    const permission = makePermission(resourceType, action);
    if (!permission || !this.rbac.catalog.hasPermission(permission)) return { kind: 'none' };

    let resolution: RbacResolution;
    try {
      resolution = await this.rbac.resolve(s, now);
    } catch {
      return { kind: 'none' };
    }
    if (this.rbac.deniedExplicitly(resolution, permission)) return { kind: 'none' };
    const rbacAllowed = this.rbac.allows(resolution, permission);

    const list = this.byResource.get(resourceType) ?? [];
    const mode: Mode = list.length > 0 ? (list[0] as Policy).mode : 'rbacAndPolicy';
    // scope.md §2.2: a missing RBAC permission settles the result before any policy is consulted.
    if (!rbacAllowed && (mode === 'rbacAndPolicy' || mode === 'rbacOnly')) return { kind: 'none' };

    const ctx: PolicyContext = {
      now,
      ...(options.request !== undefined ? { request: options.request } : {}),
    };
    const scopeInput = { subject: s, action, ctx };

    // Walls: a wall with rules but no scope function cannot be dropped (scope.md §5.1).
    const wallExprs: Expr[] = [];
    for (const w of this.walls) {
      const hasRules = this.rulesFor(w, action).length > 0;
      const fns = this.scopeFnsFor(w, action);
      if (hasRules && fns.length === 0) {
        return { kind: 'unsupported', reason: `wall ${w.name} has no scope function` };
      }
      for (const fn of fns) {
        const e = this.safeScope(fn, scopeInput);
        if (e === null) return { kind: 'none' };
        wallExprs.push(e);
      }
    }

    const policyApplicable = this.applicableRules(list, action).length > 0;
    const policyExprs: Expr[] = [];
    if (policyApplicable) {
      for (const p of list) {
        const hasRules = this.rulesFor(p, action).length > 0;
        const fns = this.scopeFnsFor(p, action);
        if (hasRules && fns.length === 0) {
          return { kind: 'unsupported', reason: `policy ${p.name} declares rules without scope` };
        }
        for (const fn of fns) {
          const e = this.safeScope(fn, scopeInput);
          if (e === null) return { kind: 'none' };
          policyExprs.push(e);
        }
      }
    }

    if (this.strictPolicies && !policyApplicable) return { kind: 'none' };

    switch (mode) {
      case 'rbacAndPolicy':
        if (!rbacAllowed) return { kind: 'none' };
        return toAuthScope(allExpr(...wallExprs, ...policyExprs));
      case 'rbacOnly':
        if (!rbacAllowed) return { kind: 'none' };
        return toAuthScope(allExpr(...wallExprs));
      case 'policyOnly':
        if (!policyApplicable) return { kind: 'none' };
        return toAuthScope(allExpr(...wallExprs, ...policyExprs));
      case 'rbacOrPolicy':
        return rbacAllowed
          ? toAuthScope(allExpr(...wallExprs))
          : toAuthScope(allExpr(...wallExprs, ...policyExprs));
    }
  }

  // ------------------------------------------------------------------ internals

  private combine(
    mode: Mode,
    rbacAllowed: boolean,
    policyApplicable: boolean,
    policyAllowed: boolean,
  ): 'allow' | 'deny' {
    if (mode === 'policyOnly') return policyApplicable && policyAllowed ? 'allow' : 'deny';
    if (mode === 'rbacOnly') return rbacAllowed ? 'allow' : 'deny';
    if (!policyApplicable) {
      // policy.md §6.4: strictPolicies denies when no policy applies.
      if (this.strictPolicies) return 'deny';
      return rbacAllowed ? 'allow' : 'deny';
    }
    if (mode === 'rbacOrPolicy') return rbacAllowed || policyAllowed ? 'allow' : 'deny';
    return rbacAllowed && policyAllowed ? 'allow' : 'deny';
  }

  private resolveResource(
    resource: ResourceArg,
  ): { ok: true; resourceType: string; resourceObject: Resource } | { ok: false; reason: string } {
    if (typeof resource === 'string') {
      return {
        ok: true,
        resourceType: resource,
        resourceObject: Object.freeze({ type: resource }),
      };
    }
    if (resource === null || resource === undefined) return { ok: false, reason: 'absent' };
    if (typeof resource !== 'object') return { ok: false, reason: 'not_an_object' };
    const declared = typeof resource.type === 'string' ? resource.type : undefined;
    const viaResolver = this.resolveTypeFn?.(resource);
    if (declared !== undefined && viaResolver !== undefined && declared !== viaResolver) {
      // policy.md §4.1: a conflict between the explicit type and the resolver is a deny.
      return { ok: false, reason: 'type_conflict' };
    }
    const resourceType = declared ?? viaResolver;
    if (resourceType === undefined) return { ok: false, reason: 'unresolved' };
    return { ok: true, resourceType, resourceObject: resource };
  }

  /** The rules of one policy applicable to an action: the concrete key and `*` (policy.md §5.2.2). */
  private rulesFor(p: Policy, action: string): readonly { key: string; fn: RuleFn }[] {
    const out: { key: string; fn: RuleFn }[] = [];
    const exact = p.rules[action];
    if (typeof exact === 'function') out.push({ key: action, fn: exact });
    const star = p.rules['*'];
    if (typeof star === 'function') out.push({ key: '*', fn: star });
    return out;
  }

  private scopeFnsFor(p: Policy, action: string): readonly import('./scope.js').ScopeFn[] {
    const out: import('./scope.js').ScopeFn[] = [];
    const exact = p.scope?.[action];
    if (typeof exact === 'function') out.push(exact);
    const star = p.scope?.['*'];
    if (typeof star === 'function') out.push(star);
    return out;
  }

  private applicableRules(
    list: readonly Policy[],
    action: string,
  ): readonly { policy: Policy; key: string; fn: RuleFn }[] {
    const out: { policy: Policy; key: string; fn: RuleFn }[] = [];
    for (const p of list) {
      for (const r of this.rulesFor(p, action)) out.push({ policy: p, key: r.key, fn: r.fn });
    }
    return out;
  }

  /** Runs one stage: every applicable rule is a required condition (policy.md §5.2.1). */
  private async runStage(
    list: readonly Policy[],
    action: string,
    input: PolicyInput,
    stage: 'wall' | 'policy',
    push: (s: TraceStep) => void,
  ): Promise<StageOutcome> {
    const matchedBy: string[] = [];
    for (const { policy, key, fn } of this.applicableRules(list, action)) {
      const name = `${policy.name}.${key}`;
      const res = await this.runRule(fn, input, policy.timeoutMs);
      if (res.kind === 'error') {
        push({ stage, name, effect: 'deny', note: 'policy_error' });
        await this.emitPolicyError(policy.name, key, res.errorClass, input);
        return { effect: 'deny', reason: 'policy_error', matchedBy: [name] };
      }
      if (res.effect === 'deny') {
        push({ stage, name, effect: 'deny' });
        return { effect: 'deny', reason: 'policy_denied', matchedBy: [name] };
      }
      push({ stage, name, effect: 'allow' });
      matchedBy.push(name);
    }
    return { effect: 'allow', matchedBy };
  }

  /**
   * Normalizes a rule result (policy.md §5.3) and enforces the timeout (§5.4). Truthiness is never
   * used: anything other than the listed shapes is an error, hence a deny.
   */
  private async runRule(
    fn: RuleFn,
    input: PolicyInput,
    timeoutMs: number,
  ): Promise<{ kind: 'ok'; effect: 'allow' | 'deny' } | { kind: 'error'; errorClass: string }> {
    let timer: NodeJS.Timeout | undefined;
    try {
      const raced = await Promise.race([
        Promise.resolve()
          .then(() => fn(input))
          .then((v) => ({ tag: 'value' as const, v })),
        new Promise<{ tag: 'timeout' }>((resolve) => {
          timer = setTimeout(() => resolve({ tag: 'timeout' }), timeoutMs);
          timer.unref?.();
        }),
      ]);
      if (raced.tag === 'timeout') return { kind: 'error', errorClass: 'timeout' };
      return normalizeResult(raced.v);
    } catch (e) {
      return { kind: 'error', errorClass: e instanceof Error ? e.name : typeof e };
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /** A scope function failure is an error, not "unsupported": the result is `none` (scope.md §5.5). */
  private safeScope(
    fn: import('./scope.js').ScopeFn,
    input: { subject: Subject; action: string; ctx: PolicyContext },
  ): Expr | null {
    try {
      const e = fn(input);
      const check = validateExpr(e);
      if (!check.ok) {
        void this.emitPolicyError('scope', input.action, `invalid_expr:${check.reason}`, {
          subject: input.subject,
          action: input.action,
          resource: {},
          ctx: input.ctx,
        });
        return null;
      }
      return e;
    } catch (e) {
      void this.emitPolicyError('scope', input.action, e instanceof Error ? e.name : typeof e, {
        subject: input.subject,
        action: input.action,
        resource: {},
        ctx: input.ctx,
      });
      return null;
    }
  }

  /** policy.md §7.1: every deny is audited; allows only per configuration. */
  private async emitDecision(
    decision: Decision,
    now: Timestamp,
    subjectId: string | undefined,
    resourceType: string | undefined,
    resourceId: string | undefined,
  ): Promise<void> {
    if (!this.audit) return;
    if (decision.effect === 'allow' && this.auditAllows === 'none') return;
    const event: AuditEvent = {
      id: this.ids.newId(),
      type: decision.effect === 'allow' ? 'authz.allowed' : 'authz.denied',
      at: now,
      severity: 'info',
      actor: { ...(subjectId !== undefined ? { id: subjectId } : {}) },
      target: {
        ...(resourceType !== undefined ? { type: resourceType } : {}),
        ...(resourceId !== undefined ? { id: resourceId } : {}),
      },
      outcome: decision.effect === 'allow' ? 'success' : 'denied',
      reason: decision.reason,
      context: {},
      // §10.4: only the permission and reason; never resource field or attribute values.
      details: {
        ...(decision.permission !== undefined ? { permission: decision.permission } : {}),
      },
    };
    await this.safeAudit(event);
  }

  private async emitPolicyError(
    policyName: string,
    ruleKey: string,
    errorClass: string,
    input: PolicyInput,
  ): Promise<void> {
    if (!this.audit) return;
    await this.safeAudit({
      id: this.ids.newId(),
      type: 'authz.policy_error',
      at: input.ctx.now,
      severity: 'warning',
      actor: { id: input.subject.id },
      target: { ...(input.resource.type !== undefined ? { type: input.resource.type } : {}) },
      outcome: 'failure',
      reason: 'policy_error',
      context: {},
      details: { policy: policyName, rule: ruleKey, errorClass },
    });
  }

  /** policy.md §7.3: an audit failure never changes a decision. */
  private async safeAudit(event: AuditEvent): Promise<void> {
    try {
      await this.audit?.write(event);
    } catch (e) {
      if (isAuthError(e)) return;
    }
  }
}

function normalizeResult(
  v: PolicyResult | unknown,
): { kind: 'ok'; effect: 'allow' | 'deny' } | { kind: 'error'; errorClass: string } {
  if (v === true) return { kind: 'ok', effect: 'allow' };
  if (v === false) return { kind: 'ok', effect: 'deny' };
  if (v !== null && typeof v === 'object') {
    const effect = (v as { effect?: unknown }).effect;
    if (effect === 'allow') return { kind: 'ok', effect: 'allow' };
    if (effect === 'deny') return { kind: 'ok', effect: 'deny' };
  }
  // null, undefined, numbers, strings, other objects: invalid result => deny (policy.md §5.3).
  return { kind: 'error', errorClass: 'invalid_result' };
}

export { parsePermission };
export { FALSE, TRUE };
