// Implements spec/policy/policy.md §2-§4: policy definition, inputs, decision shape, validation.
import { isSegment, type Json, type Subject, type Timestamp } from '../domain/index.js';
import { configInvalid, type ConfigViolation } from '../errors/index.js';
import type { ScopeFn } from './scope.js';

/** Combination mode (policy.md §4, §6.1). */
export type Mode = 'rbacAndPolicy' | 'rbacOrPolicy' | 'policyOnly' | 'rbacOnly';

/** A resource object supplied by the host. Opaque except for `type` and `id`. */
export interface Resource {
  readonly type?: string;
  readonly id?: string;
  readonly [key: string]: unknown;
}

export interface PolicyContext {
  /** The only source of time inside a rule (policy.md §4.3.1). */
  readonly now: Timestamp;
  readonly request?: Readonly<Record<string, Json>>;
  /** Named, explicitly registered loaders; a rule may not do ad-hoc I/O (policy.md §4.3.2). */
  readonly loaders?: Readonly<Record<string, (key: string) => Promise<unknown>>>;
}

export interface PolicyInput {
  readonly subject: Subject;
  readonly action: string;
  readonly resource: Resource;
  readonly ctx: PolicyContext;
}

export type PolicyResult =
  boolean | { readonly effect: 'allow' | 'deny'; readonly reason?: string };

export type RuleFn = (input: PolicyInput) => PolicyResult | Promise<PolicyResult>;

/** Policy definition input (policy.md §4). */
export interface PolicyDefinition {
  readonly name: string;
  /** A resource type, or `*` for a global wall (policy.md §6.2). */
  readonly resource: string;
  readonly mode?: Mode;
  readonly rules: Readonly<Record<string, RuleFn>>;
  readonly scope?: Readonly<Record<string, ScopeFn>>;
  /** Per-rule timeout in ms, 1..5000, default 50 (policy.md §4). */
  readonly timeoutMs?: number;
}

/** A validated, frozen policy. */
export interface Policy extends PolicyDefinition {
  readonly mode: Mode;
  readonly timeoutMs: number;
}

export type DecisionReason =
  | 'allowed'
  | 'rbac_denied'
  | 'rbac_explicit_deny'
  | 'policy_denied'
  | 'policy_error'
  | 'policy_missing'
  | 'invalid_permission'
  | 'unknown_permission'
  | 'unavailable'
  | 'invalid_subject';

export interface TraceStep {
  readonly stage: 'validate' | 'rbac_deny' | 'rbac_allow' | 'wall' | 'policy';
  readonly name: string;
  readonly effect: 'allow' | 'deny' | 'skip';
  readonly note?: string;
}

/** The result of an authorization request (policy.md §3). */
export interface Decision {
  readonly effect: 'allow' | 'deny';
  readonly permission?: string;
  readonly reason: DecisionReason;
  readonly matchedBy?: readonly string[];
  readonly trace?: readonly TraceStep[];
}

const MODES: readonly Mode[] = ['rbacAndPolicy', 'rbacOrPolicy', 'policyOnly', 'rbacOnly'];

/**
 * Validates one policy definition in isolation. Registry-dependent checks (policy.md §4.2.1 action
 * keys, §4.2.2 mode agreement) are performed by the authorizer when the policy set is registered.
 */
export function definePolicy(def: PolicyDefinition): Policy {
  const v: ConfigViolation[] = [];
  const path = `policies.${String(def.name)}`;
  if (typeof def.name !== 'string' || def.name.length < 1 || def.name.length > 64) {
    v.push({ path, rule: 'policy.name', message: 'name must be 1..64 characters' });
  }
  if (def.resource !== '*' && !isSegment(def.resource)) {
    v.push({
      path: `${path}.resource`,
      rule: 'policy.resource',
      message: 'resource must be a Segment or "*"',
    });
  }
  const mode: Mode = def.mode ?? 'rbacAndPolicy';
  if (!MODES.includes(mode)) {
    v.push({ path: `${path}.mode`, rule: 'policy.mode', message: `unknown mode ${String(mode)}` });
  }
  // policy.md §4: a wall must be rbacAndPolicy.
  if (def.resource === '*' && mode !== 'rbacAndPolicy') {
    v.push({
      path: `${path}.mode`,
      rule: 'policy.wall_mode',
      message: 'a global wall must use rbacAndPolicy',
    });
  }
  const keys = Object.keys(def.rules ?? {});
  if (keys.length === 0) {
    v.push({
      path: `${path}.rules`,
      rule: 'policy.rules',
      message: 'at least one rule is required',
    });
  }
  for (const k of keys) {
    if (k !== '*' && !isSegment(k)) {
      v.push({
        path: `${path}.rules.${k}`,
        rule: 'policy.action_key',
        message: 'action key must be a Segment or "*"',
      });
    }
    if (typeof def.rules[k] !== 'function') {
      v.push({
        path: `${path}.rules.${k}`,
        rule: 'policy.rule_fn',
        message: 'rule must be a function',
      });
    }
  }
  for (const k of Object.keys(def.scope ?? {})) {
    if (k !== '*' && !isSegment(k)) {
      v.push({
        path: `${path}.scope.${k}`,
        rule: 'policy.action_key',
        message: 'scope key must be a Segment or "*"',
      });
    }
  }
  const timeoutMs = def.timeoutMs ?? 50;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000) {
    v.push({
      path: `${path}.timeoutMs`,
      rule: 'policy.timeout',
      message: 'timeoutMs must be 1..5000',
    });
  }
  if (v.length > 0) throw configInvalid(v);
  return Object.freeze({ ...def, mode, timeoutMs });
}

/** Helper: all rules must allow; a convenience for composing conditions inside one rule. */
export function allOf(...rules: readonly RuleFn[]): RuleFn {
  return async (input) => {
    for (const r of rules) {
      const res = await r(input);
      if (res !== true && !(typeof res === 'object' && res.effect === 'allow')) return false;
    }
    return true;
  };
}

/** Helper: any rule allows. */
export function anyOf(...rules: readonly RuleFn[]): RuleFn {
  return async (input) => {
    for (const r of rules) {
      const res = await r(input);
      if (res === true || (typeof res === 'object' && res.effect === 'allow')) return true;
    }
    return false;
  };
}

/** Helper: `resource[field] === subject.id` (the ownership rule of policy.md §8.3). */
export function isOwner(field = 'ownerId'): RuleFn {
  return ({ subject, resource }) => resource[field] === subject.id;
}

/** Helper: `resource.tenantId === subject.tenantId`, both present (the tenant wall). */
export function sameTenant(field = 'tenantId'): RuleFn {
  return ({ subject, resource }) =>
    subject.tenantId !== undefined && resource[field] === subject.tenantId;
}
