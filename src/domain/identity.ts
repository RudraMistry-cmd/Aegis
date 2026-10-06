// Implements spec/auth/principal.md §3-§6: User, Identifier, Credential, password rules, account states.
import { authError, type ConfigViolation } from '../errors/index.js';
import { scalarLength, type Id, type Json, type Timestamp } from './types.js';

/** Stored user (principal.md §3). Contains no credential material. */
export interface User {
  readonly id: Id;
  readonly status: string;
  readonly version: number;
  readonly securityVersion: number;
  readonly createdAt: Timestamp;
  readonly updatedAt: Timestamp;
  readonly metadata: Readonly<Record<string, Json>>;
}

export interface NewUser {
  readonly id: Id;
  readonly status: string;
  readonly metadata: Readonly<Record<string, Json>>;
  readonly createdAt: Timestamp;
}

/** Login identifier (principal.md §4). Uniqueness is on (type, normalized). */
export interface Identifier {
  readonly id: Id;
  readonly userId: Id;
  readonly type: string;
  readonly value: string;
  readonly normalized: string;
  readonly verified: boolean;
  readonly createdAt: Timestamp;
}

/** Credential row; `payload` is secret-bearing (principal.md §5). */
export interface Credential {
  readonly id: Id;
  readonly userId: Id;
  readonly type: string;
  readonly payload: string;
  readonly createdAt: Timestamp;
  readonly lastUsedAt?: Timestamp;
}

export type NormalizeResult =
  | { readonly ok: true; readonly normalized: string }
  | { readonly ok: false; readonly reason: string };

const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,63}$/;

/** Trim + NFKC + locale-independent lowercase (common first steps of principal.md §4.1). */
export function looseNormalize(raw: string): string {
  return raw.trim().normalize('NFKC').toLowerCase();
}

/** Deterministic identifier normalization per principal.md §4.1. */
export function normalizeIdentifier(type: string, raw: unknown): NormalizeResult {
  if (typeof raw !== 'string') return { ok: false, reason: 'not_a_string' };
  const n = looseNormalize(raw);
  if (n.length === 0) return { ok: false, reason: 'empty' };
  if (type === 'email') {
    const parts = n.split('@');
    if (parts.length !== 2 || !parts[0] || !parts[1]) return { ok: false, reason: 'email_shape' };
    if (scalarLength(n) > 320) return { ok: false, reason: 'too_long' };
    return { ok: true, normalized: n };
  }
  if (type === 'username') {
    return USERNAME_RE.test(n)
      ? { ok: true, normalized: n }
      : { ok: false, reason: 'username_shape' };
  }
  // Out of scope for Phase 1 (spec/auth/principal.md §4): extension identifier types.
  return { ok: false, reason: 'unsupported_type' };
}

/** Maximum accepted password length in Unicode scalar values (principal.md §5.1.5). */
export const MAX_PASSWORD_LENGTH = 1024;

/** NFKC-normalizes a password (principal.md §5.1.5.1). */
export function normalizePassword(pw: string): string {
  return pw.normalize('NFKC');
}

/** True when a login-time password must fail without hashing (oversize). */
export function isOversizePassword(pw: string): boolean {
  return scalarLength(pw) > MAX_PASSWORD_LENGTH;
}

/** Validates a password for set/change/reset (principal.md §5.1.5). Throws VALIDATION_FAILED. */
export function assertPasswordAcceptable(pw: unknown, minLength: number): string {
  const fail = (rule: string): never => {
    throw authError('VALIDATION_FAILED', { details: { field: 'password', rule } });
  };
  if (typeof pw !== 'string') return fail('password.type');
  if (pw.includes(String.fromCharCode(0))) return fail('password.nul');
  const n = normalizePassword(pw);
  const len = scalarLength(n);
  if (len > MAX_PASSWORD_LENGTH) return fail('password.max_length');
  if (len < minLength) return fail('password.min_length');
  return n;
}

// ---- Account state machine (principal.md §6) ----

export interface AccountStateDefinition {
  readonly name: string;
  readonly canLogin: boolean;
  readonly canRefresh: boolean;
  readonly restricted: boolean;
  readonly revokeSessionsOnEnter: boolean;
}

export interface AccountStateMachine {
  readonly states: readonly AccountStateDefinition[];
  readonly initial: string;
  readonly transitions: Readonly<Record<string, readonly string[]>>;
}

/** Default state machine (principal.md §6.1.5). `initial` is `unverified`. */
export const DEFAULT_STATE_MACHINE: AccountStateMachine = {
  states: [
    {
      name: 'unverified',
      canLogin: true,
      canRefresh: true,
      restricted: true,
      revokeSessionsOnEnter: false,
    },
    {
      name: 'active',
      canLogin: true,
      canRefresh: true,
      restricted: false,
      revokeSessionsOnEnter: false,
    },
    {
      name: 'suspended',
      canLogin: false,
      canRefresh: false,
      restricted: false,
      revokeSessionsOnEnter: true,
    },
    {
      name: 'disabled',
      canLogin: false,
      canRefresh: false,
      restricted: false,
      revokeSessionsOnEnter: true,
    },
  ],
  initial: 'unverified',
  transitions: {
    unverified: ['active', 'disabled'],
    active: ['suspended', 'disabled'],
    suspended: ['active', 'disabled'],
    disabled: [],
  },
};

const STATE_NAME_RE = /^[a-z][a-z0-9_]{0,31}$/;

/** Returns all violations of principal.md §6.1 (empty when valid). */
export function validateStateMachine(sm: AccountStateMachine): ConfigViolation[] {
  const v: ConfigViolation[] = [];
  const names = new Set<string>();
  for (const s of sm.states) {
    const path = `states.${s.name}`;
    if (!STATE_NAME_RE.test(s.name))
      v.push({ path, rule: 'state.name', message: 'invalid state name' });
    if (names.has(s.name)) v.push({ path, rule: 'state.unique', message: 'duplicate state' });
    names.add(s.name);
    if (!s.canLogin && !s.revokeSessionsOnEnter) {
      v.push({
        path,
        rule: 'state.revoke_on_enter',
        message: 'canLogin=false requires revokeSessionsOnEnter',
      });
    }
    if (!s.canLogin && s.canRefresh) {
      v.push({ path, rule: 'state.refresh', message: 'canLogin=false requires canRefresh=false' });
    }
  }
  if (!sm.states.some((s) => s.canLogin)) {
    v.push({
      path: 'states',
      rule: 'state.can_login',
      message: 'at least one state must allow login',
    });
  }
  if (!names.has(sm.initial)) {
    v.push({ path: 'initial', rule: 'state.initial', message: 'initial state is not defined' });
  }
  for (const [from, tos] of Object.entries(sm.transitions)) {
    const path = `transitions.${from}`;
    if (!names.has(from))
      v.push({ path, rule: 'state.transition', message: 'unknown source state' });
    for (const to of tos) {
      if (!names.has(to))
        v.push({ path, rule: 'state.transition', message: `unknown target ${to}` });
      if (to === from)
        v.push({ path, rule: 'state.transition', message: 'self transition forbidden' });
    }
  }
  return v;
}

/** Looks up a state definition. Returns undefined for unknown names (callers fail closed). */
export function findState(
  sm: AccountStateMachine,
  name: string,
): AccountStateDefinition | undefined {
  return sm.states.find((s) => s.name === name);
}

/** True when `from -> to` is in the transition table (principal.md §6.2). */
export function canTransition(sm: AccountStateMachine, from: string, to: string): boolean {
  return (sm.transitions[from] ?? []).includes(to);
}
