// Implements spec/policy/scope.md: the constraint expression language and its evaluator.
import type { Subject, Timestamp } from '../domain/index.js';
import type { PolicyContext } from './types.js';

export type Scalar = string | number | boolean | null;

/** Constraint expression (scope.md §3). Intentionally minimal. */
export type Expr =
  | { readonly op: 'all'; readonly args: readonly Expr[] }
  | { readonly op: 'any'; readonly args: readonly Expr[] }
  | { readonly op: 'not'; readonly arg: Expr }
  | { readonly op: 'eq'; readonly field: string; readonly value: Scalar }
  | { readonly op: 'in'; readonly field: string; readonly values: readonly Scalar[] };

/** The result of `authorizeScope` (scope.md §2). */
export type AuthScope =
  | { readonly kind: 'all' }
  | { readonly kind: 'none' }
  | { readonly kind: 'constraint'; readonly expr: Expr }
  | { readonly kind: 'unsupported'; readonly reason: string };

export type ScopeFn = (input: {
  readonly subject: Subject;
  readonly action: string;
  readonly ctx: PolicyContext;
}) => Expr;

export const MAX_SCOPE_DEPTH = 16;
export const MAX_SCOPE_NODES = 256;

const FIELD_PATH_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}$/;

/** Builders (so callers do not hand-write object literals). */
export const all = (...args: Expr[]): Expr => ({ op: 'all', args });
export const any = (...args: Expr[]): Expr => ({ op: 'any', args });
export const not = (arg: Expr): Expr => ({ op: 'not', arg });
export const eq = (field: string, value: Scalar): Expr => ({ op: 'eq', field, value });
export const inList = (field: string, values: readonly Scalar[]): Expr => ({
  op: 'in',
  field,
  values,
});

/** TRUE and FALSE in normal form (scope.md §4). */
export const TRUE: Expr = { op: 'all', args: [] };
export const FALSE: Expr = { op: 'any', args: [] };

function isScalar(v: unknown): v is Scalar {
  return (
    v === null ||
    typeof v === 'string' ||
    typeof v === 'boolean' ||
    (typeof v === 'number' && Number.isFinite(v))
  );
}

/** Structural validation plus depth and node limits (scope.md §3, §3.2). */
export function validateExpr(
  e: unknown,
  depth = 1,
): { ok: true; nodes: number } | { ok: false; reason: string } {
  if (depth > MAX_SCOPE_DEPTH) return { ok: false, reason: 'depth_exceeded' };
  if (e === null || typeof e !== 'object') return { ok: false, reason: 'not_an_expression' };
  const x = e as { op?: unknown };
  switch (x.op) {
    case 'all':
    case 'any': {
      const args = (e as { args?: unknown }).args;
      if (!Array.isArray(args)) return { ok: false, reason: 'bad_args' };
      let nodes = 1;
      for (const a of args) {
        const r = validateExpr(a, depth + 1);
        if (!r.ok) return r;
        nodes += r.nodes;
        if (nodes > MAX_SCOPE_NODES) return { ok: false, reason: 'nodes_exceeded' };
      }
      return { ok: true, nodes };
    }
    case 'not': {
      const r = validateExpr((e as { arg?: unknown }).arg, depth + 1);
      return r.ok ? { ok: true, nodes: r.nodes + 1 } : r;
    }
    case 'eq': {
      const { field, value } = e as { field?: unknown; value?: unknown };
      if (typeof field !== 'string' || !FIELD_PATH_RE.test(field))
        return { ok: false, reason: 'bad_field' };
      if (!isScalar(value)) return { ok: false, reason: 'bad_value' };
      return { ok: true, nodes: 1 };
    }
    case 'in': {
      const { field, values } = e as { field?: unknown; values?: unknown };
      if (typeof field !== 'string' || !FIELD_PATH_RE.test(field))
        return { ok: false, reason: 'bad_field' };
      if (!Array.isArray(values) || !values.every(isScalar))
        return { ok: false, reason: 'bad_values' };
      return { ok: true, nodes: 1 };
    }
    default:
      return { ok: false, reason: 'unknown_op' };
  }
}

/** Reads a dotted field path. Returns `{present:false}` when any segment is missing. */
function read(resource: unknown, path: string): { present: boolean; value?: unknown } {
  let cur: unknown = resource;
  for (const seg of path.split('.')) {
    if (cur === null || typeof cur !== 'object' || !Object.hasOwn(cur as object, seg)) {
      return { present: false };
    }
    cur = (cur as Record<string, unknown>)[seg];
  }
  return { present: true, value: cur };
}

function strictEqual(a: unknown, b: Scalar): boolean {
  if (typeof a !== typeof b) return a === null && b === null;
  return a === b;
}

/**
 * Total, two-valued evaluation (scope.md §3.1). An absent field makes `eq`/`in` false, so
 * `not(eq(...))` on an absent field is true.
 */
export function evaluateExpr(e: Expr, resource: unknown): boolean {
  switch (e.op) {
    case 'all':
      return e.args.every((a) => evaluateExpr(a, resource));
    case 'any':
      return e.args.some((a) => evaluateExpr(a, resource));
    case 'not':
      return !evaluateExpr(e.arg, resource);
    case 'eq': {
      const r = read(resource, e.field);
      return r.present && strictEqual(r.value, e.value);
    }
    case 'in': {
      const r = read(resource, e.field);
      return r.present && e.values.some((v) => strictEqual(r.value, v));
    }
  }
}

/** Kind normalization of scope.md §4. */
export function toAuthScope(e: Expr): AuthScope {
  const simplified = simplify(e);
  if (simplified.op === 'all' && simplified.args.length === 0) return { kind: 'all' };
  if (simplified.op === 'any' && simplified.args.length === 0) return { kind: 'none' };
  return { kind: 'constraint', expr: simplified };
}

/** Semantics-preserving simplification (scope.md §3.2.2). */
export function simplify(e: Expr): Expr {
  switch (e.op) {
    case 'all': {
      const args = e.args.map(simplify).filter((a) => !(a.op === 'all' && a.args.length === 0));
      if (args.some((a) => a.op === 'any' && a.args.length === 0)) return FALSE;
      if (args.length === 1) return args[0] as Expr;
      return { op: 'all', args };
    }
    case 'any': {
      const args = e.args.map(simplify).filter((a) => !(a.op === 'any' && a.args.length === 0));
      if (args.some((a) => a.op === 'all' && a.args.length === 0)) return TRUE;
      if (args.length === 1) return args[0] as Expr;
      return { op: 'any', args };
    }
    case 'not':
      return { op: 'not', arg: simplify(e.arg) };
    default:
      return e;
  }
}

/** Convenience for hosts without a translator: filters a list in memory (scope.md §7). */
export function applyScope<T>(scope: AuthScope, rows: readonly T[]): readonly T[] {
  switch (scope.kind) {
    case 'all':
      return rows;
    case 'none':
      return [];
    case 'constraint':
      return rows.filter((r) => evaluateExpr(scope.expr, r));
    case 'unsupported':
      // §7.1: the caller must not run the query unfiltered. Returning [] keeps this helper safe.
      return [];
  }
}

export type { Timestamp };
