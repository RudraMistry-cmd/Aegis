// Implements spec/rbac/roles.md §1-§4 and §8: feature flags, Role, immutable Catalog, lint.
import { createHash } from 'node:crypto';
import {
  deepFreeze,
  isSegment,
  isWildcard,
  matches,
  parsePattern,
  parsePermission,
} from '../domain/index.js';
import { configInvalid, type ConfigViolation } from '../errors/index.js';

/** Feature flags of roles.md §1, with the specified defaults. */
export interface RbacFeatures {
  readonly multiRole: boolean;
  readonly hierarchy: boolean;
  readonly deny: boolean;
  readonly wildcards: boolean;
  readonly directGrants: boolean;
  readonly dynamicRoles: boolean;
}

export const DEFAULT_FEATURES: RbacFeatures = {
  multiRole: true,
  hierarchy: false,
  deny: false,
  wildcards: false,
  directGrants: false,
  dynamicRoles: false,
};

/** Role definition input (roles.md §2). */
export interface RoleDefinition {
  readonly permissions?: readonly string[];
  readonly inherits?: readonly string[];
  readonly deny?: readonly string[];
  readonly superuser?: boolean;
  readonly description?: string;
}

/** Compiled role: closure resolved, grants and denies flattened (roles.md §4.8). */
export interface CompiledRole {
  readonly name: string;
  readonly superuser: boolean;
  /** Role names in `closure(name)`, including itself. */
  readonly closure: ReadonlySet<string>;
  /** Union of `permissions` across the closure. */
  readonly grants: ReadonlySet<string>;
  /** Union of `deny` across the closure. */
  readonly denies: ReadonlySet<string>;
}

export interface CatalogInput {
  /** The complete permission registry: concrete permissions only (permissions.md §3). */
  readonly permissions: readonly string[];
  readonly roles: Readonly<Record<string, RoleDefinition>>;
  readonly features?: Partial<RbacFeatures>;
  /** Maximum inheritance depth (roles.md §4.4). Default 5, absolute maximum 16. */
  readonly maxDepth?: number;
}

export type LintSeverity = 'error' | 'warning' | 'info';
export interface LintFinding {
  readonly finding: string;
  readonly severity: LintSeverity;
  readonly path: string;
  readonly message: string;
}

const ROLE_NAME_RE = /^[a-z][a-z0-9_-]{0,63}$/;
const RESERVED_ROLE_NAMES = new Set(['*', 'system']);

/** Reserved permissions of permissions.md §6, mapped to the capability that requires them. */
export const RESERVED_PERMISSIONS = [
  'role:assign',
  'role:revoke',
  'role:read',
  'role:manage',
  'grant:assign',
  'session:read',
  'session:revoke',
  'account:setstatus',
] as const;

/**
 * The immutable, versioned catalog (roles.md §3). All RBAC decisions are made against one of these.
 */
export class Catalog {
  readonly permissions: ReadonlySet<string>;
  readonly features: RbacFeatures;
  readonly version: string;
  readonly maxDepth: number;
  private readonly compiled: ReadonlyMap<string, CompiledRole>;
  private readonly definitions: Readonly<Record<string, RoleDefinition>>;

  private constructor(args: {
    permissions: ReadonlySet<string>;
    features: RbacFeatures;
    compiled: ReadonlyMap<string, CompiledRole>;
    definitions: Readonly<Record<string, RoleDefinition>>;
    version: string;
    maxDepth: number;
  }) {
    this.permissions = args.permissions;
    this.features = args.features;
    this.compiled = args.compiled;
    this.definitions = args.definitions;
    this.version = args.version;
    this.maxDepth = args.maxDepth;
    Object.freeze(this);
  }

  /** Compiled role, or undefined for an unknown name (callers treat it as contributing nothing). */
  role(name: string): CompiledRole | undefined {
    return this.compiled.get(name);
  }

  roleNames(): readonly string[] {
    return [...this.compiled.keys()].sort();
  }

  /** True when the permission is in the registry (permissions.md §3.2). */
  hasPermission(p: string): boolean {
    return this.permissions.has(p);
  }

  /** Lint findings of roles.md §8. Errors are already rejected by `defineCatalog`. */
  lint(): readonly LintFinding[] {
    const out: LintFinding[] = [];
    for (const [name, role] of this.compiled) {
      const def = this.definitions[name] as RoleDefinition;
      if (role.superuser) {
        out.push({
          finding: 'superuser_role',
          severity: 'warning',
          path: `roles.${name}`,
          message: 'role holds superuser authority',
        });
      }
      for (const g of [...(def.permissions ?? []), ...(def.deny ?? [])]) {
        if (isWildcard(g)) {
          out.push({
            finding: 'wildcard_grant',
            severity: 'warning',
            path: `roles.${name}`,
            message: `wildcard pattern ${g}`,
          });
        }
      }
      const net = [...this.permissions].filter(
        (p) => matchesAny(role.grants, p) && !matchesAny(role.denies, p),
      );
      if (net.length === 0 && role.grants.size > 0) {
        out.push({
          finding: 'ineffective_role',
          severity: 'warning',
          path: `roles.${name}`,
          message: 'grants are fully cancelled by denies',
        });
      }
    }
    for (const p of this.permissions) {
      const granted = [...this.compiled.values()].some((r) => matchesAny(r.grants, p));
      if (!granted) {
        out.push({
          finding: 'unused_permission',
          severity: 'info',
          path: `permissions.${p}`,
          message: 'permission is granted to no role',
        });
      }
    }
    for (const rp of RESERVED_PERMISSIONS) {
      if (!this.permissions.has(rp)) {
        out.push({
          finding: 'reserved_permission_missing',
          severity: 'warning',
          path: `permissions.${rp}`,
          message: 'reserved permission is not registered; the capability will be denied',
        });
      }
    }
    return out;
  }

  /**
   * Validates and compiles a catalog. Throws CONFIG_INVALID listing **all** violations
   * (roles.md §3.1).
   */
  static define(input: CatalogInput): Catalog {
    const features: RbacFeatures = { ...DEFAULT_FEATURES, ...(input.features ?? {}) };
    const maxDepth = input.maxDepth ?? 5;
    const v: ConfigViolation[] = [];
    if (!Number.isInteger(maxDepth) || maxDepth < 1 || maxDepth > 16) {
      v.push({ path: 'maxDepth', rule: 'role.max_depth', message: 'maxDepth must be 1..16' });
    }

    // --- permission registry: concrete permissions only (permissions.md §3.1, §3.3, §5 note)
    const registry = new Set<string>();
    for (const p of input.permissions) {
      const path = `permissions.${String(p)}`;
      if (!parsePermission(p)) {
        v.push({ path, rule: 'permission.grammar', message: 'invalid concrete permission' });
        continue;
      }
      if (registry.has(p)) {
        v.push({ path, rule: 'permission.unique', message: 'duplicate permission' });
        continue;
      }
      registry.add(p);
    }

    // --- roles
    const names = Object.keys(input.roles);
    for (const name of names) {
      const def = input.roles[name] as RoleDefinition;
      const path = `roles.${name}`;
      if (!ROLE_NAME_RE.test(name) || RESERVED_ROLE_NAMES.has(name)) {
        v.push({ path, rule: 'role.name', message: 'invalid or reserved role name' });
      }
      const superuser = def.superuser === true;
      const checkPatterns = (list: readonly string[], field: 'permissions' | 'deny'): void => {
        for (const pat of list) {
          const p = `${path}.${field}`;
          const parsed = parsePattern(pat);
          if (!parsed) {
            v.push({ path: p, rule: 'permission.grammar', message: `invalid pattern ${pat}` });
            continue;
          }
          if (isWildcard(pat)) {
            if (!features.wildcards) {
              v.push({ path: p, rule: 'feature.wildcards', message: `wildcards disabled: ${pat}` });
              continue;
            }
            if (pat === '*:*' && !superuser) {
              v.push({ path: p, rule: 'role.superuser', message: '*:* requires superuser: true' });
            }
            // permissions.md §3.2: a pattern matching nothing is a typo.
            if (![...registry].some((perm) => matches(pat, perm))) {
              v.push({
                path: p,
                rule: 'permission.unmatched_pattern',
                message: `matches no registered permission: ${pat}`,
              });
            }
          } else if (!registry.has(pat)) {
            v.push({
              path: p,
              rule: 'permission.undefined',
              message: `unregistered permission: ${pat}`,
            });
          }
        }
      };
      checkPatterns(def.permissions ?? [], 'permissions');
      if ((def.deny ?? []).length > 0 && !features.deny) {
        v.push({ path: `${path}.deny`, rule: 'feature.deny', message: 'deny feature disabled' });
      } else {
        checkPatterns(def.deny ?? [], 'deny');
      }
      if ((def.inherits ?? []).length > 0 && !features.hierarchy) {
        v.push({
          path: `${path}.inherits`,
          rule: 'feature.hierarchy',
          message: 'hierarchy feature disabled',
        });
      }
      for (const parent of def.inherits ?? []) {
        if (!Object.hasOwn(input.roles, parent)) {
          v.push({
            path: `${path}.inherits`,
            rule: 'role.unknown_inherited',
            message: `unknown role ${parent}`,
          });
        }
      }
    }

    // --- cycles and depth (roles.md §4.2, §4.4)
    if (features.hierarchy) {
      for (const start of names) {
        const cycle = findCycle(input.roles, start);
        if (cycle) {
          v.push({
            path: `roles.${start}.inherits`,
            rule: 'role.cycle',
            message: `cycle: ${cycle.join(' -> ')}`,
          });
          continue;
        }
        const depth = longestPath(input.roles, start);
        if (depth > maxDepth) {
          v.push({
            path: `roles.${start}.inherits`,
            rule: 'role.max_depth',
            message: `inheritance depth ${depth} exceeds ${maxDepth}`,
          });
        }
      }
    }

    if (v.length > 0) throw configInvalid(v);

    // --- compile closures
    const compiled = new Map<string, CompiledRole>();
    for (const name of names) {
      const closure = features.hierarchy ? closureOf(input.roles, name) : new Set([name]);
      const grants = new Set<string>();
      const denies = new Set<string>();
      let superuser = false;
      for (const rn of closure) {
        const def = input.roles[rn] as RoleDefinition;
        for (const p of def.permissions ?? []) grants.add(p);
        for (const d of def.deny ?? []) denies.add(d);
        if (def.superuser === true) superuser = true;
      }
      compiled.set(name, {
        name,
        superuser,
        closure: Object.freeze(closure),
        grants: Object.freeze(grants),
        denies: Object.freeze(denies),
      });
    }

    return new Catalog({
      permissions: Object.freeze(registry),
      features: deepFreeze(features),
      compiled,
      definitions: deepFreeze(structuredClone(input.roles)),
      version: catalogVersion(registry, input.roles, features),
      maxDepth,
    });
  }
}

/** Convenience wrapper mirroring the configuration helper of DESIGN.md §13. */
export function defineCatalog(input: CatalogInput): Catalog {
  return Catalog.define(input);
}

function matchesAny(patterns: ReadonlySet<string>, permission: string): boolean {
  for (const p of patterns) if (matches(p, permission)) return true;
  return false;
}

function closureOf(roles: Readonly<Record<string, RoleDefinition>>, start: string): Set<string> {
  const out = new Set<string>();
  const stack = [start];
  while (stack.length > 0) {
    const n = stack.pop() as string;
    if (out.has(n)) continue;
    out.add(n);
    for (const p of roles[n]?.inherits ?? []) if (Object.hasOwn(roles, p)) stack.push(p);
  }
  return out;
}

function findCycle(
  roles: Readonly<Record<string, RoleDefinition>>,
  start: string,
): string[] | null {
  const path: string[] = [];
  const onPath = new Set<string>();
  const seen = new Set<string>();
  const walk = (n: string): string[] | null => {
    if (onPath.has(n)) return [...path.slice(path.indexOf(n)), n];
    if (seen.has(n)) return null;
    seen.add(n);
    onPath.add(n);
    path.push(n);
    for (const p of roles[n]?.inherits ?? []) {
      if (!Object.hasOwn(roles, p)) continue;
      const c = walk(p);
      if (c) return c;
    }
    path.pop();
    onPath.delete(n);
    return null;
  };
  return walk(start);
}

function longestPath(roles: Readonly<Record<string, RoleDefinition>>, start: string): number {
  const memo = new Map<string, number>();
  const walk = (n: string, guard: ReadonlySet<string>): number => {
    const cached = memo.get(n);
    if (cached !== undefined) return cached;
    let best = 1;
    for (const p of roles[n]?.inherits ?? []) {
      if (!Object.hasOwn(roles, p) || guard.has(p)) continue;
      best = Math.max(best, 1 + walk(p, new Set([...guard, n])));
    }
    memo.set(n, best);
    return best;
  };
  return walk(start, new Set());
}

/** Deterministic version digest over the canonical form (roles.md §3.2). */
function catalogVersion(
  permissions: ReadonlySet<string>,
  roles: Readonly<Record<string, RoleDefinition>>,
  features: RbacFeatures,
): string {
  const canonical = {
    permissions: [...permissions].sort(),
    roles: Object.keys(roles)
      .sort()
      .map((name) => {
        const d = roles[name] as RoleDefinition;
        return {
          name,
          permissions: [...(d.permissions ?? [])].sort(),
          inherits: [...(d.inherits ?? [])].sort(),
          deny: [...(d.deny ?? [])].sort(),
          superuser: d.superuser === true,
        };
      }),
    features: Object.fromEntries(Object.entries(features).sort(([a], [b]) => (a < b ? -1 : 1))),
  };
  return createHash('sha256').update(JSON.stringify(canonical)).digest('hex').slice(0, 32);
}

export { isSegment };
