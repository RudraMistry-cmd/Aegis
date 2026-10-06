// Implements spec/rbac/roles.md §5-§6: effective roles, effective permissions, deny precedence.
import { anyMatches, type Id, type Subject, type Timestamp } from '../domain/index.js';
import type { AssignmentStore, Clock } from '../ports/index.js';
import type { Catalog } from './catalog.js';

/** The resolved RBAC view of a subject at one instant. */
export interface RbacResolution {
  /** Union of closures of the subject's active assigned roles (roles.md §5). */
  readonly roles: ReadonlySet<string>;
  readonly grants: ReadonlySet<string>;
  readonly denies: ReadonlySet<string>;
  /** Assigned role names absent from the catalog; they contribute nothing (roles.md §5.2). */
  readonly orphaned: readonly string[];
  readonly catalogVersion: string;
}

/**
 * RBAC resolution service.
 *
 * NO CACHING in Phase 1 (the brief excludes a caching layer). Every resolution reads the
 * AssignmentStore, so a role change is observed by the next decision with no staleness window —
 * the strongest form of INV-AUTHZ-06. spec/rbac/assignments.md §7 permits a cache with a bounded
 * TTL; adding one must preserve the invalidation rules of that section.
 */
export class Rbac {
  constructor(
    readonly catalog: Catalog,
    private readonly assignments: AssignmentStore,
    private readonly clock: Clock,
  ) {}

  /**
   * Resolves the subject's effective roles, grants and denies (roles.md §5).
   * Scoped assignments are not applied in Phase 1; see `isApplicable`.
   */
  async resolve(
    subject: Pick<Subject, 'id'>,
    now: Timestamp = this.clock.now(),
  ): Promise<RbacResolution> {
    const active = await this.assignments.listActive(subject.id, now);
    const roles = new Set<string>();
    const grants = new Set<string>();
    const denies = new Set<string>();
    const orphaned: string[] = [];
    for (const a of active) {
      if (!this.isApplicable(a.scope)) continue;
      const compiled = this.catalog.role(a.roleName);
      if (!compiled) {
        orphaned.push(a.roleName);
        continue;
      }
      for (const r of compiled.closure) roles.add(r);
      for (const g of compiled.grants) grants.add(g);
      if (this.catalog.features.deny) for (const d of compiled.denies) denies.add(d);
    }
    return {
      roles: Object.freeze(roles),
      grants: Object.freeze(grants),
      denies: Object.freeze(denies),
      orphaned: Object.freeze(orphaned),
      catalogVersion: this.catalog.version,
    };
  }

  /**
   * assignments.md §3.2: this implementation does not support scoped assignments, so a non-global
   * scope never applies. (`assign` rejects such scopes with VALIDATION_FAILED.)
   * Out of scope for Phase 1 (spec/rbac/assignments.md §3.3): scope contexts.
   */
  private isApplicable(scope: { type: string; id: Id } | null | undefined): boolean {
    return scope === undefined || scope === null;
  }

  /**
   * The single definition of "is permission `p` allowed" (roles.md §5.1, INV-ARCH-03).
   * A matching deny always overrides any matching allow (INV-AUTHZ-01).
   */
  allows(resolution: RbacResolution, permission: string): boolean {
    if (anyMatches(resolution.denies, permission)) return false;
    return anyMatches(resolution.grants, permission);
  }

  /** True when an explicit deny matches, so callers can report `rbac_explicit_deny`. */
  deniedExplicitly(resolution: RbacResolution, permission: string): boolean {
    return anyMatches(resolution.denies, permission);
  }

  /** Registered concrete permissions the subject holds (roles.md §5.5). Consistent with `allows`. */
  async permissionsFor(subject: Pick<Subject, 'id'>, now?: Timestamp): Promise<readonly string[]> {
    const res = await this.resolve(subject, now);
    return [...this.catalog.permissions].filter((p) => this.allows(res, p)).sort();
  }

  /** Effective role names, including those reached by inheritance (roles.md §2.2). */
  async rolesFor(subject: Pick<Subject, 'id'>, now?: Timestamp): Promise<readonly string[]> {
    const res = await this.resolve(subject, now);
    return [...res.roles].sort();
  }

  /**
   * Coarse role check for `requireRole` (roles.md §2.2). It never bypasses deny rules or policies:
   * callers that need a decision must use the authorizer.
   */
  async hasRole(subject: Pick<Subject, 'id'>, roleName: string, now?: Timestamp): Promise<boolean> {
    const res = await this.resolve(subject, now);
    return res.roles.has(roleName);
  }

  /** True when the subject holds any superuser role (used by the last-superuser guard). */
  async isSuperuser(subject: Pick<Subject, 'id'>, now?: Timestamp): Promise<boolean> {
    const res = await this.resolve(subject, now);
    for (const r of res.roles) {
      if (this.catalog.role(r)?.superuser === true) return true;
    }
    return false;
  }
}
