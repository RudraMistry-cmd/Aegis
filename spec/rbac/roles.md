# Aegis Spec — Roles, Catalog, Inheritance, Deny

Status: Draft 0.1 · Normative
Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** are as defined in RFC 2119 / RFC 8174 when in capitals.
Permission grammar and matching: `rbac/permissions.md`. Assignments: `rbac/assignments.md`.

## 1. Feature flags

The following features are independently configurable. Every flag MUST default to the value shown. A feature that is `false` MUST be **inert**: configuration or stored data using it MUST be rejected at start-up (for configuration) or ignored-and-reported (for stored data), never silently honored.

| Flag | Default | Effect when `false` |
|---|---|---|
| `multiRole` | `true` | When `false`, a subject MUST have at most one active role assignment per scope. |
| `hierarchy` | `false` | `inherits` MUST be empty in every role. |
| `deny` | `false` | `deny` sets MUST be empty; direct denies MUST be rejected. |
| `wildcards` | `false` | No pattern containing `*` may be used. |
| `directGrants` | `false` | Direct grants MUST be rejected; stored ones MUST be ignored and reported `direct_grant_ignored`. |
| `dynamicRoles` | `false` | Roles exist only as defined in the catalog (code/config). |

## 2. Role

```
Role {
  name         : RoleName                  REQUIRED, unique   [a-z][a-z0-9_-]{0,63}
  description  : String(0..500)?           OPTIONAL
  permissions  : Set<Pattern>              REQUIRED (may be empty)
  inherits     : Set<RoleName>             REQUIRED (empty unless hierarchy)
  deny         : Set<Pattern>              REQUIRED (empty unless deny)
  superuser    : Boolean                   REQUIRED, default false
  source       : "catalog" | "dynamic"     REQUIRED
}
```

### 2.1 Constraints

1. `name` is case-sensitive and MUST NOT be normalized. It MUST NOT equal a reserved name: `*`, `system`.
2. Every entry of `permissions` and `deny` MUST be a valid Pattern (`permissions.md` §1) and MUST satisfy `permissions.md` §3.2 (registered / matches ≥ 1 registered).
3. `superuser`: only a role with `superuser = true` MAY contain `*:*` in `permissions`. A `superuser` role MUST be listed in the start-up report (`doctor`) as `superuser_role`.
4. A role MUST NOT inherit itself, directly or transitively (§4).
5. A role's contents MUST be immutable once part of a published catalog snapshot (§3). Changing a role means publishing a new snapshot.

### 2.2 Roles are not identities

A role MUST NOT be usable as a Subject, and role names MUST NOT be used as permission names or vice versa. Application code SHOULD authorize on permissions; role-name checks (`requireRole`) are a coarse convenience, evaluated as "the subject's *effective roles* (§5) contain this role name", and MUST NOT bypass deny rules or policies (INV-AUTHZ-02).

## 3. Catalog

The **catalog** is the immutable, versioned set `{ permission registry, roles, features }` against which all RBAC decisions are made.

1. A catalog MUST be validated as a whole at construction: every rule in this document and in `permissions.md` MUST hold, else `CONFIG_INVALID` listing *all* violations (not merely the first).
2. `catalogVersion` MUST be a deterministic digest of the canonical form of the catalog (same catalog ⇒ same version, independent of declaration order). Implementations MUST define canonicalization as: sort role names, sort each set lexicographically by code-point order, serialize without insignificant whitespace.
3. The catalog is the source of truth for role *definitions*; stores (`RoleCatalogStore`) mirror it for referential integrity and administration, but MUST NOT be able to alter the evaluated definition of a `catalog` role.
4. Once built, a catalog MUST be read-only. A running process MAY atomically swap in a new catalog; evaluations in progress MUST use one catalog snapshot consistently from start to finish (no mixed-version decisions).
5. When `dynamicRoles = true`, dynamic roles are additional Role records with `source = "dynamic"`, created through an authorized API (`role:manage`) subject to §7. They MUST NOT be able to override or shadow a `catalog` role name.

## 4. Inheritance (only if `hierarchy = true`)

1. `inherits` forms a **directed acyclic graph**: an edge `R → P` means R inherits everything from P.
2. Cycles MUST be rejected at catalog construction (and at dynamic role creation) with `CONFIG_INVALID` / `VALIDATION_FAILED`, with the cycle path reported.
3. Referencing an unknown role in `inherits` MUST be rejected.
4. Maximum depth (longest path) MUST be configurable, default **5**, absolute maximum **16**. Exceeding it MUST be rejected.
5. The **closure** `closure(R)` is the set containing R and every role reachable by inheritance edges. Diamond inheritance (multiple paths to one ancestor) MUST yield the ancestor once (set semantics) and MUST NOT affect results.
6. Inheritance transfers **both** permissions and denies: if `P.deny` contains pattern `d`, every role inheriting from `P` is subject to `d` (§6).
7. Inheritance MUST NOT cross scopes: it is a relation between role *definitions*; scoping is an attribute of assignments (`assignments.md` §3).
8. Computing closure MUST be deterministic and MUST be performed at catalog build time (memoized); it MUST NOT depend on storage.

## 5. Effective permissions

Given a subject, a point in time `now`, and a scope context `σ` (possibly empty; `assignments.md` §3):

```
assignedRoles(subject, now, σ)   = { a.roleName | a ∈ active assignments of subject that apply to σ }
effectiveRoles                    = ⋃ closure(r) for r ∈ assignedRoles          (closure(r) = {r} if hierarchy = false)
grants                            = ⋃ role(r).permissions for r ∈ effectiveRoles
                                    ∪ directAllow(subject, now, σ)               (only if directGrants)
denies                            = ⋃ role(r).deny for r ∈ effectiveRoles
                                    ∪ directDeny(subject, now, σ)                (only if directGrants ∧ deny)
allows(p)                          = (∃ g ∈ grants : matches(g, p))  ∧  ¬(∃ d ∈ denies : matches(d, p))
```

1. `allows` MUST be the **only** definition used by every consumer (guards, `can`, `authorize`, `permissionsFor`). There MUST NOT be a second code path computing permission checks with different semantics.
2. A role name in an assignment that is absent from the catalog (and dynamic role store) MUST contribute nothing and MUST be reported as `orphaned_assignment`; it MUST NOT cause an error that denies the subject's other roles, and MUST NOT grant access.
3. An *empty* effective role set yields `allows(p) = false` for all `p` (deny-by-default).
4. Subject without assignments is valid and has no permissions.
5. `permissionsFor(subject)` (introspection) returns the set of registered concrete permissions `p` for which `allows(p)` holds. It MUST be consistent with `allows`.

## 6. Deny precedence (only if `deny = true`)

1. **A matching deny ALWAYS overrides any matching allow**, regardless of: the role it came from, inheritance depth, specificity of pattern, wildcard vs exact, or whether the allow comes from a role or a direct grant. There is no ordering, priority, or "most specific wins" rule (INV-AUTHZ-01).
   * Allow `project:*`, deny `project:delete` ⇒ `project:delete` denied; `project:read` allowed.
   * Allow `project:delete` (exact), deny `project:*` ⇒ everything on `project` denied.
   * Allow `*:*` (superuser), deny `user:delete` ⇒ `user:delete` denied. (Superuser is not exempt from deny.)
2. Deny is evaluated within RBAC only. It is **not** overridden by policy in any combination mode (`policy/policy.md` §6.3).
3. A deny in any role in `effectiveRoles` applies to the whole subject for the evaluated scope; denies MUST NOT be "scoped to the role that carries them".
4. An expired direct deny/allow MUST NOT apply (`assignments.md` §4.2).
5. A catalog containing a role whose `permissions` and `deny` fully cancel each other (net grants empty) SHOULD be reported by lint as `ineffective_role`.

## 7. Dynamic roles (only if `dynamicRoles = true`)

1. A dynamic role MAY contain only concrete permissions and (if `wildcards`) patterns that are *covered* by the creator's own effective grants (grant ceiling, `assignments.md` §5.3). It MUST NOT be `superuser`.
2. It MAY inherit only roles that are already within the creator's effective roles (or a subset thereof).
3. Creation, modification and deletion MUST require `role:manage` and MUST be audited (`role.defined`, `role.deleted`).
4. Modification of a dynamic role MUST publish a new immutable version; evaluations in progress finish on the old version.
5. Deleting a dynamic role MUST make its assignments inert (§5.2) and MUST report them as `orphaned_assignment`; it MUST NOT silently re-point them.
6. Dynamic roles in a multi-tenant deployment MUST be namespaced by tenant such that one tenant cannot reference or modify another tenant's roles.

## 8. Lint (`doctor`) — required findings

A conforming implementation MUST provide a lint operation that reports, at least:

| Finding | Severity |
|---|---|
| `undefined_permission` (role references unregistered permission) | error |
| `unmatched_pattern` | error |
| `role_cycle`, `unknown_inherited_role` | error |
| `superuser_role` | warning |
| `wildcard_grant` (any use of `*`) | warning |
| `unused_permission` (registered but granted to no role) | info |
| `unused_role` (defined but never referable) | info |
| `ineffective_role` | warning |
| `or_mode_policy` (any policy in `rbacOrPolicy`, see `policy.md`) | warning |
| `reserved_permission_missing` | warning |
| `orphaned_assignment`, `orphaned_permission` (against stored data) | warning |

Errors MUST fail start-up; warnings MUST be emitted as `config.warning` audit events.
