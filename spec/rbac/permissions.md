# Aegis Spec — Permissions

Status: Draft 0.1 · Normative
Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** are as defined in RFC 2119 / RFC 8174 when in capitals.

## 1. Definition

A **Permission** is a string naming one *action* on one *resource type*. It is the unit that roles grant (`roles.md`) and that the authorization engine tests (`policy/policy.md` §5).

```
Permission     = Resource ":" Action
Resource       = Segment
Action         = Segment
Segment        = [a-z] [a-z0-9_-]{0,47}          ; 1–48 characters
Pattern        = Permission
               | Resource ":" "*"                 ; all actions on a resource
               | "*" ":" Action                   ; one action on all resources
               | "*" ":" "*"                      ; everything
```

Examples of valid permissions: `user:read`, `user:update`, `project:delete`, `auction:bid`, `report:review`.
Examples of invalid permissions: `User:Read` (upper case), `user.read` (wrong separator), `user:` (empty action), `:read`, `user:read:own` (three segments), `user:rea*` (partial wildcard), `us er:read`, `1user:read`.

A *Permission* (concrete) contains no `*`. A *Pattern* is a Permission that MAY contain `*` as an entire segment. The word "permission" in this specification means a concrete Permission unless "pattern" is stated.

## 2. Validation rules

1. Permission and Pattern strings MUST match the grammar in §1 **exactly** (anchored at both ends).
2. Strings MUST be compared **case-sensitively and byte-for-byte as Unicode scalar sequences**. Implementations MUST NOT apply case-folding, trimming, Unicode normalization, or any other normalization to permission strings; a non-conforming string is *invalid*, not "corrected".
3. The total length MUST NOT exceed 97 characters.
4. A segment MUST NOT contain `*` unless it is exactly the single character `*` (no partial globs, no `**`, no regular expressions, no character classes).
5. `*` is permitted in **declarations of role grants/denies** only when the `wildcards` feature is enabled (`roles.md` §2). It MUST NOT appear in:
   1. the **permission registry** (§3), where only concrete permissions are declared;
   2. the permission derived for an authorization request (§5);
   3. any permission *required* by a route/guard (`requirePermission`) — guards require concrete permissions.
6. `*:*` MAY be granted only to a role that is explicitly declared `superuser` (`roles.md` §2.3).
7. Validation failure at configuration time MUST fail start-up with `CONFIG_INVALID`, naming the offending string and its location. Validation failure at runtime (e.g. an API argument) MUST produce `VALIDATION_FAILED`, except in the authorization decision path where §5.3 applies.

## 3. Registry

1. A project MUST declare the **complete set** of concrete permissions it uses (the *permission registry*). The registry is part of the immutable *catalog* (`roles.md` §3).
2. Every permission referenced by a role grant, role deny, direct grant, direct deny, guard, or authorization request MUST exist in the registry, except for wildcard patterns which MUST each match at least one registered permission (a pattern matching nothing MUST be rejected at start-up with `CONFIG_INVALID` — typo protection).
3. Duplicates MUST be rejected. The registry MUST be treated as a set.
4. The registry SHOULD record an optional human-readable description per permission (not used for evaluation).
5. A permission MAY be removed from the registry in a later catalog version. Stored assignments or grants that refer to a no-longer-registered permission MUST NOT confer access (treated as non-matching) and MUST be reported by the start-up lint (`doctor`) as `orphaned_permission`.
6. The registry MUST be addressable such that tooling can enumerate it; adding a permission MUST NOT implicitly grant it to any existing role. (In particular, a pattern grant such as `project:*` is evaluated against the registry **at catalog build time**; see `roles.md` §4.3.)

## 4. Matching semantics

`matches(pattern, permission) → Boolean`, where `permission` is concrete:

| pattern | matches `r:a` iff |
|---|---|
| `r:a` (concrete) | pattern is exactly `r:a` |
| `r:*` | `permission.resource == r` |
| `*:a` | `permission.action == a` |
| `*:*` | always |

1. Matching MUST be exact on whole segments. `user:*` MUST NOT match `users:read`.
2. Matching is a pure function; it MUST NOT consult storage, time, subject, or resource.
3. A set of patterns `S` **allows** concrete permission `p` iff there exists `s ∈ S` with `matches(s, p)`.
4. Pattern-to-pattern containment (needed by the grant-ceiling rule, `assignments.md` §5.3) is defined as: `A` covers `B` iff every concrete permission matched by `B` is matched by `A`. Equivalently: `*:*` covers all; `r:*` covers `r:*` and `r:a`; `*:a` covers `*:a` and `r:a`; a concrete permission covers only itself.

## 5. Request-time derivation

An authorization request has the form `(subject, action, resource)` (`policy/policy.md` §5). The permission tested by RBAC is derived as:

```
permission = resourceType + ":" + action
```

1. `resourceType` is obtained per `policy/policy.md` §4.1. `action` is the caller-supplied string.
2. Derivation MUST NOT include any request data other than those two strings.
3. **Fail-closed on invalid input.** If `resourceType` or `action` does not match `Segment`, or the derived permission is not in the registry, the decision MUST be `deny` with reason `invalid_permission` or `unknown_permission` respectively. The decision functions that return a boolean/decision (`can`, `authorize`) MUST NOT throw for this reason; `assert` MUST throw `FORBIDDEN`. The event MUST be audited as `authz.denied` with the reason, because it indicates a code defect or probing.
4. Derivation MUST NOT attempt "closest match", pluralization, or aliasing.

## 6. Reserved permissions

The following permissions are reserved by the core. A project MUST include them in its registry if it enables the corresponding capability, and the core MUST evaluate them through the same engine as any other permission:

| Permission | Required for |
|---|---|
| `role:assign` | Assigning a role to a subject (`assignments.md` §5) |
| `role:revoke` | Removing a role assignment |
| `role:read` | Listing a subject's assignments |
| `role:manage` | Creating/editing roles when `dynamicRoles` is enabled |
| `grant:assign` | Creating direct grants/denies, when `directGrants` is enabled |
| `session:read` | Listing another subject's sessions |
| `session:revoke` | Revoking another subject's sessions |
| `account:setstatus` | Changing another user's account state |

If a capability is invoked and its permission is absent from the registry, the operation MUST be denied with `FORBIDDEN` (never silently allowed) and the start-up lint MUST warn.

## 7. Naming guidance (non-normative)

* `resource` is a noun in the singular (`project`, not `projects`); `action` is a verb (`read`, `update`, `invite`) or a domain verb (`bid`, `close`).
* Prefer coarse, stable `resource:action` permissions and push *contextual* restrictions (ownership, state, tenant, time) into policies rather than encoding them into permission names (`post:update_own` is discouraged).
