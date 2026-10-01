# Aegis Spec — Assignments, Direct Grants, Escalation Guards, Caching

Status: Draft 0.1 · Normative
Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** are as defined in RFC 2119 / RFC 8174 when in capitals.
Role and permission semantics: `rbac/roles.md`, `rbac/permissions.md`.

## 1. Role assignment

```
RoleAssignment {
  subjectId   : Id                REQUIRED
  roleName    : RoleName          REQUIRED
  scope       : Scope?            OPTIONAL   absent/null = global
  expiresAt   : Timestamp?        OPTIONAL
  grantedBy   : Id                REQUIRED   subject id of the assigner, or the reserved id "system"
  grantedAt   : Timestamp         REQUIRED
}
Scope { type: String(1..32) matching [a-z][a-z0-9_-]*,  id: Id }     e.g. {type:"tenant", id:"t-42"}
```

1. Identity of an assignment is `(subjectId, roleName, scope)`. At most one assignment per identity MUST exist.
2. `assign` is **idempotent**: assigning an existing identity MUST succeed without error. It MAY update `expiresAt` only if the request explicitly supplies a different value and the caller is authorized; `grantedBy`/`grantedAt` of the original assignment MUST be preserved. It MUST NOT emit a second `role.assigned` event when nothing changed.
3. `unassign` is **idempotent**: removing a non-existent assignment MUST succeed and MUST be a no-op.
4. `roleName` MUST exist in the catalog (or dynamic store) at assignment time, else `VALIDATION_FAILED`. (An assignment may later become orphaned, see `roles.md` §5.2.)
5. `expiresAt`, if present, MUST be in the future at assignment time, else `VALIDATION_FAILED`.
6. `grantedBy` MUST be derived by the implementation from the acting Principal. It MUST NOT be supplied by the caller (INV-AUTHZ-08).
7. With `multiRole = false`, an `assign` that would create a second active assignment in the same scope MUST fail with `CONFLICT`.

## 2. Subject existence

`assign` for a `subjectId` that does not exist in the identity store MUST fail with `NOT_FOUND` where the subject type is `user`. For other subject types, existence checking is delegated to the extension that owns the type.

## 3. Scope

1. The scope mechanism is reserved to allow tenancy/organization/resource-scoped roles without a schema change.
2. An implementation that **does not** support scoped assignments MUST reject any non-null `scope` with `VALIDATION_FAILED` and MUST NOT store it.
3. An implementation that supports scopes MUST apply this rule: given an evaluation scope context `σ` (a possibly-empty set of `Scope` values supplied by the caller/engine, e.g. `{tenant:t-42}` derived from `subject.tenantId` or the resource), an assignment *applies* iff `assignment.scope` is absent **or** `assignment.scope ∈ σ`.
4. An assignment with a scope MUST NOT apply when `σ` is empty (scoped grants never leak into unscoped decisions).
5. A global assignment applies to every `σ`. Deployments needing tenant isolation SHOULD avoid global assignments for tenant-facing roles.
6. `σ` MUST be derived only from trusted sources: `Subject.tenantId` and the resource object loaded by the host. It MUST NOT be taken from request input.

## 4. Time-bounded assignments and direct grants

1. `expiresAt` is evaluated against the injected `Clock` at **read/evaluation** time: an assignment is *active* iff `expiresAt` is absent or `now < expiresAt`. An expired assignment MUST NOT contribute to effective roles even if the record has not been cleaned up.
2. The same rule applies to direct grants (§5).
3. Housekeeping deletion of expired records MAY occur at any time and MUST NOT change any decision.

## 5. Direct grants (only if `directGrants = true`)

```
DirectGrant {
  subjectId  : Id
  permission : Pattern                  (Pattern only if wildcards enabled; else concrete)
  effect     : "allow" | "deny"         ("deny" only if deny feature enabled)
  scope      : Scope?
  expiresAt  : Timestamp?
  reason     : String(1..500)           REQUIRED (audit justification)
  grantedBy  : Id
  grantedAt  : Timestamp
}
```

1. Identity is `(subjectId, permission, effect, scope)`; idempotent as in §1.
2. Direct grants participate in `effectiveRoles`-independent evaluation per `roles.md` §5.
3. Creating or removing a direct grant requires `grant:assign`, is subject to §6 (escalation guard) as if the grant were a one-permission role, and MUST emit `grant.assigned` / `grant.revoked`.
4. A `reason` is REQUIRED. Direct grants without expiry SHOULD be flagged by lint (`permanent_direct_grant`).

## 6. Assignment-authority and escalation guards

The assignment API is itself an authorization-sensitive operation. It MUST be evaluated through the same authorization engine (not a bypass).

Given acting Principal `A`, target subject `T`, role `R`:

1. **Permission required.** `A` MUST hold `role:assign` (assign) or `role:revoke` (unassign) via `authorize(A, ...)` for the target scope. Denied ⇒ `FORBIDDEN`.
2. **No self-escalation.** When `blockSelfAssign = true` (default `true`), `A.id == T.id` MUST be rejected with `ESCALATION_DENIED` for `assign` (for any role). Self-`unassign` MAY be permitted.
3. **Grant ceiling** (default **on**). `A` MUST NOT assign a role `R` whose effective permission set (`grants` of `closure(R)`) is not **covered** by `A`'s own effective grants in the target scope (coverage per `permissions.md` §4.4, using the *allows* relation: for every concrete registered permission `p` allowed by `R`, `allows_A(p)` MUST hold). Violation ⇒ `ESCALATION_DENIED`. A `superuser` role MAY be assigned only by a Principal holding a superuser role.
4. **Deny non-removal.** Where `deny = true`, an actor MUST NOT be able to remove a deny that applies to the *actor themselves* by editing their own assignments; (same as rule 2).
5. **Last-superuser protection.** The system MUST NOT permit an operation (unassign, expiry-setting, account disable, delete) that would leave **zero** active superuser-role holders when at least one existed, unless called with an explicit, separately-audited `forceLastSuperuser` flag by the reserved `system` actor. Violation ⇒ `ESCALATION_DENIED`.
6. **Tenant boundary.** When `A` is bound to a `tenantId`, `A` MUST NOT assign or revoke roles of a subject in a different tenant, and MUST NOT create assignments with a scope outside A's tenant, unless `A` holds a global role that permits it (ceiling applies).
7. **Atomicity.** Checks 1–6 and the write MUST be performed in one atomic unit with respect to concurrent changes of `A`'s own effective grants and of the last-superuser count (a TOCTOU between ceiling check and write MUST NOT allow escalation; INV-AUTHZ-07).
8. **Audit.** Every successful and every denied attempt MUST emit `role.assigned` / `role.revoked` / `authz.denied` with `actor`, `target`, `role`, `scope`, and `reason`.
9. The assignment API MUST NOT accept `grantedBy`, `grantedAt`, or the audit fields from input.

## 7. Resolution inputs and caching

Resolution of effective permissions (`roles.md` §5) uses the data-sources below. Caching is OPTIONAL but, when implemented, MUST obey this section.

1. **Catalog-derived data** (role closures, permission sets) is a pure function of `catalogVersion` and MAY be cached indefinitely keyed by `catalogVersion`. A new catalog version MUST NOT reuse old cache entries.
2. **Subject-derived data** (assignments, direct grants) MAY be cached per `(subjectId, scopeContext)` with TTL `subjectTtl` (default **30 s**, MUST be ≤ 300 s, MAY be 0).
3. **Invalidation.** Every mutation of a subject's assignments or direct grants (assign, unassign, grant, expiry change, subject deletion) MUST invalidate that subject's cache entries *in the local process* before the mutation call returns, and SHOULD publish an invalidation to other processes when a shared invalidation channel is configured.
4. **Staleness bound.** With no shared channel, the bound on observing a change in another process is `subjectTtl`. The implementation MUST document this bound. With a working channel the bound SHOULD be the channel's propagation delay.
5. **Expiry awareness.** A cache entry MUST NOT be served past the earliest `expiresAt` among the assignments/grants it contains (entries expire no later than that instant), so an elapsed assignment never lingers for `subjectTtl`.
6. **Fail-safe.** If the cache is unavailable, evaluation MUST fall back to the store; if the store is also unavailable the decision MUST be `deny` (reason `unavailable`) for `can/authorize`, and `STORAGE_UNAVAILABLE` for operations that cannot represent a decision. A cache error MUST NEVER produce `allow`.
7. **Security version interplay.** A change of `User.securityVersion` MUST bypass subject-derived cache entries for that subject (the cache key MUST include `securityVersion`, or the entry MUST be invalidated on bump).
8. **Mid-session role changes.** Because tokens carry no permissions (`tokens.md` §2.4), after the invalidation in rule 3 completes, the very next authorization request for that subject — on the *same session* and *without re-login* — MUST observe the new assignments (INV-AUTHZ-06). Role *removal* MUST NOT be delayed by a still-valid access token.

## 8. Listing and introspection

1. `listAssignments(subjectId)` MUST exclude expired assignments by default and MUST be authorized (`role:read`) unless the subject is the caller.
2. `listSubjectsByRole(role, page)` MUST be paginated with a stable ordering (by subject id) and MUST be authorized (`role:read`).
3. `permissionsFor(subject)` MUST be authorized (callers MAY introspect themselves without additional permission).
4. Introspection results MUST reflect the same cache semantics as decisions (§7); an implementation MUST NOT return a more or less permissive view than `allows` would.
