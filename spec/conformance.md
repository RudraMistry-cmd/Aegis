# Aegis Spec — Conformance

Status: Draft 0.1 · Normative
Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** are as defined in RFC 2119 / RFC 8174 when in capitals.

This document defines **what it means to conform** and the **behavioral test cases** that decide it. Tests are described by *observable behavior* (given / when / then). They prescribe no language, framework, database, or test runner. A *conformance suite* is any executable realization of these cases; the reference suite lives in `testkit` and consumes the machine-readable vectors described in §8.

---

## 1. Conformance claims

An implementation (or adapter) MAY claim conformance to one or more **profiles**. A claim is valid only if **every MUST-level test** of the profile passes. SHOULD-level tests are reported but do not invalidate the claim.

| Profile | Applies to | Test groups |
|---|---|---|
| **P-AUTHZ** | Authorization core (RBAC + policy + scope + assignments) | AZ, POL, SCP, ASG, ESC, CAT, TEN, MID, TIME, CFG (rbac/policy parts), AUD (authz parts), ERR |
| **P-AUTHN** | Authentication core (identity, sessions, tokens, flows) | PRN, ID, CRED, STATE, AUTH, REG, VER, RST, CHG, SESS, TOK-REF, OTT, REF, REV, RACE, TIME, CFG, AUD, ERR |
| **P-TRANSPORT-TOKEN** | Access-token + refresh transport | TOK-ACC, REF, X-SWAP |
| **P-TRANSPORT-SESSION** | Opaque server-session transport | SES-OPQ, X-SWAP |
| **P-STORE-FULL** | Storage adapter with full atomicity (`A-FULL`) | STO (all) |
| **P-STORE-LITE** | Storage adapter (`A-LITE`) | STO (all except those marked **[A2]**); adapter MUST declare unsupported compound operations |
| **P-INTEGRATION** (non-core) | Framework integrations | Out of scope for this document; MUST NOT alter any result above |

An implementation claiming P-AUTHN **and** P-AUTHZ and a transport profile and a store profile is a *full conformant system*. Third-party adapters (storage, cache, hasher, transport, policy engine) are certified individually against the relevant group.

A claim MUST state: spec version, profile list, and for each optional feature (hierarchy, deny, wildcards, directGrants, dynamicRoles, scopes, reuseGrace) whether it is implemented. Strict revocation is not optional (`tokens.md` §2.5). Tests tagged `[feature: X]` apply only if X is claimed. A claimed-but-failing feature voids the claim for that feature; an unclaimed feature MUST be inert (CFG-03).

## 2. Harness requirements

A conformance harness MUST provide:

1. **Controllable Clock** (`storage/interfaces.md` §9.1): set, advance, and jump backward.
2. **Deterministic Random/IdGenerator** (test-only), plus the real CSPRNG for entropy tests.
3. **Reference in-memory adapters** for every port, themselves passing group STO. (These define semantics; they are the oracle for differential testing.)
4. **Concurrency driver:** starts N tasks behind a barrier against the system under test (threads, processes, or hosts as the implementation permits); supports `schedule` fuzzing — each RACE test MUST be repeated for **at least 200 randomized schedules** (or exhaustively via a deterministic scheduler where available). A single invariant violation in any schedule fails the test.
5. **Fault injector** wrapping any port: fail the k-th call; fail after commit but before return (“lost acknowledgement”); inject latency/timeout; make a port permanently `Unavailable`; crash the "process" after a named step (the harness discards all in-memory state and re-instantiates the system from the stores).
6. **Observation taps:** capture every audit event, log line, error value, and every string written to any store, so tests can assert on absence of secrets and on exact event multiplicity.
7. **Instrumented ports** (call counters and ordering) for `PasswordHasher`, `RateLimiter`, stores — to assert *behavioral* properties such as "exactly one hasher operation".
8. **Two-instance mode:** two independent system instances sharing the same stores (simulating multi-process deployment), with and without a shared cache-invalidation channel.

## 3. Test case notation

`ID — Title.` **Given** preconditions. **When** actions. **Then** observable results. A trailing `[MUST]` / `[SHOULD]`, `[feature: X]`, `[A2]` annotates level. Unless stated, tests are `[MUST]`.

## 4. Standard fixtures

**F-CAT** (feature flags all enabled unless a test says otherwise):

* Permissions: `post:read`, `post:update`, `post:delete`, `project:read`, `project:update`, `project:delete`, `user:read`, `user:update`, `user:delete`, `role:assign`, `role:revoke`, `role:read`, `session:read`, `session:revoke`, `account:setstatus`.
* Roles: `viewer` = {`post:read`, `project:read`}; `editor` inherits `viewer` + {`post:update`, `project:update`}; `admin` inherits `editor` + {`user:*`, `post:delete`, `project:delete`, `role:assign`, `role:revoke`, `role:read`, `session:read`, `session:revoke`, `account:setstatus`}; `contractor` inherits `editor`, deny {`post:delete`, `project:delete`}; `root` = {`*:*`}, `superuser = true`; `auditor` = {`user:read`, `role:read`}.

**F-USERS** (all `active`): `alice`=admin, `bob`=editor, `carol`=viewer, `dave`=no roles, `erin`=contractor, `frank`=root, `gina`=editor + viewer. Tenants: `alice`, `bob` in tenant `T1`; `hank` (editor) in tenant `T2`.

**F-POL**: policy `post` (rbacAndPolicy): `update` ⇒ `resource.authorId == subject.id`; `delete` ⇒ owner OR `subject.attributes.moderator == true`; wall `*`: `resource.tenantId == subject.tenantId`.

**F-TIME**: clock starts at `2030-01-01T00:00:00.000Z`.

---

## 5. Authorization groups (P-AUTHZ)

### 5.1 AZ-ARCH / AZ-RBAC — RBAC resolution

| ID | Scenario |
|---|---|
| AZ-ARCH-01 | Given a Subject constructed by hand (no token, no session, no authentication occurred), and a Principal for the same identity; when each is authorized for the same (action, resource); then Decisions are identical. A Subject missing `type` ⇒ deny `invalid_subject`. |
| AZ-RBAC-01 | `carol` (viewer): allowed exactly `post:read`, `project:read` among the registry; denied every other registered permission. |
| AZ-RBAC-02 | `dave` (no assignments): denied every registered permission; `permissionsFor(dave)` is empty. |
| AZ-RBAC-03 | `gina` (editor + viewer): effective permissions equal the union; duplicates have no effect. |
| AZ-RBAC-04 | [feature: hierarchy] `admin` is allowed `post:read` (via editor → viewer) and `post:update`; closure computed transitively. |
| AZ-RBAC-05 | [feature: hierarchy] Diamond: roles B and C inherit A; D inherits B and C; D grants exactly A ∪ B ∪ C ∪ D once; decisions unaffected by path count. |
| AZ-RBAC-06 | [feature: hierarchy unclaimed] Catalog with `inherits` ⇒ `CONFIG_INVALID`. |
| AZ-RBAC-07 | [feature: wildcards] `admin` holding `user:*`: allowed `user:read|update|delete`; denied `users:read` (not registered) with reason `unknown_permission`. |
| AZ-RBAC-08 | [feature: wildcards] A role holding `*:read` is allowed `post:read`, `project:read`, `user:read`; denied `post:update`. |
| AZ-RBAC-09 | `user:*` does not match any permission whose resource segment merely starts with `user` (e.g. `user_group:read`, if registered). |
| AZ-RBAC-10 | Patterns `us*:read`, `**`, `user:re*`, `*:*:*`, `user:` ⇒ `CONFIG_INVALID` in a catalog; as a runtime action ⇒ deny `invalid_permission`. |
| AZ-RBAC-11 | `authorize(s, "Read", "post")`, `authorize(s, "read", "Post")`, `authorize(s, " read", "post")` ⇒ deny `invalid_permission` (no normalization). |
| AZ-RBAC-12 | An assignment naming a role absent from the catalog contributes nothing and does not grant anything; `doctor` reports `orphaned_assignment`. |
| AZ-RBAC-13 | A subject with one orphaned and one valid assignment keeps the valid role's permissions. |
| AZ-RBAC-14 | Property: for every registered permission `p` and every fixture user, `p ∈ permissionsFor(u)` ⇔ `can(u, action(p), type(p))` is true for a resource with no policy. |
| AZ-RBAC-15 | `requireRole("editor")` passes for `alice` (admin) via hierarchy and for `bob`; fails for `carol`, `dave`. |
| AZ-RBAC-16 | `erin` (contractor) passes `requireRole("editor")` but `project:delete` is denied: a role check never bypasses deny. |
| AZ-RBAC-17 | Shuffling declaration order of roles/permissions/inherits yields identical decisions for all (user, permission) pairs and an identical `catalogVersion`. |
| AZ-RBAC-18 | A role with empty `permissions` and no inherits is valid and grants nothing. |
| AZ-RBAC-19 | `frank` (root): allowed every registered permission; `root` appears in `doctor` as `superuser_role` and `wildcard_grant`. |
| AZ-RBAC-20 | For the full product of fixture users × registered permissions, the five entry points — `can`, `authorize`, `assert`, `permissionsFor`, and the permission guard — agree (INV-ARCH-03). |

### 5.2 AZ-DENY — deny precedence [feature: deny]

| ID | Scenario |
|---|---|
| AZ-DENY-01 | Role grants `project:*`, role denies `project:delete`: `project:delete` denied (`rbac_explicit_deny`); `project:read|update` allowed. |
| AZ-DENY-02 | Role allows exact `project:delete`; same subject holds role denying `project:*`: all `project:*` denied. |
| AZ-DENY-03 | `frank` (`*:*`) additionally assigned a role denying `user:delete`: `user:delete` denied; all else allowed. |
| AZ-DENY-04 | Deny declared on a parent role applies to every child role inheriting it (`erin`: `post:delete` denied although `editor` ancestry has none). |
| AZ-DENY-05 | Subject holds role X (allows `post:delete`) and role Y (denies it): denied regardless of assignment order, count, or timestamps. |
| AZ-DENY-06 | A policy in `rbacOrPolicy` mode that would allow, a direct grant allowing, and a wall allowing — none overrides an RBAC explicit deny. |

### 5.3 AZ-DEF / AZ-DET — default deny, fail closed, determinism

| ID | Scenario |
|---|---|
| AZ-DEF-01 | Permission not in registry ⇒ deny `unknown_permission`; audit `authz.denied`. |
| AZ-DEF-02 | Action not matching Segment grammar (empty, `a:b`, 49 chars, unicode) ⇒ deny `invalid_permission`; `can`/`authorize` never throw; `assert` throws `FORBIDDEN`. |
| AZ-DEF-03 | Resource type not resolvable ⇒ deny `invalid_permission`. |
| AZ-DEF-04 | Explicit type argument conflicts with `resource.type` ⇒ deny `invalid_permission`. |
| AZ-DEF-05 | Assignment store fails (`Unavailable`) with no cache ⇒ deny `unavailable`; never allow. |
| AZ-DEF-06 | Cache throws on `get`: treated as miss; store consulted; correct decision. |
| AZ-DEF-07 | Cache returns corrupted/undecodable bytes: treated as miss; correct decision; no allow derived from garbage. |
| AZ-DEF-08 | Cache and store both fail ⇒ deny `unavailable`. |
| AZ-DEF-09 | Policy throws ⇒ deny `policy_error` (see POL-ERR). |
| AZ-DEF-10 | `AuditSink.write` throws on every call ⇒ decisions unchanged (allow stays allow, deny stays deny); failures reported to `Logger`. |
| AZ-DET-01 | Same (subject, action, resource, state, clock) evaluated 1 000 times, sequentially and concurrently, with randomized internal evaluation order: identical `effect` and `reason` every time. |

### 5.4 POL — policy engine

| ID | Scenario |
|---|---|
| POL-01 | F-POL owner rule: `bob` updates own post ⇒ allow; updates another's post ⇒ deny `policy_denied`. |
| POL-02 | Tenant wall: `bob` (T1) reads a post of T2 ⇒ deny even though RBAC allows. |
| POL-03 | State-based rule (moderator only on state ∈ {reported}): allowed for `reported`, denied for `published`. |
| POL-04 | Time-based rule with F-TIME: allowed at 09:00:00.000Z, denied at the first instant the rule disallows (boundary inclusive/exclusive as defined by the rule), unaffected by the host timezone or DST. |
| POL-05 | Mode truth tables over (R, P): `rbacAndPolicy` (R∧P), `rbacOrPolicy` (R∨P), `policyOnly` (P; no applicable rule ⇒ deny `policy_missing`), `rbacOnly` (R). Each of the four (R,P) combinations is exercised for each mode. |
| POL-06 | Action rule and `*` rule both defined: both MUST allow; one denying denies. |
| POL-07 | Two policies registered for the same resource type: AND semantics; order of registration irrelevant. |
| POL-08 | Two policies for the same resource with different modes ⇒ `CONFIG_INVALID`. |
| POL-09 | `strictPolicies = true`: resource type with no applicable rule ⇒ deny `policy_missing` although RBAC allows. |
| POL-10 | Type-only resource (`authorize(s, "create", "project")`) is handled; rules needing missing fields deny without error. |
| POL-11 | A rule that attempts to mutate `subject`/`resource` has no effect visible to later rules or the caller. |
| POL-12 | `explain = false` ⇒ `trace` absent; `explain = true` ⇒ trace lists stages in order with effects; trace contains no resource field values. |
| POL-13 | `reason` for each denial path is exactly as defined in `policy.md` §6.5 (table-driven). |
| POL-14 | Rule keyed to an action absent from the permission registry ⇒ `CONFIG_INVALID`. |
| POL-15 | Policies are not cached: mutating the resource between two calls changes the second Decision accordingly. |
| POL-WALL-01 | A wall denies even when a resource policy in `rbacOrPolicy` allows and RBAC allows. |
| POL-WALL-02 | A wall denies even in `policyOnly` mode. |
| POL-WALL-03 | A wall whose required field is absent from the resource denies (no implicit allow). |
| POL-ERR-01 | Rule throws ⇒ deny `policy_error`. |
| POL-ERR-02 | Rule returns `undefined`/`null` ⇒ deny `policy_error`. |
| POL-ERR-03 | Rule returns `1`, `"true"`, `{}`, `[]` ⇒ deny `policy_error` (no truthiness). |
| POL-ERR-04 | Rule exceeds `timeoutMs` ⇒ deny `policy_error`; the late result, if any, is discarded. |
| POL-ERR-05 | Loader fails or times out ⇒ deny `policy_error`. Every POL-ERR case also emits `authz.policy_error` and an `authz.denied`; none ever yields `INTERNAL` to the caller. |

### 5.5 SCP — authorization scope

| ID | Scenario |
|---|---|
| SCP-01 | **Equivalence property.** For each policy declaring both rules and scope, over ≥ 1 000 generated subjects × resources (including missing/null fields): `evaluate(scope, r)` ⇔ `authorize(s, a, r).effect = allow` (soundness and completeness). |
| SCP-02 | RBAC does not allow ⇒ `{kind:"none"}` (modes `rbacAndPolicy`, `rbacOnly`). |
| SCP-03 | RBAC explicit deny ⇒ `none`, under every mode. |
| SCP-04 | Rules present, no scope function for the action ⇒ `unsupported`. |
| SCP-05 | A wall policy with rules but no scope function ⇒ `unsupported` (walls never dropped). |
| SCP-06 | Scope function throws/times out ⇒ `none` and `authz.policy_error`; never `all`. |
| SCP-07 | Reference translator applied to a 1 000-row dataset: items, total count, and page cursors for a subject contain no information about unauthorized rows (compare outputs for datasets differing only in unauthorized rows ⇒ identical). |
| SCP-08 | Absent-field semantics: `eq(f,v)` false when `f` absent; `not(eq(f,v))` true; `eq(f,null)` false when absent. |
| SCP-09 | `in` with empty list ⇒ false; `all([])` ⇒ `{kind:"all"}`; `any([])` ⇒ `{kind:"none"}`. |
| SCP-10 | Expression exceeding depth 16 or 256 nodes ⇒ `unsupported`. |
| SCP-11 | A subject value such as `"x' OR '1'='1"` or `"\"; DROP"` is matched **literally** by the reference evaluator and appears only as a data value in the constraint. |
| SCP-12 | `rbacOrPolicy`: RBAC allows ⇒ scope is walls only; RBAC denies ⇒ walls ∧ policy scope. |
| SCP-13 | Translator given an unknown field path fails closed (matches nothing) and reports configuration error. |

### 5.6 ASG — assignments and direct grants

| ID | Scenario |
|---|---|
| ASG-01 | `assign` twice ⇒ second returns `unchanged`; one `role.assigned` audit event total. |
| ASG-02 | `unassign` of non-existing ⇒ success, no event. |
| ASG-03 | `assign` with unknown role ⇒ `VALIDATION_FAILED`; unknown user ⇒ `NOT_FOUND`. |
| ASG-04 | Assignment with `expiresAt = T`: allowed at `T − 1 ms`, **not** active at `T` (strict `now < expiresAt`), with no housekeeping run and a warm cache. |
| ASG-05 | Same for a direct grant and a direct deny; an expired deny stops denying. |
| ASG-06 | `expiresAt` in the past at assignment time ⇒ `VALIDATION_FAILED`. |
| ASG-07 | `multiRole = false`: second assignment in same scope ⇒ `CONFLICT`. |
| ASG-08 | [implementation without scopes] non-null `scope` ⇒ `VALIDATION_FAILED`, nothing stored. |
| ASG-09 | 50 concurrent identical assignments ⇒ exactly one `created`, 49 `unchanged`, one audit event. |
| ASG-10 | Caller-supplied `grantedBy` is rejected or ignored; stored value equals the actor. |
| ASG-11 | [feature: directGrants] Direct allow grants exactly the named permission; removal revokes; `reason` is mandatory (`VALIDATION_FAILED` otherwise). |
| ASG-12 | [feature: directGrants unclaimed] Direct grant API ⇒ rejected; stored direct grants ignored and reported. |
| ASG-13 | Pagination of `listSubjectsByRole` is stable and complete under concurrent inserts (no duplicates, no skips of pre-existing items). |

### 5.7 ESC — privilege-escalation attempts

| ID | Scenario |
|---|---|
| ESC-01 | `bob` (no `role:assign`) assigns `viewer` to `carol` ⇒ `FORBIDDEN`; `authz.denied` audited. |
| ESC-02 | An actor holding `role:assign` assigns any role to **self** ⇒ `ESCALATION_DENIED` (`self_assign`). |
| ESC-03 | Actor with `role:assign` and effective grants ⊂ `admin` assigns `admin` to another ⇒ `ESCALATION_DENIED` (`grant_ceiling`). |
| ESC-04 | Same actor assigns a role whose permissions are all within their own grants ⇒ success. |
| ESC-05 | Assigning a `superuser` role by a non-superuser ⇒ `ESCALATION_DENIED`. |
| ESC-06 | **Race:** actor A (holding `role:assign` via role X) concurrently assigns role Y to T while another actor revokes X from A (or A's ceiling shrinks). Over ≥ 200 schedules the end state never contains an assignment that A could not have made at the linearization point. |
| ESC-07 | Registration/update payloads containing `roles`, `status`, `id`, `securityVersion`, `version`, `tenantId`, or nested equivalents in `metadata` ⇒ `VALIDATION_FAILED` (or provably ignored) and **no** such state set. |
| ESC-08 | Audit actor/`grantedBy` always equals the authenticated actor; forging via input fields is impossible. |
| ESC-09 | Last-superuser protection: unassign, expiry-set, disable, or delete that would leave 0 active superusers ⇒ `ESCALATION_DENIED` (`last_superuser`); with 2 holders, removing one succeeds. |
| ESC-10 | Actor bound to tenant T1 assigning a role to a subject in T2, or creating a scope outside T1 ⇒ `ESCALATION_DENIED` (`tenant_boundary`). |
| ESC-11 | [feature: dynamicRoles] Creating a role with permissions not covered by the creator ⇒ rejected; creating `superuser` dynamic role ⇒ rejected; shadowing a catalog role name ⇒ `CONFLICT`. |
| ESC-12 | A correctly signed access token carrying extra claims (`roles:["admin"]`, `perms:["*:*"]`, `role`, `scope`) does not alter any decision or the Principal's attributes. |
| ESC-13 | Cross-tenant: tenant admin of T1 attempts `revokeSession`/`setStatus`/`assign` on T2 user ⇒ denied by wall (`NOT_FOUND`/`FORBIDDEN` per spec), no change. |

### 5.8 CAT — catalog

| ID | Scenario |
|---|---|
| CAT-01 | A catalog with a cycle, an unknown inherited role, an undefined permission, and a partial wildcard ⇒ `CONFIG_INVALID` listing **all four** violations with paths. |
| CAT-02 | Mutating the original configuration objects after construction has no effect on decisions (immutability). |
| CAT-03 | A catalog swap during 1 000 concurrent evaluations: each Decision is consistent with exactly one of the two versions (never a mixture). |
| CAT-04 | `catalogVersion` is identical for reordered-equal catalogs and different after any semantic change. |
| CAT-05 | Hierarchy depth > configured maximum ⇒ `CONFIG_INVALID`; depth = maximum accepted. |
| CAT-06 | Wildcard grant containing no registered permission ⇒ `CONFIG_INVALID` (`unmatched_pattern`). |
| CAT-07 | A new permission added to the registry is **not** granted to existing roles that hold only concrete grants; for roles holding `project:*` it is granted iff the new permission's resource is `project`, evaluated at catalog build time. |
| CAT-08 | `*:*` in a non-`superuser` role ⇒ `CONFIG_INVALID`. |

### 5.9 TEN — scoped assignments and tenancy

| ID | Scenario |
|---|---|
| TEN-01 | [feature: scopes] Assignment scoped to `{tenant:T1}` allows decisions with σ ∋ T1 and denies with σ = {T2}. |
| TEN-02 | A scoped assignment never applies when σ is empty. |
| TEN-03 | A global assignment applies for every σ. |
| TEN-04 | Scope context passed through request metadata/options is ignored or rejected; σ derives only from `Subject.tenantId` and the loaded resource. |
| TEN-05 | Cached effective permissions for `(subject, σ1)` never serve `(subject, σ2)`. |

### 5.10 MID — permission changes mid-session

| ID | Scenario |
|---|---|
| MID-01 | `dave` logs in; `authorize(dave, "read", post)` ⇒ deny. Assign `viewer` to `dave`. Without logging in again and with the **same** access token and session: next `authorize` ⇒ allow. |
| MID-02 | `carol` has a valid unexpired access token and session. Revoke `viewer`. Immediately (single process): `authorize` ⇒ deny, although the token is valid. |
| MID-03 | Two-instance mode, no invalidation channel: instance B has cached carol's permissions. Revoke on instance A. On B: decisions follow the cache until `subjectTtl` elapses (clock advanced), then deny; the bound is not exceeded by more than 1 ms of scheduling. With the invalidation channel: B denies as soon as the message is delivered. |
| MID-04 | Assignment expiring at `T`: decision flips at `T` with the cache warm and no cleanup (cache entries expire no later than the earliest `expiresAt`). |
| MID-05 | Adding a deny to a role mid-session takes effect on the next decision. |
| MID-06 | A permission change neither invalidates the access token, nor changes the session, nor increments `securityVersion`; `resolve` still returns the same Principal. |
| MID-07 | Demoting a user (revoke admin, assign viewer) in the middle of 100 concurrent requests: every request that starts after the mutation returned observes the new permissions. |

---

## 6. Authentication groups (P-AUTHN)

### 6.1 PRN — Principal and request resolution

| ID | Scenario |
|---|---|
| PRN-01 | Principal after login has `id`, `type`, `authMethod`, `authenticatedAt` (= session creation), `sessionId`, `amr` (e.g. `["pwd"]`); `toSubject` drops auth-specific fields. |
| PRN-02 | Serialized Principal (JSON/string/log) contains none of: password, hash, access/refresh/session token, key material. |
| PRN-03 | Principal is immutable: attempts to modify any field (including nested `attributes`) do not alter other holders' view. |
| PRN-04 | `resolve` returns `null` (no error) for: no credential, malformed, bad signature, expired, revoked session, expired session, deleted user, `canLogin=false`, `sv` mismatch. |
| PRN-05 | `resolve` raises `STORAGE_UNAVAILABLE` (never `null`, never a Principal) when the session store, user store, or attribute provider is unavailable. |
| PRN-06 | `amr`, `authMethod`, `authenticatedAt` come from the session: a request carrying forged equivalents (header/claim) has no effect. |
| PRN-07 | After a refresh, `authenticatedAt` and `amr` are unchanged. |
| PRN-08 | `tenantId` taken from request input is ignored; the Principal's tenant is the identity layer's. |
| PRN-09 | A `restricted` state yields a Principal whose `attributes.accountRestricted` is `true`. |
| PRN-10 | Principal not cached across requests: after the user is suspended and sessions revoked, the next `resolve` returns `null`. |

### 6.2 ID / CRED / STATE — identity, credentials, account state

| ID | Scenario |
|---|---|
| ID-01 | `Alice@Example.COM`, ` alice@example.com `, and the full-width-form equivalent normalize to the same identifier; registration of the second ⇒ conflict/accepted-uniform; login with any form works. |
| ID-02 | 50 concurrent registrations with the same normalized email ⇒ exactly one user; all others receive the uniform result (default) or `CONFLICT`; no orphan user/identifier/credential rows. |
| ID-03 | Username grammar: `ab` rejected; `a_b.c-d1` accepted; uppercase normalized; leading `_` rejected; 65 chars rejected. |
| ID-04 | Email invalid forms (no `@`, two `@`, empty local/domain, 321 chars) ⇒ `VALIDATION_FAILED`; no provider-specific rewriting (`a.b+tag@x` stays distinct from `ab@x`). |
| ID-05 | After deleting a user, an `IdGenerator` stub that returns the deleted id is not accepted for a new user (no reuse); deletion cascades to identifiers, credentials, sessions, tokens, assignments. |
| CRED-01 | Hashing the same password twice yields different encoded values; parameters not weaker than `principal.md` §5.1.3; salt ≥ 128 bits. |
| CRED-02 | `verify` on malformed/empty/truncated encoded hash returns false (no throw). |
| CRED-03 | Hash stored with weaker parameters ⇒ `needsRehash`; after successful login the stored hash is upgraded; failed login does not rehash. |
| CRED-04 | Password length is counted in Unicode scalars: 12 emoji accepted at min 12; 11 rejected; 1024 accepted; 1025 rejected at set time; at login 1025 ⇒ `INVALID_CREDENTIALS` with **no hasher call**. |
| CRED-05 | NUL in password rejected at set; at login ⇒ `INVALID_CREDENTIALS`. NFKC-equivalent passwords verify equal. |
| CRED-06 | [pepper configured] Hashes verify with pepper v1 and v2 during rotation; hashes stored contain no pepper; omitting the pepper at verify ⇒ mismatch. |
| CRED-07 | Configured minimum below 8 ⇒ `CONFIG_INVALID`. Default composition rules absent (`aaaaaaaaaaaa` accepted unless denylisted). |
| CRED-08 | [BreachChecker] breached ⇒ `VALIDATION_FAILED`; checker `Unavailable` ⇒ password accepted unless `breachCheckFailMode = closed`; checker never receives full hash/plaintext over a network port (checked via instrumentation contract). |
| STATE-01 | Every transition in the default table succeeds; every non-listed transition ⇒ `STATE_TRANSITION_INVALID`. |
| STATE-02 | `setStatus` with stale `expectedVersion` ⇒ `PRECONDITION_FAILED`, no change. Retrying a successful call with the same version ⇒ `PRECONDITION_FAILED`. |
| STATE-03 | `active → suspended`: in the same atomic step all sessions revoked, all families revoked, `securityVersion` +1. Fault-inject failure after status write ⇒ everything rolled back (status unchanged). |
| STATE-04 | `suspended → active` does not restore any session; login required. |
| STATE-05 | State-machine config violations (no `canLogin` state, `canLogin=false` without `revokeSessionsOnEnter`, unknown transition endpoint) ⇒ `CONFIG_INVALID`. |
| STATE-06 | Custom state (`pending_approval`, `canLogin=false`) behaves like `suspended` for login (`ACCOUNT_RESTRICTED`) and refresh. |

### 6.3 AUTH — login

| ID | Scenario |
|---|---|
| AUTH-01 | Valid email+password ⇒ `Authenticated` with credentials; exactly one active session; audit `login.succeeded` + `session.created`. |
| AUTH-02 | Login by username and by email both work when both configured; case/Unicode variants accepted. |
| AUTH-03 | Wrong password ⇒ `INVALID_CREDENTIALS`; no session created; audit `login.failed`. |
| AUTH-04 | Per default state: `unverified` (restricted=true) logs in; `active` logs in; `suspended`/`disabled` with correct password ⇒ `ACCOUNT_RESTRICTED`. |
| AUTH-05 | Second login creates a **different** session; both active; each credential independent; revoking one leaves the other working. |
| AUTH-06 | Login while presenting an existing valid session/refresh token ignores it and creates a brand-new session and credentials. |
| AUTH-07 | 1025-char password ⇒ `INVALID_CREDENTIALS`, no hasher operation of any kind is invoked, throttle counters are incremented. |
| AUTH-08 | [reserved MFA] A strategy requiring a second factor returns `MfaChallenge`; zero sessions and zero credentials exist until verification. |
| AUTH-09 | Credential issue failure after session creation (fault-inject transport) ⇒ error returned and the session is revoked (no usable half-session). |
| AUTH-10 | Attribute provider failure at step 12 ⇒ error and the new session is revoked. |
| AUTH-11 | State changed to `suspended` between password verify and session creation (fault-inject interleaving) ⇒ `ACCOUNT_RESTRICTED`; no session exists. |
| AUTH-12 | Rehash failure (store error on `put`) does not fail the login. |
| AUTH-SEC-01 | Scan every captured log line, audit event, error value, and store write for the test password, its NFKC form, and the stored hash: not found outside the hash column of `CredentialStore`. |
| AUTH-SEC-02 | Login responses and errors never contain hashes, salts, or credential payload. |
| AUTH-SEC-03 | `Notifier` latency of 5 s does not delay any login/registration/reset response (async, not awaited). |
| AUTH-SEC-04 | Concurrent logins up to the session limit never produce duplicate session ids or tokens (10⁴ draws unique). |
| AUTH-SEC-05 | Session-fixation: pre-login anonymous token/cookie value X; after login the active session id/credential ≠ X and X is not valid. |

### 6.4 AUTH-ENUM / AUTH-TIM / AUTH-THR / AUTH-DOS — enumeration, timing, throttling

| ID | Scenario |
|---|---|
| AUTH-ENUM-01 | Unknown identifier vs known identifier + wrong password: identical error `code`, `message`, `details`, shape. |
| AUTH-ENUM-02 | Malformed identifier (e.g. `"%%%"`, 500 chars normalized-empty) vs unknown: identical. |
| AUTH-ENUM-03 | User without password credential vs wrong password: identical. |
| AUTH-ENUM-04 | Oversize password vs wrong password: identical code/message. |
| AUTH-ENUM-05 | Suspended account: wrong password ⇒ `INVALID_CREDENTIALS` (state not revealed); correct password ⇒ `ACCOUNT_RESTRICTED`. |
| AUTH-ENUM-06 | `requestPasswordReset` for (existing active, existing disabled, unverified, non-existing, malformed) ⇒ all `ResetRequestAccepted` with identical content; only the existing/permitted account receives a notifier call. |
| AUTH-ENUM-07 | Registration with an existing email (default config) returns the same `RegistrationAccepted` as a fresh email, contains no user id/token; owner receives a "registration attempt" notice; with `enumerationSafeRegistration=false` ⇒ `CONFLICT` and `config.warning` at start-up. |
| AUTH-ENUM-08 | `logout` with valid, expired, revoked, unknown, malformed credential ⇒ identical success result. |
| AUTH-ENUM-09 | `revealRestrictedState = false`: correct password on suspended account ⇒ `INVALID_CREDENTIALS`. |
| AUTH-TIM-01 | Instrumented hasher: for each of {known+correct, known+wrong, unknown, no credential, malformed identifier}, exactly **one** of `verify`/`dummyVerify` is invoked per attempt (except oversize password: zero). Deterministic. |
| AUTH-TIM-02 | [SHOULD] Statistical: with ≥ 200 samples each, the median latency of unknown vs known-wrong paths differs by ≤ 20 % (hash cost dominates). Reported, never flaky-failing the claim. |
| AUTH-THR-01 | After the identifier is blocked, a login with the **correct** password returns `RATE_LIMITED`; instrumentation shows zero store lookups and zero hasher calls. |
| AUTH-THR-02 | Failed attempts against **unknown** identifiers call `recordFailure` on `K_id`, `K_ip`, `K_g` exactly as for known ones. |
| AUTH-THR-03 | Sequences of N failures against an existing and a non-existing identifier produce identical limiter state and identical `retryAfter` progression. |
| AUTH-THR-04 | Success resets `K_id` only; `K_ip` and `K_g` counters are unchanged. |
| AUTH-THR-05 | Default config: after exceeding the threshold the block **expires** per the backoff schedule using the fake clock; no permanent lock; a victim's own correct login succeeds after expiry. |
| AUTH-THR-06 | Limiter unavailable: `throttleFailMode=open-with-alert` ⇒ login proceeds and `security.throttle_unavailable` audited; `closed` ⇒ `RATE_LIMITED`. |
| AUTH-THR-07 | A hundred different identifiers from one IP trip `K_ip` independent of per-identifier counts. |
| AUTH-DOS-01 | 1 000 parallel logins with the hasher limit L: observed simultaneous hasher invocations ≤ L; excess queue or fail with infrastructure error; memory bounded. |

### 6.5 REG / VER / RST / CHG — registration, verification, reset, change

| ID | Scenario |
|---|---|
| REG-01 | Registration creates user, identifier, and credential atomically; fault between them ⇒ none exist. |
| REG-02 | Weak password / bad metadata / forbidden field ⇒ `VALIDATION_FAILED`; nothing created; hash cost still paid on existence path (instrumented). |
| REG-03 | Initial state per verification config (`unverified` when email verification `required`/`optional`, `active` when `off`). |
| REG-04 | Default role assignment at registration is applied by `system`, from config only. |
| VER-01 | Valid verification token marks the identifier verified and transitions `unverified → active`; second use ⇒ `TOKEN_INVALID`. |
| VER-02 | Token for `password_reset` presented to `verifyEmail` ⇒ `TOKEN_INVALID`. |
| VER-03 | Changing email: new identifier unverified, login identifier unchanged until verified; notices sent to old and new addresses. |
| RST-01 | Reset request ⇒ notifier receives a token (≥ 256 bits); the API response contains no token; token digest, not token, stored. |
| RST-02 | Completing reset with a valid token: password changed, **all** sessions and families revoked, `securityVersion` +1, no session/credentials issued, notice sent, audit emitted. |
| RST-03 | Reset token second use ⇒ `TOKEN_INVALID`; expired (boundary) ⇒ `TOKEN_INVALID`. |
| RST-04 | New request invalidates earlier outstanding reset tokens. |
| RST-05 | Invalid new password (policy) rejects **without** consuming the token; the token still works with a valid password. |
| RST-06 | Fault injection after token consumption but before commit ⇒ rolled back; token still valid (A-FULL) or recoverable by re-request (A-LITE). |
| RST-07 | Reset for a `suspended` account succeeds in changing the password but does not change state or log in. |
| CHG-01 | Change password requires correct current password; wrong ⇒ `INVALID_CREDENTIALS` and counts toward throttle. |
| CHG-02 | Success revokes all other sessions, bumps `securityVersion`, keeps the current session only with credentials carrying the new `sv` (or issues a new session). |
| CHG-03 | New password equal to current ⇒ `VALIDATION_FAILED`. |
| CHG-04 | `revokeCurrentOnPasswordChange=true` revokes the current session too. |

### 6.6 SESS — sessions

| ID | Scenario |
|---|---|
| SESS-01 | Each login yields a fresh, unique session id; ids unpredictable (≥ 122 bits when bearer-derivable). |
| SESS-02 | `listActive` returns `id, createdAt, lastSeenAt, device, authMethod, current` only; no token/hash; `current` true for exactly the caller's session. |
| SESS-03 | `idleExpiresAt` never exceeds `absoluteExpiresAt` (touch near the end clamps). |
| SESS-04 | After many touches/refreshes, `absoluteExpiresAt` is unchanged; at that instant the session is `expired` and unusable. |
| SESS-05 | `touch` on a revoked session returns false and changes nothing; no operation reactivates a revoked session. |
| SESS-06 | After the session record is deleted (housekeeping), the formerly valid credential ⇒ `TOKEN_INVALID`/`null` Principal. |
| SESS-07 | Limit = 3, `evict-oldest`: 4th login revokes the oldest session (reason `evicted`) **and** its refresh tokens atomically; the oldest's refresh ⇒ `TOKEN_INVALID`; ties broken by id. |
| SESS-08 | Limit = 3, `reject`: 4th login ⇒ `SESSION_LIMIT_REACHED`; no state change; no credentials. |
| SESS-09 | Idle expiry by clock advance ⇒ `null` Principal / refresh fail, without any housekeeping job running. |
| SESS-10 | `revokeSession` for another user's session id by an unauthorized caller ⇒ `NOT_FOUND`, identical to an unknown id (message, timing class, audit absent of existence). |
| SESS-11 | Touch throttling: requests within `touchInterval` do not write; after it they do; interval > idleTtl/4 ⇒ `CONFIG_INVALID`. |
| SESS-12 | Concurrent revoke with different reasons: first reason wins; one audit event. |
| SESS-13 | `unlimited` must be explicit; omitting `max` yields finite default 10. |

### 6.7 TOK — tokens

| ID | Scenario |
|---|---|
| TOK-ACC-01 | Valid access token verifies; claims equal issue input. |
| TOK-ACC-02 | `exp` boundary: valid at `exp−1 ms` (leeway 0); invalid at `exp`; with leeway L valid until `exp+L`; L > 60 s ⇒ `CONFIG_INVALID`. |
| TOK-ACC-03 | `nbf` in the future ⇒ failure `not_yet_valid` (beyond leeway). |
| TOK-ACC-04 | Altering any byte of header, payload or signature ⇒ failure; verification occurs before claims trusted (instrument: no store lookup occurs for a tampered token). |
| TOK-ACC-05 | [JWT] `alg: none` and empty signature ⇒ failure. |
| TOK-ACC-06 | [JWT] Algorithm confusion: token MAC'd with the public key as HMAC secret when an asymmetric algorithm is configured ⇒ failure. |
| TOK-ACC-07 | Unknown `kid` ⇒ `unknown_key`; no outbound network I/O performed (instrumented). |
| TOK-ACC-08 | Wrong `iss` ⇒ failure. |
| TOK-ACC-09 | Missing or wrong `aud` ⇒ failure; verifier configured without audience ⇒ `CONFIG_INVALID`. |
| TOK-ACC-10 | A refresh token / one-time token / session token presented as an access token ⇒ failure `wrong_type` or `malformed`; and the reverse. |
| TOK-ACC-11 | Malformed battery (each input ⇒ failure, **no exception**, completes ≤ 50 ms): empty; 8 KiB+1; 1 MiB; non-UTF-8; wrong segment counts (0,1,2,4,100); invalid base64; non-JSON; JSON arrays/scalars; deeply nested JSON (10 000); duplicate security claims; `exp` as string/float/NaN/huge/negative; NUL bytes; whitespace-padded; null `sub`. |
| TOK-ACC-12 | Issued token contains no roles/permissions/email/name claims; contains `iss aud sub sid iat exp jti sv typ`. |
| TOK-ACC-13 | TTL > 60 min without override ⇒ `CONFIG_INVALID`; with override ⇒ starts and emits `config.warning`. |
| TOK-ACC-14 | [JWT] Headers with `crit`, `jwk`, `jku`, `x5u`, `x5c`, `zip` ⇒ failure. |
| TOK-ACC-15 | Key rotation: tokens signed by the previous key verify during overlap, fail after the old key is removed; new tokens use the new `kid`; no valid unexpired token fails during the documented procedure. |
| TOK-ACC-16 | Every `resolve` of a correctly signed, unexpired token performs the revocation check of `tokens.md` §2.5 against the authoritative store (instrumented: ≥ 1 session read and ≥ 1 user read); none is answered from a cache. |
| TOK-REF-01 | Refresh token ≥ 256 bits; 10⁵ issued tokens are unique; encoding length consistent. |
| TOK-REF-02 | Dump of all stored bytes (all stores, audit, logs) never contains a raw refresh/session/one-time token; only digests. |
| TOK-REF-03 | No API returns a raw token after issuance (session listing, refresh-record reads, audit). |
| TOK-REF-04 | A refresh token presented where an access token is expected, and a session token as refresh token ⇒ failure. |
| TOK-REF-05 | Refresh tokens are opaque: two tokens for the same user share no structure; digest lookup is the only validation path. |
| OTT-01 | One-time token is consumable once; replay ⇒ `TOKEN_INVALID`. |
| OTT-02 | Purpose binding: `email_verify` token for `password_reset` ⇒ fail, and the token remains consumable for its own purpose (failed wrong-purpose attempt does not consume). |
| OTT-03 | Expiry boundary at `expiresAt` (invalid at the instant) and TTL caps (`password_reset` ≤ 60 min without override). |
| OTT-04 | 100 concurrent consumers ⇒ exactly one success. |
| OTT-05 | Issuing a new token invalidates previous unconsumed tokens of same `(user, purpose, target)`. |
| OTT-06 | Request operations never return the raw token to the caller. |
| SES-OPQ-01 | Opaque-session transport: each request consults store/cache (`cacheTtl ≤ 5 s`); revocation visible within the bound. |
| SES-OPQ-02 | New token on every login; old pre-login value invalid. |
| SES-OPQ-03 | Token digest only in the store; token ≥ 256 bits. |

### 6.8 REF — refresh rotation

| ID | Scenario |
|---|---|
| REF-01 | Chain of 5 refreshes: each returns a new access+refresh pair; session id constant; `authenticatedAt` unchanged. |
| REF-02 | After a refresh, presenting the previous refresh token ⇒ `TOKEN_INVALID` (reuse path, REF-04). |
| REF-03 | **Concurrent presentation:** 50 simultaneous refreshes with the same active token: exactly one returns credentials; 49 return `TOKEN_INVALID`; (grace 0) the family and session end up revoked; exactly one `refresh.reuse_detected` event is **not** required but ≥ 1 is. Repeat ≥ 200 schedules. |
| REF-04 | **Token reuse:** refresh with T1 (success ⇒ T2). Present T1 again ⇒ `TOKEN_INVALID`; **session revoked and family revoked**; audit `refresh.reuse_detected` severity high with session/user/token ids (no token value). |
| REF-05 | Continuing REF-04: the legitimate T2 now ⇒ `TOKEN_INVALID`; access tokens previously issued are rejected on their next use. |
| REF-06 | Refresh token past its `expiresAt` ⇒ `TOKEN_EXPIRED`; session not reactivated. |
| REF-07 | Repeated refreshes up to `absoluteExpiresAt`: the last successful successor's `expiresAt` is clamped; after the absolute instant ⇒ `TOKEN_EXPIRED`/`TOKEN_INVALID`; no way to continue. |
| REF-08 | State with `canRefresh=false` (restricted) ⇒ `ACCOUNT_RESTRICTED`; session revoked; `suspended` ⇒ sessions already revoked ⇒ `TOKEN_INVALID`. |
| REF-09 | **Revoked session:** revoke the session; present its (still active) refresh token ⇒ `TOKEN_INVALID`; no new token minted. |
| REF-10 | `sv` mismatch between user and session ⇒ session revoked, `TOKEN_INVALID`, audit high. |
| REF-11 | Successor `expiresAt = min(now + idleTtl, absoluteExpiresAt)`. |
| REF-12 | New access token carries current `securityVersion`; Principal attributes equal login-time `authMethod/amr`. |
| REF-13 | **Crash safety:** crash after `consume` before `rotate` ⇒ no credentials returned; after restart the old token ⇒ `TOKEN_INVALID` (reuse) and a fresh login works; no safety violation. |
| REF-14 | [feature: reuseGrace] Replay of a used token within the grace window yields a **new** successor and the former successor becomes `revoked(superseded)`; presenting the superseded one ⇒ `TOKEN_INVALID` **without** family revocation (audit `refresh.superseded_presented`). |
| REF-15 | [feature: reuseGrace] Token `used` with no successor yet within grace ⇒ `TOKEN_INVALID` flagged retryable, no revocation; beyond grace ⇒ revocation. |
| REF-16 | [feature: reuseGrace] Replay after the grace window ⇒ family and session revoked. If the former successor was already used (chain advanced) ⇒ treated as reuse even within grace. |
| REF-17 | Responses for reuse, unknown, revoked and malformed tokens are byte-identical. |
| REF-18 | An access token or session token supplied as `refreshToken` ⇒ `TOKEN_INVALID`. |
| REF-19 | Over-long/empty/non-string input ⇒ `TOKEN_INVALID` with **zero** store calls. |
| REF-20 | Refresh does not create sessions: session count and ids unchanged. |
| REF-21 | Lost-acknowledgement fault: refresh committed server-side but response lost; client retries with old token ⇒ reuse path (grace 0) ⇒ family revoked ⇒ client must re-login. Verifies documented behavior. |
| REF-22 | Refresh when `Notifier` or `AuditSink` is down still works (audit failures logged only). |

### 6.9 REV — revocation and logout

| ID | Scenario |
|---|---|
| REV-01 | Logout with Principal: session revoked (`logout`), refresh tokens revoked, `session.revoked` + `logout` audited once. |
| REV-02 | **Atomicity:** fault injection at every step boundary of `terminate`: after any failure, either the session and all its refresh tokens are revoked, or none is; never session-revoked/token-active. |
| REV-03 | `logoutAll(except=current)`: all other sessions revoked, current alive; returns the count; second call returns 0, success. |
| REV-04 | **Revoked session:** after revoke returns, refresh with any token of that session fails **immediately** even with a warm cache and a second instance. |
| REV-05 | Revoking twice ⇒ second succeeds, no field changes, no second audit event. |
| REV-06 | A revoked session cannot be revived by: refresh, touch, login with its old credential, state change back to `active`, retry of the revoking call, housekeeping. |
| REV-07 | Logout by presenting an expired or already-used refresh token revokes the session; by an unknown token ⇒ success without effect. |
| REV-08 | Logout with malformed input never throws and returns success. |
| REV-09 | Remote revoke: owner may revoke own other session; non-owner without permission ⇒ `NOT_FOUND`; admin with `session:revoke` in the same tenant ⇒ success; admin of another tenant ⇒ denied by wall. |
| REV-10 | The first request after revocation returns bearing a still-unexpired access token of the revoked session ⇒ `null` (no cache window). |
| REV-11 | A configuration requesting `eventual` (or any non-`strict`) revocation ⇒ `CONFIG_INVALID` at construction; `describe()` reports `revocation: "strict"`. |
| REV-12 | Password change/reset ⇒ sessions revoked per `login.md`, `securityVersion` bumped; tokens of the user rejected thereafter. |
| REV-13 | Storage failure during logout ⇒ `STORAGE_UNAVAILABLE` (never success); retry succeeds; no partial state. |
| REV-14 | `invalidateCredentials` bumps `securityVersion`, revokes all sessions, requires authorization; unauthorized ⇒ `FORBIDDEN`. |
| REV-15 | `revokeEverything` is resumable: interrupted halfway, rerun completes; reports `partial` until done; emits `high` audit. |
| REV-16 | Denylist (if configured) cannot un-revoke: removing a denylist entry leaves the session revoked. |

### 6.10 RACE — concurrency

| ID | Scenario |
|---|---|
| RACE-01 | 50 parallel registrations of one identifier (see ID-02). |
| RACE-02 | 50 parallel refreshes of one token (see REF-03). |
| RACE-03 | **Refresh vs revoke:** parallel `refresh(T)` and `revokeSession(s)`. Over all schedules: after the revoke returns, no refresh succeeds; no `active` refresh token remains for the session; if the refresh won, its tokens are revoked by the end. |
| RACE-04 | 100 parallel `resetPassword` with one token ⇒ exactly one `PasswordResetCompleted`. |
| RACE-05 | Parallel revoke/revoke/refresh/logoutAll on one session ⇒ terminal state consistent (INV-TOK-05), exactly one `session.revoked`. |
| RACE-06 | 100 parallel logins for a user with limit 3 ⇒ afterward exactly 3 `active` sessions (evict) or ≤ 3 successes (reject); no refresh token of an evicted session is active. |
| RACE-07 | Parallel logins vs `setStatus(suspended)`: after both complete, the user has **zero** active sessions and zero active refresh tokens; no `Authenticated` result is accompanied by a surviving session. |
| RACE-08 | Parallel `assign`/`unassign`/ceiling changes/last-superuser removal (see ESC-06, ESC-09): invariants hold at every schedule. |
| RACE-09 | 1 000 parallel `bumpSecurityVersion` ⇒ final value = initial + 1 000. |
| RACE-10 | Parallel refresh vs `setStatus(canRefresh=false)`: after both complete, no usable token. |
| RACE-11 | Parallel `changePassword` with two different new passwords ⇒ exactly one final credential; `securityVersion` incremented twice; sessions revoked. |
| RACE-12 | Parallel catalog swap and authorization (see CAT-03). |

### 6.11 TIME

| ID | Scenario |
|---|---|
| TIME-01 | Expiry boundaries for access token, refresh token, session idle/absolute, one-time token, assignment, direct grant, throttle block: valid at `t−1 ms`, invalid at `t`. |
| TIME-02 | Setting the fake clock to year 2100 or 1970 changes all computed expiries relative to the injected time; no value derived from the real clock appears. |
| TIME-03 | Backward clock jump after an expiry was observed does not make the expired token/session valid again in the same process. |
| TIME-04 | Time-based policies depend only on the UTC instant (varying host timezone and DST has no effect). |
| TIME-05 | Leeway never exceeds 60 s; skew within leeway tolerated, beyond rejected. |

---

## 7. Cross-cutting groups

### 7.1 AUD — audit

| ID | Scenario |
|---|---|
| AUD-01 | Table-driven: each operation of `storage/interfaces.md` §10.3 emits its event type, with required fields (`at`, `severity`, `actor`, `target`, `outcome`, `reason`), exactly once per effect. |
| AUD-02 | Exactly-once under retries/idempotent calls (revocation, assignment, logout). |
| AUD-03 | Sentinel secrets (password, tokens, hashes, one-time tokens, pepper) never appear in any event. |
| AUD-04 | Signing/pepper key material never appears in events, logs, errors, `describe()`. |
| AUD-05 | Resource field values and attribute values never appear; only `resourceId`. |
| AUD-06 | The public API has no operation to modify/delete audit events (structural check). |
| AUD-07 | Sink failure: decisions unchanged; `auditFailureMode = fail-closed` converts a *sensitive allow* to deny `unavailable`. |
| AUD-08 | `login.failed` never records whether the identifier exists; identifier recorded only as keyed digest by default. |

### 7.2 ERR — errors

| ID | Scenario |
|---|---|
| ERR-01 | For each code in `errors.md` §2, the produced `message` equals the fixed text and contains no variable data. |
| ERR-02 | `cause` is not part of the serialized error; including driver text/SQL/paths in any externally visible field fails the test. |
| ERR-03 | An unexpected internal exception surfaces as `INTERNAL` with the fixed message; the cause is logged only. |
| ERR-04 | Every internal reason of `errors.md` §3 maps to the stated external code (table-driven). |
| ERR-05 | Error precedence of `errors.md` §6 is respected on requests violating multiple constraints (e.g. rate-limited + invalid password ⇒ `RATE_LIMITED`; over-long identifier + blocked ⇒ `VALIDATION_FAILED`). |
| ERR-06 | `CONFIG_INVALID` is raised only at construction, includes **all** violations, and no request-time path raises it. |

### 7.3 CFG — configuration

| ID | Scenario |
|---|---|
| CFG-01 | A config with N independent violations ⇒ one `CONFIG_INVALID` with N entries (paths + rule ids). |
| CFG-02 | Table-driven invalid fixtures — one per MUST in `permissions.md` §2–§3, `roles.md` §2–§4, `principal.md` §6, `tokens.md` §2.3/§6 — each ⇒ `CONFIG_INVALID`. |
| CFG-03 | Unclaimed feature inert: configuring/using hierarchy, deny, wildcards, directGrants, dynamicRoles, scopes while disabled ⇒ `CONFIG_INVALID` or rejection; stored data for them ignored and reported. |
| CFG-04 | Each insecure relaxation (INV-CFG-02 list) emits exactly one `config.warning` at start-up. |
| CFG-05 | Missing explicit `unlimited` ⇒ finite default; missing `max` ≠ unlimited. |
| CFG-06 | `describe()` output redacts all secrets (`[redacted]`), shows revocation mode, throttle fail mode, reuse grace, TTLs, features, catalog version. |
| CFG-07 | Configuration is immutable after construction (mutation attempts have no effect or fail). |
| CFG-08 | Weak/empty/placeholder signing key, no active key, duplicate `kid` ⇒ `CONFIG_INVALID`. |

### 7.4 X — cross-implementation

| ID | Scenario |
|---|---|
| X-SWAP-01 | Run PRN/AZ/MID scenarios once with the token transport and once with the opaque-session transport: every Decision and `permissionsFor` result is identical (INV-ARCH-01). |
| X-DIFF-01 | **Differential:** random sequences (≥ 10⁴ operations, seeded) applied to the system with the reference in-memory adapter and with the adapter under test produce identical external results and identical final store-observable state. |
| X-VEC-01 | All machine-readable vectors (§8) pass. |

---

## 8. Storage-adapter group (P-STORE-FULL / P-STORE-LITE)

Tests directly exercise the ports of `storage/interfaces.md`. Items marked **[A2]** need cross-record atomicity and are excluded from `P-STORE-LITE`.

| ID | Scenario |
|---|---|
| STO-USR-01 | `create` with existing id ⇒ `Conflict`; adapter ignores caller-supplied `version`/`securityVersion` (starts 0). |
| STO-USR-02 | 50 concurrent `setStatus(expectedVersion=v)` ⇒ exactly one succeeds; others `PreconditionFailed`. |
| STO-USR-03 | 1 000 concurrent `bumpSecurityVersion` ⇒ exact +1 000. |
| STO-USR-04 | Every mutation increments `version`; `updatedAt` updated. |
| STO-ID-01 | `add` + `findByNormalized` round-trip; display value preserved; `listByUser` correct. |
| STO-ID-02 | 50 concurrent `add` of one `(type, normalized)` ⇒ exactly one succeeds, others `Conflict`; `findByNormalized` returns exactly one. |
| STO-ID-03 | Over-length values ⇒ `Invalid`, never truncated; case-sensitive uniqueness (normalization is the caller's job). |
| STO-CRED-01 | Concurrent readers during `put` replacement never observe "no credential" nor two. |
| STO-CRED-02 | `get` returns payload byte-exact; no logging of payload by the adapter (tap). |
| STO-SES-01 | `createWithLimit` with 100 concurrent callers, limit 3 ⇒ exactly 3 active sessions (evict) / 3 successes (reject). |
| STO-SES-02 | `revoke` returns true once, then false; fields unchanged after the first. |
| STO-SES-03 | **[A2]** `revokeAllForUser` concurrent with `createWithLimit`: no session ends active that was created before the revoke began; refresh families revoked consistently. |
| STO-SES-04 | `touch` rejected for revoked sessions and for values that would shrink/exceed absolute bounds; unchanged. |
| STO-SES-05 | `get` returns revoked/expired records; `null` only for absent. |
| STO-SES-06 | `deleteTerminalBefore` deletes only terminal sessions older than the cutoff. |
| STO-SES-07 | `listActiveByUser` ordering stable (createdAt DESC, id DESC), paging complete without duplicates under concurrent inserts. |
| STO-RT-01 | N=100 concurrent `consume(h)` on an active token ⇒ exactly one `consumed`, 99 `reused`; across two processes/instances as well. |
| STO-RT-02 | `consume` precedence: unknown / revoked / used(`reused`) / active+expired(`expired`) / active(`consumed`) — table-driven, including used+expired ⇒ `reused`; state unchanged for all but `consumed`. |
| STO-RT-03 | `rotate` requires `used` and unset `successorId`; second `rotate` ⇒ `PreconditionFailed`; links `parentId`/`successorId`. |
| STO-RT-04 | `replaceActiveSuccessor`: atomically supersedes only an `active` successor; `not_active` otherwise; exactly one `active` record remains in the family. |
| STO-RT-05 | **[A2]** `rotate`/`insert`/`replaceActiveSuccessor` for a revoked session ⇒ `PreconditionFailed`; no record inserted. |
| STO-RT-06 | `revokeFamily` idempotent; counts changes; no-op returns 0. |
| STO-RT-07 | `deleteTerminalBefore` honors the retention rule (does not delete `used` records of live families inside the window). |
| STO-OTT-01 | `consume` succeeds once; failure cases (unknown, wrong purpose, expired, consumed) return `null` indistinguishably and change nothing. |
| STO-OTT-02 | `invalidate` affects only the stated `(user, purpose, target)`. |
| STO-ASG-01 | `assign` idempotent results (`created`/`unchanged`/`updated`); 50 concurrent identical ⇒ one `created`. |
| STO-ASG-02 | `listActive` excludes expired by `now` parameter in the query; cursor stable. |
| STO-ASG-03 | **[A2]** Serializable behavior for last-superuser counting: two concurrent removals of the two holders ⇒ exactly one succeeds (no write skew). |
| STO-CAT-01 | `sync` of the same catalog from 10 concurrent starters ⇒ no error, no duplicates; catalog role evaluation cannot be altered via the store. |
| STO-CONS-01 | Read-after-write: a write acknowledged to process A is visible to the very next primary read in process B for `consume`, session, user state, revocation. Replica-lag simulation never serves these reads. |
| STO-FAIL-01 | Timeout ⇒ `Unavailable`; no raw driver/SQL text in the error. |
| STO-FAIL-02 | Lost acknowledgement on a non-idempotent operation (`create`, `consume`): the core treats the flow as failed and issues no credentials (e.g. login with lost ack on session create ⇒ error, and any created session is not delivered/usable or is revoked on retry). |
| STO-FAIL-03 | Lost acknowledgement on idempotent operations (`revoke`, `assign`, `unassign`): the core's retry yields the same final state. |
| STO-FAIL-04 | Permanent unavailability of each store in turn: every flow fails closed (`STORAGE_UNAVAILABLE`, deny, or `null`-never) — table-driven; no flow returns success or `allow`. |
| STO-FAIL-05 | Adapter errors for `Conflict`, `PreconditionFailed`, `Invalid` are mapped to the specified failures, never leaked as generic exceptions. |
| STO-UOW-01 | **[A2]** Failure inside `fn` after several writes ⇒ no write persists; invisible to concurrent readers before commit. |
| STO-UOW-02 | **[A2]** Serializable isolation: classic write-skew scenarios (session limit, last superuser) do not occur. |
| STO-UOW-03 | **[A2]** Nested `run` joins the outer transaction; adapter retries `fn` on serialization conflict without duplicating external effects (side-effect counter stays 1). |
| STO-DATA-01 | Millisecond timestamp round-trip without loss; UTC preserved. |
| STO-DATA-02 | Secret fields (digests, hashes) absent from adapter logs/errors (tap). |
| STO-DATA-03 | `delete(user)` cascades per `interfaces.md` §2.6, atomically **[A2]**; id not reusable. |

---

## 9. Machine-readable vectors

To make the cases portable across implementation languages, the reference suite ships vectors under `spec/vectors/` (to be authored from this document). A vector file is JSON with the following shape; harnesses MUST treat vectors as authoritative inputs and results as normative.

```
{
  "id": "AZ-DENY-01",
  "spec": ["rbac/roles.md#6", "policy/policy.md#5"],
  "features": ["deny", "wildcards"],
  "given": {
    "catalog": { "permissions": [...], "roles": { "<name>": { "permissions": [...], "inherits": [...], "deny": [...] } } },
    "clock": "2030-01-01T00:00:00.000Z",
    "subjects": { "<alias>": { "id": "...", "type": "user", "tenantId": "...", "attributes": {...} } },
    "assignments": [ { "subject": "<alias>", "role": "...", "scope": null, "expiresAt": null } ],
    "policies": [ { "name": "...", "resource": "...", "mode": "...", "rules": [ { "action": "...", "expr": <declarative expression> } ] } ]
  },
  "steps": [
    { "do": "authorize", "subject": "<alias>", "action": "delete", "resource": { "type": "project", "...": "..." },
      "expect": { "effect": "deny", "reason": "rbac_explicit_deny" } },
    { "do": "advance", "ms": 60000 },
    { "do": "assign", "actor": "<alias>", "target": "<alias>", "role": "...", "expect": { "error": "ESCALATION_DENIED" } }
  ]
}
```

1. Policy rules in vectors are expressed in a small declarative expression language (a superset of the scope `Expr` of `policy/scope.md` §3 adding `subject.<path>`, `resource.<path>`, `now`, comparisons) so that every language can evaluate them identically. Implementations MUST provide a vector-loader that compiles these into native policies; the loader is test code and does not extend the specification.
2. Vectors cover at minimum: AZ, POL, SCP, ASG, ESC, CAT, TEN, MID, TIME, and the pure state-machine parts of REF/REV/SESS/STATE (store behaviors executed against the reference in-memory adapter).
3. A vector's `expect` MAY name `effect`, `reason`, `error` (code), `value`, `auditEvents` (type+count), or `state` (selected store-observable fields).

## 10. Reporting

A conformance report MUST list, per test ID: result (pass/fail/skipped-unclaimed), the feature tags, the random seed(s) and number of schedules for RACE tests, harness version and spec version. Any failure of a test annotated by an invariant (`invariants.md`) MUST be reported as a **violation of that invariant ID**. Skipped tests must correspond to an unclaimed feature or profile; an unexplained skip is a failure.

## 11. Traceability

Every MUST in the specification documents MUST be covered by at least one test case of this document. When adding a normative statement, the author MUST add or extend a test case in the same change; CI SHOULD check that each `INV-*` ID in `invariants.md` appears in this document and each test ID referenced by `invariants.md` is defined here.
