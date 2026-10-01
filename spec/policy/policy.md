# Aegis Spec — Policy System and Authorization Decision

Status: Draft 0.1 · Normative
Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** are as defined in RFC 2119 / RFC 8174 when in capitals.
RBAC semantics: `rbac/*`. List filtering: `policy/scope.md`.

## 1. Purpose

RBAC answers "may this subject perform this *kind* of action on this *kind* of resource?". A **policy** answers "may this subject perform this action on **this particular resource**, in this context?". The *authorization decision engine* combines both and yields a **Decision**.

## 2. Inputs

```
authorize(subject: Subject|Principal, action: String, resource: Resource, options?) -> Decision

Resource {                       // supplied by the host; opaque to the engine except as below
  type?       : Segment          // resource type, see §4.1
  ...fields   : Json             // arbitrary data the host's policies understand
}
```

1. The `Subject` MUST be projected per `principal.md` §2.2 first.
2. `resource` MAY be `null`/absent for type-level checks ("may this subject create projects at all?") by passing a type-only resource `{type: "project"}`, or the string form `authorize(subject, "create", "project")`, which is equivalent to the type-only resource. Policies MUST handle a type-only resource (fields absent) without error; rules that need fields MUST treat absence as non-match (⇒ deny).
3. The engine MUST NOT mutate `subject`, `resource`, or any option. Policy functions receive **read-only** views (deep-immutable or deep copies).

## 3. Decision

```
Decision {
  effect      : "allow" | "deny"
  permission  : String?                  derived permission (permissions.md §5), absent if derivation failed
  reason      : DecisionReason           REQUIRED
  matchedBy   : List<String>?            names of policies/rules that contributed
  trace       : List<TraceStep>?         only when explain = true
}
DecisionReason =
    "allowed"                        // all required stages allowed
  | "rbac_denied"                    // missing permission
  | "rbac_explicit_deny"             // matched deny
  | "policy_denied"
  | "policy_error"                   // policy threw / timed out / returned invalid value
  | "policy_missing"                 // strictPolicies and no policy applies
  | "invalid_permission" | "unknown_permission"
  | "unavailable"                    // infrastructure failure
  | "invalid_subject"
TraceStep { stage: "validate"|"rbac_deny"|"rbac_allow"|"wall"|"policy", name: String, effect: "allow"|"deny"|"skip", note: String? }
```

1. A Decision MUST always carry `effect` and `reason`. `allow` MUST carry reason `allowed`.
2. `reason` and `trace` are for developers/audit. A host MUST NOT expose them to end users by default; the core MUST NOT include secrets, resource field values, or attribute values in `reason`/`trace` text (names and stage results only).
3. `trace` MUST be produced only when requested (`explain = true`), because it can reveal policy structure.
4. Three verbs MUST be offered with identical decision semantics:
   * `authorize(...) -> Decision`
   * `can(...) -> Boolean` ≡ `authorize(...).effect == "allow"`
   * `assert(...)` — returns on allow, throws `FORBIDDEN` on deny.
   An implementation MUST NOT offer a verb that can return a different answer for identical inputs and state.

## 4. Policy definition

```
Policy {
  name      : String(1..64)                 REQUIRED, unique
  resource  : Segment | "*"                 REQUIRED   "*" = global wall (§6.2)
  mode      : Mode                          REQUIRED   default "rbacAndPolicy"; MUST be "rbacAndPolicy" when resource = "*"
  rules     : Map<ActionKey, RuleFn>        REQUIRED   ActionKey = Segment | "*"
  scope     : Map<ActionKey, ScopeFn>?      OPTIONAL   see scope.md
  timeoutMs : Integer 1..5000               OPTIONAL   default 50
}
Mode = "rbacAndPolicy" | "rbacOrPolicy" | "policyOnly" | "rbacOnly"

RuleFn(input: PolicyInput) -> PolicyResult | Future<PolicyResult>
PolicyInput {
  subject  : Subject                  read-only
  action   : Segment
  resource : Resource                 read-only
  ctx      : PolicyContext
}
PolicyContext {
  now      : Timestamp                from the injected Clock; MUST be the only source of time
  request  : Map<String,Json>?        host-supplied request metadata (e.g. ip); informational
  loaders  : Map<String, LoaderFn>?   explicitly registered, named data loaders (§4.3)
}
PolicyResult = Boolean | { effect: "allow" | "deny", reason?: String }
```

### 4.1 Resource type resolution

The `resourceType` used for permission derivation and policy lookup is determined, in order, by:
1. an explicit string argument (`authorize(s, a, "project")`),
2. `resource.type` if present,
3. a project-configured `resolveType(resource) -> Segment` function.

If none yields a valid Segment the decision MUST be `deny` (`invalid_permission`). The engine MUST NOT guess from object shape/class names unless that logic is the configured `resolveType`.

If both an explicit type and `resource.type` are present and differ, the decision MUST be `deny` (`invalid_permission`).

### 4.2 Registration validation (start-up)

1. `name` unique; `resource` is a valid Segment or `*`; every `ActionKey` is `*` or a Segment, and each concrete `ActionKey` is `action` of at least one registered permission for that resource (typo protection) — otherwise `CONFIG_INVALID`.
2. All policies registered for the same concrete `resource` MUST declare the same `mode`; a mismatch ⇒ `CONFIG_INVALID`.
3. `mode = "rbacOrPolicy"` MUST emit a lint warning `or_mode_policy`.
4. `policyOnly` and `rbacOnly` for resource types that appear in the permission registry SHOULD be reported by lint as `rbac_bypass` / `policy_bypass` info.

### 4.3 Purity and I/O

1. A rule MUST be a **deterministic function of its `PolicyInput`** (including `ctx.now` and values returned by `ctx.loaders`). It MUST NOT read ambient time, randomness, process state, or perform I/O on its own.
2. Data that is not on the subject or the resource MUST be obtained through a **named loader** declared in configuration (`loaders[name]`). Loader invocation is visible to the engine, counted in the trace, subject to the policy timeout, and cancellable. A loader failure ⇒ treated as a rule error (§5.5).
3. A rule MUST NOT cause side effects visible outside itself. The engine MAY invoke a rule more than once for one request (e.g. retries, consistency checks) and MAY skip it by short-circuit.

## 5. Evaluation order (normative)

For `authorize(subject, action, resource)`, the engine MUST perform stages in this order and MUST NOT reorder them in ways that change the result:

```
Stage 0  VALIDATE
   0.1  subject valid (principal.md §1)                    else deny invalid_subject
   0.2  resolve resourceType (§4.1)                         else deny invalid_permission
   0.3  derive permission p = type ":" action; validate     else deny invalid_permission / unknown_permission
Stage 1  RBAC DENY
   1.1  if deny feature enabled and ∃ d ∈ denies(subject, σ): matches(d, p)
        →  DENY (rbac_explicit_deny)                         [final; no later stage can override]
Stage 2  RBAC ALLOW
   2.1  rbacAllowed = allows(p)                              (roles.md §5, minus denies already handled)
Stage 3  WALL  (global policies with resource = "*")
   3.1  evaluate all global policies' rules for `action` and "*"; each is a *required* condition
   3.2  any deny/error → DENY (policy_denied / policy_error)  [final]
Stage 4  RESOURCE POLICY
   4.1  P = policies whose resource == resourceType
   4.2  if P = ∅  → policyApplicable = false
   4.3  else evaluate the rules for ActionKey=`action` and ActionKey="*" across all p ∈ P  (§5.2)
        policyAllowed = every evaluated rule returned allow
        (if P ≠ ∅ but no rule exists for `action` or "*": policyApplicable = false)
Stage 5  COMBINE  (mode of P; "rbacAndPolicy" if P = ∅)  → §6
Stage 6  EMIT  audit (§7) and return Decision
```

### 5.1 Ordering guarantees

1. Stage 1 (explicit RBAC deny) is evaluated **before and independently of** all policies and is final.
2. Stage 3 (walls) MUST NOT be bypassable by any `mode`, including `rbacOrPolicy` and `policyOnly`.
3. The engine MAY short-circuit: once a stage yields a final DENY, later stages MAY be skipped. If skipped, trace entries for them MUST be `skip`. Short-circuiting MUST NOT change the Decision effect.
4. The engine MAY evaluate independent rules concurrently; the result MUST NOT depend on completion order.

### 5.2 Rule aggregation within a stage

1. Within Stage 3 and Stage 4, *every applicable rule* is a required condition: effects combine with logical **AND**. A single `deny` (explicit `{effect:"deny"}` or `false`) makes the stage `deny`.
2. Applicable rules for an action are: the rule keyed by the concrete action (if any) **and** the rule keyed `*` (if any), for every policy of the stage.
3. When both rules exist both MUST allow. (`*` is a *constraint on all actions*, not a fallback.)

### 5.3 Result normalization

Each rule result MUST be normalized as follows. Any value not listed MUST be treated as an **invalid result** ⇒ error (§5.5):

| Returned | Normalized |
|---|---|
| `true` | allow |
| `false` | deny |
| `{effect:"allow"}` | allow |
| `{effect:"deny", reason?}` | deny |
| `null`, `undefined`, absent value, numbers, strings, `Promise` rejection, any other object | **invalid ⇒ deny, reason `policy_error`** |

Truthiness MUST NOT be used (a rule returning `1`, `"yes"`, or a non-empty object is invalid, not allow).

### 5.4 Asynchrony and timeouts

1. A rule MAY be asynchronous. The engine MUST await it.
2. If a rule does not complete within its `timeoutMs`, the stage result is `deny` with reason `policy_error`, and the in-flight work SHOULD be cancelled; a late result MUST be discarded and MUST NOT alter the Decision.

### 5.5 Failure handling (fail closed)

1. An exception, rejection, timeout, invalid result, or loader failure in any rule ⇒ that rule yields **deny** and the Decision has reason `policy_error`.
2. Such an event MUST be audited as `authz.policy_error` including policy name, rule key, error class (not message text containing resource data).
3. A failure in the RBAC data path (store/cache unavailable, §7 of `assignments.md`) ⇒ `deny` with reason `unavailable`.
4. The engine MUST NOT convert a failure into `allow` under any configuration, including `rbacOrPolicy`.

## 6. Combination of RBAC and policy (Stage 5)

Let `R = rbacAllowed` (after Stage 1 did not deny), `W = wall result` (Stage 3, already `allow` if this stage is reached), `Pa = policyApplicable`, `P = policyAllowed`.

### 6.1 Mode table

| Mode | Final effect (given Stage 1 and Stage 3 did not deny) | `Pa = false` (no policy rule applies) |
|---|---|---|
| `rbacAndPolicy` (default) | `allow` iff `R ∧ P` | `allow` iff `R` — unless `strictPolicies` (§6.4) |
| `rbacOrPolicy` | `allow` iff `R ∨ P` | `allow` iff `R` |
| `policyOnly` | `allow` iff `P` | **deny** (`policy_missing`) — a `policyOnly` resource with no applicable rule MUST deny |
| `rbacOnly` | `allow` iff `R` | `allow` iff `R` |

### 6.2 Global walls

Policies with `resource = "*"` are *walls*: they apply to **every** authorization request after Stage 1 and are always `rbacAndPolicy`. Typical use: tenant isolation (`resource.tenantId == subject.tenantId`). A wall that does not recognize the resource type (rule input lacks needed fields) MUST deny rather than allow, unless the wall rule is written to abstain by returning `true` explicitly.

### 6.3 Deny precedence summary

Precedence from strongest to weakest:

1. Stage 0 validation failures (deny).
2. Stage 1 RBAC explicit deny — **not overridable by any policy or mode**.
3. Stage 3 walls — not overridable by any mode.
4. Mode combination (Stage 5).

### 6.4 strictPolicies

When the project sets `strictPolicies = true`, a request whose `resourceType` has `Pa = false` (no resource policy rule applicable) MUST be denied with reason `policy_missing`, regardless of `R`. Default `false`.

### 6.5 Reason selection

When the final effect is `deny`, the Decision `reason` MUST be the reason of the **first** denying stage in the order Stage 0, 1, 3, then Stage 5 (`rbac_denied` if `¬R` and `Pa=false` or `mode ∈ {rbacAndPolicy, rbacOnly}` and `¬R`; `policy_denied` if `R ∧ ¬P` under `rbacAndPolicy`; for `rbacOrPolicy` where both fail, `rbac_denied`; `policy_missing` per §6.1/§6.4). Determinism of `reason` is required for test reproducibility.

## 7. Auditing of decisions

1. Every **deny** MUST emit `authz.denied` (reason, permission, subject id, resourceType, and `resourceId` if the resource carries an `id` field and the project permits; never other resource fields).
2. Allows MAY be audited by configuration (`auditAllows: "none" | "sampled" | "all"`, default `"none"`). Allows on permissions marked *sensitive* in the registry MUST be audited when `auditAllows ≠ "none"`.
3. Audit emission failure MUST NOT change the Decision, but MUST be reported through the `Logger` port; an implementation MAY be configured as `auditFailureMode = "fail-closed"`, in which case a failure to audit a *sensitive* allow converts it to deny with reason `unavailable`.

## 8. Determinism and consistency

1. For identical inputs, identical catalog version, identical stored RBAC state, identical loader results, and identical `ctx.now`, `authorize` MUST return identical `effect` and `reason` (INV-AUTHZ-03).
2. Decisions MUST NOT be cached across requests except via the RBAC caching rules (`assignments.md` §7). **Policy results MUST NOT be cached**, since they depend on resource state and time.
3. The engine MUST be **reentrant and thread/task-safe**; catalog, policies and compiled structures are immutable after construction.

## 9. Extensibility constraint

The policy engine is a replaceable port (`PolicyEngine`). A replacement (e.g. an external ABAC engine) MUST satisfy the entire §5–§8 contract and the conformance suite (`conformance.md` group `POL`); it MAY use any internal language. It MUST NOT be able to weaken Stage 0–1.
