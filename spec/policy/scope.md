# Aegis Spec — Authorization Scope (list/query authorization)

Status: Draft 0.1 · Normative
Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** are as defined in RFC 2119 / RFC 8174 when in capitals.
Decision semantics: `policy/policy.md`. (Not to be confused with *assignment scope* in `rbac/assignments.md` §3.)

## 1. Purpose

Per-resource checks (`authorize`) do not scale to listing, searching or counting. `authorizeScope` returns a **data-store-neutral constraint** describing exactly which resources of a type the subject may perform an action on. The host (or a storage adapter) applies it as a filter.

## 2. Operation

```
authorizeScope(subject: Subject|Principal, action: String, resourceType: Segment, options?) -> AuthScope

AuthScope =
    { kind: "all" }                              // every resource of the type
  | { kind: "none" }                             // no resource of the type
  | { kind: "constraint", expr: Expr }           // resources satisfying expr
  | { kind: "unsupported", reason: String }      // cannot be expressed; caller MUST NOT treat as allow
```

1. The operation MUST apply Stage 0 and Stage 1 of the decision engine (`policy.md` §5). A Stage 0 failure or a Stage 1 explicit deny ⇒ `{kind:"none"}`.
2. RBAC allow (Stage 2): if `allows(p)` is false and mode ∈ {`rbacAndPolicy`, `rbacOnly`} ⇒ `{kind:"none"}`. For `rbacOrPolicy` see §5.
3. Walls (Stage 3) and resource policies (Stage 4) contribute constraints by the rules of §5.
4. The operation MUST be **fail-closed**: on any error, timeout, unavailable store, or policy that cannot produce a constraint, the result MUST be `{kind:"none"}` or `{kind:"unsupported"}`; it MUST NEVER be `{kind:"all"}` as a consequence of an error.
5. The result MUST contain only data derived from the subject, the policy definitions, and constants — never resource data.

## 3. Constraint expression language

```
Expr =
    { op: "all", args: List<Expr> }          // conjunction; empty list ≡ true
  | { op: "any", args: List<Expr> }          // disjunction; empty list ≡ false
  | { op: "not", arg: Expr }
  | { op: "eq",  field: FieldPath, value: Scalar }
  | { op: "in",  field: FieldPath, values: List<Scalar> }     // values MAY be empty ≡ false

FieldPath = Name ( "." Name )*       Name = [A-Za-z_][A-Za-z0-9_]{0,63}      max 8 names
Scalar    = String | Number(finite) | Boolean | Null
```

The language is intentionally minimal. Adding operators requires a spec revision.

### 3.1 Semantics (evaluation over a resource `r`)

1. `eq(f, v)` is true iff the field `f` is **present** in `r` and its value equals `v` (strict equality: same JSON type and value; `"1" ≠ 1`; strings compared as Unicode scalar sequences without normalization).
2. If the field is absent in `r`, `eq` and `in` are **false** — and `not(eq(...))` is therefore **true**. (This is the defined semantics; translators MUST reproduce it, including for `NULL`-like absent columns/fields.)
3. `eq(f, null)` is true iff `f` is present and null (an absent field does not equal null).
4. `all`, `any`, `not` have standard boolean semantics (two-valued; no "unknown").
5. Evaluation MUST be total: no expression can raise.

### 3.2 Normal form and limits

1. Implementations MUST produce expressions of depth ≤ 16 and ≤ 256 nodes; a policy scope exceeding this ⇒ `{kind:"unsupported"}`.
2. Implementations MAY simplify (`all([])` → all; `any([x])` → x) provided semantics are preserved; the *kind* mapping in §4 is normative.

### 3.3 Binding of subject values

Values that originate from the subject (e.g. `subject.id`, a tenant id, an attribute list) MUST be placed in `value`/`values` as **data** at construction time. A constraint MUST NOT contain references or templates that a consumer would have to interpolate into a query string. Consumers (translators) MUST treat every `value` as data and MUST NOT interpret it as part of query syntax.

## 4. Kind normalization

| Expression result | `AuthScope` |
|---|---|
| `all([])` (true) | `{kind:"all"}` |
| `any([])` (false) | `{kind:"none"}` |
| any other | `{kind:"constraint", expr}` |

## 5. Computing the scope

Let `E_rbac` = true if RBAC allows (after Stage 1), else false. Let `walls` = scopes from global policies (each `ScopeFn` keyed by `action` or `*`), and `P` = the resource policies' scopes for `action` and `*`.

1. **Walls.** For each applicable wall policy that defines a `scope` function for the action (or `*`), include its expression as a conjunct. A wall that has *rules* but *no* corresponding `scope` function ⇒ the whole result is `{kind:"unsupported"}` (walls cannot be silently dropped; INV-AUTHZ-10).
2. **Resource policies** (`P ≠ ∅`):
   1. If rules apply for the action but no `ScopeFn` exists for them ⇒ `{kind:"unsupported"}`.
   2. Otherwise conjoin all applicable `ScopeFn` expressions (concrete + `*` keyed, all policies) — AND semantics identical to `policy.md` §5.2.
3. **Combine by mode** (given Stage 1 did not deny):

| Mode | Result |
|---|---|
| `rbacAndPolicy` | `E_rbac = false` ⇒ `none`; else `all(walls ∪ P)` |
| `rbacOnly` | `E_rbac = false` ⇒ `none`; else `all(walls)` |
| `policyOnly` | `P` empty-because-no-policy ⇒ `none`; else `all(walls ∪ P)` |
| `rbacOrPolicy` | `E_rbac = true` ⇒ `all(walls)`; `E_rbac = false` ⇒ `all(walls ∪ P)`; i.e. the policy constraint applies **only** when RBAC does not already allow everything |

4. `strictPolicies = true` and no applicable resource policy ⇒ `none`.
5. If any contributing `ScopeFn` throws, times out, or returns an invalid expression ⇒ `{kind:"none"}` plus `authz.policy_error` audit (`policy.md` §5.5). (Contrast with "unsupported": *unsupported* means "not expressible by design"; *error* means failure.)

## 6. Consistency with `authorize` (soundness and completeness)

For every policy that declares both `rules` and `scope` for an action, over any resource `r` carrying the fields the rules use, and any subject `s`:

1. **Soundness (MUST):** if `evaluate(scope, r) = true` then `authorize(s, action, r).effect = "allow"`. Scope MUST NOT admit a resource that `authorize` would deny.
2. **Completeness (MUST for declared scopes):** if `authorize(s, action, r).effect = "allow"` then `evaluate(scope, r) = true`. Scope MUST NOT hide a resource that `authorize` allows.

The only permitted divergence is **time-dependent** rules, where `evaluate` is performed at the instant used to build the scope and the resource listing occurs later; implementations MUST document this and SHOULD apply the scope in the same operation as the data read.
Conformance verifies this equivalence with generated resources (`conformance.md` group `SCP`).

## 7. Consumer obligations (translators and hosts)

1. A consumer receiving `{kind:"unsupported"}` MUST NOT run the query unfiltered. It MUST either filter every candidate through `authorize` individually, or refuse (`FORBIDDEN`).
2. A consumer receiving `{kind:"none"}` MUST return an empty result without querying, or MUST apply a contradiction filter.
3. A translator encountering a `FieldPath` that does not correspond to a known/allowed filterable field of the resource type MUST fail closed (match nothing) and MUST report a configuration error; it MUST NOT ignore the unknown conjunct.
4. A translator MUST implement the absent-field semantics of §3.1.2 or reject the expression as unsupported.
5. Counts, aggregates and pagination MUST be computed *after* applying the scope, so that totals, `has more`, and paging cursors do not leak the existence of unauthorized resources.
