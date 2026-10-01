# Aegis Spec — Errors

Status: Draft 0.1 · Normative
Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** are as defined in RFC 2119 / RFC 8174 when in capitals.

## 1. Error model

Every failure that crosses the public API boundary MUST be an instance of the following abstract structure. Languages map it to their native error/exception/result idiom; the **codes** and **semantics** are normative, the representation is not.

```
AuthError {
  code        : ErrorCode          REQUIRED   stable, from §2; part of the public contract
  category    : Category           REQUIRED   "validation" | "authentication" | "authorization" | "conflict"
                                              | "throttling" | "configuration" | "infrastructure" | "internal"
  message     : String             REQUIRED   fixed text per code (§5); safe to show to end users
  retryable   : Boolean            REQUIRED   whether an identical retry could succeed without changed input
  retryAfter  : Duration?          OPTIONAL   only for RATE_LIMITED / retryable infrastructure errors
  details     : Map<String, Json>? OPTIONAL   only the whitelisted fields in §2 for that code
  requestId   : String?            OPTIONAL
  cause       : internal           INTERNAL   diagnostic chain; MUST NOT be serialized to clients, logs at `debug` only
}
```

Rules:

1. `code` values MUST NOT change meaning between releases of the same major spec version. New codes MAY be added in a minor version; consumers MUST treat unknown codes as `INTERNAL`.
2. `message` MUST be the fixed text of §5. It MUST NOT include identifiers, resource values, internal state names (other than where §2 explicitly allows), stack traces, driver messages, SQL, file paths, token fragments, or user-supplied input.
3. `details` MUST contain only the fields §2 lists for the code.
4. `cause` is for operators. It MUST be scrubbed of secrets (passwords, tokens, hashes, key material) *before* being attached.
5. An implementation MUST NOT use any code of §2 for a different situation than the one defined, and MUST NOT invent codes for the situations enumerated.
6. Errors MUST be **typed**: callers MUST be able to branch on `code` without parsing `message`.

## 2. Catalog

| Code | Category | Retryable | Raised when | `details` allowed |
|---|---|---|---|---|
| `VALIDATION_FAILED` | validation | no | An input violates a documented constraint: wrong type, over-length, bad grammar (permission/role/identifier/scope), password policy failure, metadata schema failure, forbidden mass-assigned field, expired `expiresAt` supplied, unsupported scope for an implementation that lacks it. **Not** raised for credential mismatch. | `field` (name), `rule` (rule identifier, e.g. `password.min_length`) |
| `INVALID_CREDENTIALS` | authentication | no | Login (or change-password current-password check) failed for **any** of: unknown identifier, wrong password, no password credential, malformed identifier, over-length password. MUST be indistinguishable across these. | none |
| `ACCOUNT_RESTRICTED` | authentication | no | The password (or equivalent factor) was **correct** but the account state forbids the operation (`canLogin=false` at login; `canRefresh=false` at refresh). | `state` (state name) — only when `revealRestrictedState = true` |
| `RATE_LIMITED` | throttling | yes | A throttle key is blocked (login, refresh, reset, registration, change-password), or hasher saturation. | `retryAfter` |
| `UNAUTHENTICATED` | authentication | no | A guard/operation requiring an authenticated Principal was invoked with none (`resolve` returned `null`). | none |
| `TOKEN_INVALID` | authentication | no (unless flagged `retryable` in-flight, `refresh.md` §3) | A presented token (access, refresh, session, one-time) is unknown, malformed, bad signature, wrong type/purpose/audience/issuer, revoked, reused, consumed, superseded, or its session/user is gone. MUST NOT reveal which. | none |
| `TOKEN_EXPIRED` | authentication | no | A presented **access token** is correctly signed but expired (`verify` failure `expired`), or a **refresh token** record exists and is expired. | none |
| `FORBIDDEN` | authorization | no | `assert`/guard evaluation produced `deny` (any reason), or an operation requires a permission the Principal lacks. | `permission` (concrete permission string) — MAY be omitted by configuration |
| `ESCALATION_DENIED` | authorization | no | A role/grant/state change would violate an escalation guard (`assignments.md` §6): self-assign, grant ceiling, last-superuser, tenant boundary. | `rule` (`self_assign`, `grant_ceiling`, `last_superuser`, `tenant_boundary`) |
| `SESSION_LIMIT_REACHED` | authentication | no | Session creation refused: limit reached with policy `reject`. | none |
| `NOT_FOUND` | validation | no | A target entity does not exist **or** the caller is not permitted to learn that it exists (`session.md` §7.4, `revoke.md` §3.3). | none |
| `CONFLICT` | conflict | no | A uniqueness constraint failed (identifier taken with `enumerationSafeRegistration = false`, duplicate role name, `multiRole=false` second role). | `field` |
| `PRECONDITION_FAILED` | conflict | yes (after re-read) | An expected-version/expected-state comparison failed (`User.version`, dynamic role version); nothing was changed. | none |
| `STATE_TRANSITION_INVALID` | validation | no | A requested account-state transition is not in `transitions[current]`. | `from`, `to` (state names; only to authorized callers) |
| `CONFIG_INVALID` | configuration | no | Start-up/registration validation failed: malformed permission/role, cycle, unknown reference, conflicting policy modes, weak/missing key, unsafe option without override. Raised **at construction**, never during request handling. | `violations`: list of `{ path, rule, message }` — ALL violations, not just the first |
| `STORAGE_UNAVAILABLE` | infrastructure | yes | A store, cache required for correctness, hasher pool, key provider, or attribute provider failed or timed out, and the operation cannot safely proceed (fail closed). | `retryAfter` (optional) |
| `INTERNAL` | internal | no | An unexpected defect or invariant breach. MUST be treated as a bug; MUST emit an `error`-level log with `cause`. | none |

## 3. External vs internal reasons

Internal flows distinguish more situations than callers may see. The mapping below is normative.

| Internal reason | External code |
|---|---|
| refresh: unknown / revoked / reused / superseded / session missing / user deleted / `sv` mismatch / integrity failure | `TOKEN_INVALID` |
| refresh: record exists, expired | `TOKEN_EXPIRED` |
| refresh: `canRefresh = false` | `ACCOUNT_RESTRICTED` |
| access token verify: `malformed`, `bad_signature`, `unknown_key`, `wrong_issuer`, `wrong_audience`, `wrong_type`, `unsupported_algorithm`, `not_yet_valid` | `TOKEN_INVALID` |
| access token verify: `expired` | `TOKEN_EXPIRED` |
| `resolve`: any of the above, session revoked/expired/absent, `sv` mismatch, state forbids | **`null`** (Principal absent; *not an error*); guards then raise `UNAUTHENTICATED` (or `TOKEN_EXPIRED` if the integration layer surfaces the distinction for client refresh behavior) |
| login: unknown identifier, bad format, wrong password, no credential, over-length password | `INVALID_CREDENTIALS` |
| one-time token: unknown, expired, consumed, wrong purpose | `TOKEN_INVALID` |
| authorization deny, any `DecisionReason` | `FORBIDDEN` (via `assert`/guards); `Decision` value (via `authorize`/`can`) |
| policy exception / timeout | `Decision{deny, policy_error}` → `FORBIDDEN` when asserted; **never** `INTERNAL` to the caller |
| adapter `Conflict` | `CONFLICT` |
| adapter `PreconditionFailed` | `PRECONDITION_FAILED` |
| adapter `Unavailable`, timeout | `STORAGE_UNAVAILABLE` |
| adapter `Invalid` | `VALIDATION_FAILED` |

## 4. Return versus raise

1. **Authorization decisions are values.** `authorize` and `can` MUST return a `Decision`/boolean for every deny, including invalid input to the decision (`policy.md` §5 Stage 0). They MAY raise only `STORAGE_UNAVAILABLE`-class errors when no safe deny can be produced — in which case the preferred behavior is `deny/unavailable` (`assignments.md` §7.6). `assert` and guards raise `FORBIDDEN`.
2. **`resolve` returns absence, not errors,** for all credential problems (`principal.md` §7.1). It raises only infrastructure failures.
3. **Authentication operations** (`login`, `refresh`, `logout`, `register`, …) raise (or return failure for) the codes of §2.
4. **Configuration problems** surface only at construction as `CONFIG_INVALID`. After successful construction, no code path may raise `CONFIG_INVALID`.
5. **Idempotent operations** (`logout`, `unassign`, `revoke`) MUST report success for already-satisfied requests rather than `NOT_FOUND`, except where §2 `NOT_FOUND` is defined for authorization-hiding.

## 5. Fixed messages (default locale-neutral English)

| Code | Message |
|---|---|
| `VALIDATION_FAILED` | `The request is invalid.` |
| `INVALID_CREDENTIALS` | `Invalid credentials.` |
| `ACCOUNT_RESTRICTED` | `This account cannot perform that action.` |
| `RATE_LIMITED` | `Too many attempts. Try again later.` |
| `UNAUTHENTICATED` | `Authentication required.` |
| `TOKEN_INVALID` | `The credential is invalid.` |
| `TOKEN_EXPIRED` | `The credential has expired.` |
| `FORBIDDEN` | `You do not have permission to perform this action.` |
| `ESCALATION_DENIED` | `This change is not permitted.` |
| `SESSION_LIMIT_REACHED` | `Too many active sessions.` |
| `NOT_FOUND` | `Not found.` |
| `CONFLICT` | `The request conflicts with existing data.` |
| `PRECONDITION_FAILED` | `The resource was modified; reload and retry.` |
| `STATE_TRANSITION_INVALID` | `That state change is not allowed.` |
| `CONFIG_INVALID` | `The configuration is invalid.` |
| `STORAGE_UNAVAILABLE` | `Service temporarily unavailable.` |
| `INTERNAL` | `An unexpected error occurred.` |

Implementations MAY localize these strings but MUST preserve the one-to-one meaning and MUST NOT make a localized message depend on internal state beyond the code.

## 6. Precedence when several errors apply

When one request violates several constraints, the implementation MUST report the **first** applicable in this order (so that error outcomes are deterministic and non-leaking):

1. `VALIDATION_FAILED` (shape/type/over-length) — before touching any store;
2. `RATE_LIMITED`;
3. `UNAUTHENTICATED` / `TOKEN_*`;
4. `INVALID_CREDENTIALS`;
5. `ACCOUNT_RESTRICTED`;
6. `FORBIDDEN` / `ESCALATION_DENIED`;
7. `NOT_FOUND` / `STATE_TRANSITION_INVALID`;
8. `CONFLICT` / `PRECONDITION_FAILED` / `SESSION_LIMIT_REACHED`;
9. `STORAGE_UNAVAILABLE` / `INTERNAL`.

Exception: infrastructure failure encountered before a later check can be evaluated MUST be reported as `STORAGE_UNAVAILABLE` (the earlier checks that completed stand).

## 7. Integration-layer note (non-normative)

Transport-specific encodings (e.g. an HTTP status class per `category`) are the responsibility of integration adapters and are intentionally **not** part of the core specification. An integration SHOULD map: `authentication` → "unauthenticated"-class, `authorization` → "forbidden"-class, `throttling` → "too many requests"-class, `validation` → "bad request"-class, `conflict` → "conflict"-class, `infrastructure` → "unavailable"-class, `internal`/`configuration` → "server error"-class, and MUST NOT add detail beyond §1.
