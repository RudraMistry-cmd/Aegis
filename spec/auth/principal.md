# Aegis Spec — Principal, Subject, and Identity Contracts

Status: Draft 0.1 · Normative
Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** are to be interpreted as in RFC 2119 / RFC 8174 when, and only when, they appear in capitals.

This document is a *contract*. It defines data shapes, constraints and guarantees. It prescribes no language, framework, database or wire format.

## 0. Notation and primitive types

| Type | Definition |
|---|---|
| `String(a..b)` | Sequence of Unicode scalar values, length `a`–`b` inclusive, counted in scalar values (not bytes). |
| `Id` | `String(1..128)`, opaque, matching `[A-Za-z0-9_\-.:~]+`. Implementations MUST NOT assign meaning to its content. Ids MUST be unguessable-by-enumeration (MUST NOT be sequential integers exposed externally). |
| `Timestamp` | An instant in UTC with millisecond precision or finer. Comparison is by instant. |
| `Duration` | Non-negative integer number of milliseconds. |
| `Bytes` | Opaque octet string. |
| `Json` | A JSON value (RFC 8259) restricted to: objects, arrays, strings, finite numbers, booleans, `null`. |
| `T?` | Optional: the field MAY be absent. An absent field and a field holding `null` MUST be treated as equivalent unless stated otherwise. |
| `Set<T>` | Unordered collection without duplicates. |
| `Map<K,V>` | Collection of unique keys. |

All time-dependent behavior in this specification MUST be evaluated against an injected `Clock` (see `storage/interfaces.md` §9). Implementations MUST NOT read ambient system time directly in any code path governed by this specification.

---

## 1. Subject

A **Subject** is the *only* representation of "who" that the authorization layer (`rbac/*`, `policy/*`) is permitted to consume.

```
Subject {
  id          : Id                       REQUIRED
  type        : SubjectType              REQUIRED
  tenantId    : Id?                      OPTIONAL
  attributes  : Map<String, Json>?       OPTIONAL
}
SubjectType = String(1..32) matching [a-z][a-z0-9_-]*
```

Well-known `type` values: `user`. Other values (e.g. `service`, `apikey`) are reserved for extensions and MUST be treated by the core as opaque strings.

### 1.1 Field constraints

1. `id` MUST be non-empty and MUST be stable for the lifetime of the underlying identity. It MUST NOT be reused for a different identity after deletion.
2. `type` MUST be present. Absence MUST be rejected with `VALIDATION_FAILED` (see `errors.md`).
3. `tenantId`, when present, MUST be non-empty. An empty string MUST be rejected; it MUST NOT be coerced to "absent".
4. `attributes`:
   1. Keys MUST match `[A-Za-z][A-Za-z0-9_.-]{0,63}`.
   2. The serialized form SHOULD NOT exceed 8 KiB. An implementation MAY enforce a lower or higher documented limit and MUST reject excess with `VALIDATION_FAILED`.
   3. `attributes` MUST NOT contain secrets (passwords, tokens, key material, hashes). Implementations that populate attributes MUST NOT copy any `Credential` content into them.
   4. `attributes` is a **snapshot**: values reflect the state at the time the Subject was built and MUST NOT be updated in place.
5. A `Subject` MUST be immutable after construction. Any API that returns a Subject MUST return a value that callers cannot use to alter the Subject observed by other holders.
6. Authorization components **MUST NOT** accept, read, or branch on any field not defined in §1. In particular they MUST NOT read `sessionId`, `authMethod`, tokens, or raw claims, except through `attributes` populated by the host.

---

## 2. Principal

A **Principal** is a Subject whose identity has been *authenticated for the current request/operation*.

```
Principal extends Subject {
  authMethod       : String(1..64)            REQUIRED   e.g. "password", "oidc:<provider>", "apikey"
  authenticatedAt  : Timestamp                REQUIRED   time the primary authentication event occurred
  sessionId        : Id?                      CONDITIONAL
  amr              : List<String(1..32)>?     OPTIONAL   authentication method references
  claims           : Map<String, Json>?       OPTIONAL   verified, non-secret transport claims
}
```

### 2.1 Constraints

1. `authMethod` and `authenticatedAt` MUST be present on every Principal.
2. `sessionId` MUST be present when the Principal was resolved from a session-backed transport (every transport defined by this specification is session-backed). It MAY be absent only for extension strategies that explicitly document a session-less model.
3. `authenticatedAt` MUST be the time of the *original* authentication (login), not of the current request, token issue, or refresh. A refresh MUST NOT advance `authenticatedAt`.
4. `amr`, when present, MUST list only methods that were actually verified in the authentication that created the session (e.g. `["pwd"]`). It MUST NOT be client-supplied. A refresh MUST preserve `amr` unchanged and MUST NOT add elements.
5. A Principal MUST NOT contain, and MUST NOT expose through any accessor, a password, password hash, refresh token, session token, access token string, signing key, or one-time token. (Principals MAY be logged; therefore this rule is a security requirement.)
6. A Principal MUST be immutable and MUST be valid only for the operation/request for which it was resolved. Implementations MUST NOT cache a Principal across requests (see INV-AUTH-01).
7. A Principal MUST only be produced by:
   1. successful authentication (`flows/login.md`),
   2. successful request resolution (§6), or
   3. an explicit test/fixture constructor clearly segregated from production APIs.
   The public API MUST NOT offer a way for host code to turn arbitrary input into a Principal.
8. A Principal's `type` MUST equal the `type` of the stored identity it represents; an implementation MUST NOT promote `type`.

### 2.2 Principal → Subject projection

`toSubject(principal)` MUST yield a Subject with identical `id`, `type`, `tenantId`, and `attributes`, and MUST drop all authentication-specific fields. Authorization entry points MUST accept either a Subject or a Principal and MUST apply this projection before any evaluation, so that behavior is identical for both.

### 2.3 Attribute population

`attributes` is populated by an **attribute provider** configured by the host (see `storage/interfaces.md` §9.6). Requirements:

1. The provider MUST be invoked during request resolution (§6) after the account state check, and its result MUST be frozen into the Principal.
2. A provider failure MUST cause resolution to fail with `STORAGE_UNAVAILABLE` or `INTERNAL`; it MUST NOT cause the Principal to be returned without attributes (authorization relying on missing attributes would silently change behavior).
3. A provider MUST NOT be able to change `id`, `type`, or `tenantId`.
4. `tenantId` is determined by the identity layer (or provider) and MUST NOT be taken from request input (headers, body, URL).

---

## 3. User

```
User {
  id               : Id                       REQUIRED  immutable
  status           : AccountStateName         REQUIRED
  version          : Integer ≥ 0              REQUIRED  incremented on every mutation of the row
  securityVersion  : Integer ≥ 0              REQUIRED  see §3.2
  createdAt        : Timestamp                REQUIRED
  updatedAt        : Timestamp                REQUIRED
  metadata         : Map<String, Json>        REQUIRED  may be empty; opaque to the core
}
```

1. `id` MUST be immutable.
2. `metadata` is project-defined. The core MUST store and return it verbatim and MUST NOT interpret it. A project MAY supply a validation schema; if configured, writes failing it MUST be rejected with `VALIDATION_FAILED`. Implementations SHOULD bound `metadata` to 16 KiB serialized.
3. A User record MUST NOT contain credential material. Credentials are separate (§5).
4. Registration payloads MUST NOT be able to set `id`, `status`, `version`, `securityVersion`, role assignments, or any authorization data via `metadata` or any other field (mass-assignment prevention; see INV-AUTHZ-09).

### 3.1 Optimistic concurrency

Every mutation of `status` MUST be conditional on `version` (compare-and-set). A mismatch MUST fail with `PRECONDITION_FAILED` and MUST NOT apply any part of the change.

### 3.2 securityVersion

`securityVersion` is a monotonically increasing integer. It MUST be incremented (atomically with the triggering change) when:

1. the password is changed or reset,
2. the account enters a state whose `canLogin` is `false`,
3. an administrator invokes "invalidate all credentials" for the user.

It MUST NOT be incremented by role assignment changes (permissions are not carried in tokens; see `tokens.md` §2.4).

---

## 4. Identifier

```
Identifier {
  id          : Id
  userId      : Id
  type        : IdentifierType                 "email" | "username" | (extension types)
  value       : String(1..320)                 as supplied (display form)
  normalized  : String(1..320)                 canonical form used for lookup and uniqueness
  verified    : Boolean                        REQUIRED
  createdAt   : Timestamp
}
```

1. `(type, normalized)` MUST be globally unique. A second insertion MUST fail with `CONFLICT`.
2. A `User` MAY have several Identifiers, including several of the same type. At most one identifier per `type` MAY be marked primary if the project configures that (not required by this spec).
3. Lookup MUST be by `(type, normalized)`.

### 4.1 Normalization (MUST)

Normalization is deterministic and MUST be applied identically at registration, login, reset request, and any other lookup.

| Type | Steps (in order) | Additional validation |
|---|---|---|
| `email` | Trim leading/trailing Unicode whitespace → Unicode NFKC → lowercase using locale-independent full case mapping | Exactly one `@`; local-part and domain non-empty; total length ≤ 320; MUST NOT apply provider-specific rewriting (no dot or `+tag` removal). |
| `username` | Trim → NFKC → lowercase (locale-independent) | After normalization MUST match `[a-z0-9][a-z0-9._-]{2,63}`. A project MAY restrict further and MUST NOT loosen. |

Two inputs that normalize to the same string MUST be treated as the same identifier. A normalization that produces the empty string MUST be rejected with `VALIDATION_FAILED`.

### 4.2 Uniqueness across types

An `email` and a `username` with identical normalized text MUST NOT collide with each other (uniqueness is per `type`). A login that accepts several identifier types MUST define a deterministic lookup order, and if the supplied value could match more than one user across types, it MUST authenticate against **all** candidates only if the project explicitly enables that; otherwise it MUST resolve in configured type order and stop at the first match. (Enumeration-safety rules in `flows/login.md` apply regardless.)

---

## 5. Credential

```
Credential {
  id          : Id
  userId      : Id
  type        : CredentialType                "password" | (extension types e.g. "totp", "passkey")
  payload     : Bytes | String                opaque, type-defined; confidentiality-sensitive
  createdAt   : Timestamp
  lastUsedAt  : Timestamp?
}
```

1. A `User` MUST have at most one active credential per `type` unless the type's definition says otherwise (the `password` type: exactly zero or one).
2. `payload` MUST NOT be returned by any API intended for host/UI consumption and MUST NOT appear in logs, audit events, errors, traces, or serialized Principals.

### 5.1 Password credential

1. The payload MUST be a self-describing, salted, memory-hard hash string (an encoded form carrying the algorithm identifier, parameters, salt, and digest). The plaintext password MUST NOT be persisted anywhere, ever.
2. The `PasswordHasher` port (`storage/interfaces.md` §9.4) MUST:
   1. generate a fresh, unique, cryptographically random salt of at least 128 bits per hash,
   2. compare in constant time with respect to the digest,
   3. report whether stored parameters are weaker than the configured target (`needsRehash`).
3. The default algorithm MUST be Argon2id with parameters not weaker than: memory 19 MiB, iterations 2, parallelism 1. Implementations SHOULD document tuning toward 100–250 ms per hash on target hardware. Other algorithms (scrypt, bcrypt) MAY be offered only as explicitly selected, named alternatives.
4. If a pepper is configured, it MUST be applied identically at hash and verify time via a keyed construction, it MUST be versioned so rotation does not invalidate stored hashes silently, and it MUST NOT be stored alongside the hashes.
5. **Password input rules** (apply at set/change/reset; verification applies steps 1–3 only):
   1. Input MUST be NFKC-normalized before hashing or verifying.
   2. Input containing U+0000 MUST be rejected with `VALIDATION_FAILED` at set time and MUST fail verification (as a normal credential mismatch) at login time.
   3. Input longer than 1024 Unicode scalar values MUST be rejected at set time with `VALIDATION_FAILED`, and at login time MUST fail as a normal credential mismatch **without invoking the hasher**.
   4. At set time: length (in scalar values) MUST be ≥ the configured minimum (default 12, MUST NOT be configurable below 8). Composition rules (mandatory character classes) MUST NOT be applied by default. The project MAY configure a denylist and a `BreachChecker`; a positive match MUST reject with `VALIDATION_FAILED`.
   5. A password equal (after normalization) to any identifier of the user SHOULD be rejected.
6. The user's password MUST NOT be sent to, or influence, any `Notifier` payload.

---

## 6. Account state

```
AccountStateDefinition {
  name                  : String(1..32) matching [a-z][a-z0-9_]*   REQUIRED, unique
  canLogin              : Boolean                                  REQUIRED
  canRefresh            : Boolean                                  REQUIRED
  restricted            : Boolean                                  REQUIRED, default false
  revokeSessionsOnEnter : Boolean                                  REQUIRED, default false
}
AccountStateMachine {
  states      : Set<AccountStateDefinition>
  initial     : name
  transitions : Map<name, Set<name>>
}
```

### 6.1 Constraints

1. At least one state MUST have `canLogin = true`. The `initial` state MUST exist.
2. Every transition endpoint MUST name a defined state. A transition `s → s` is implicitly forbidden.
3. A state with `canLogin = false` MUST also have `revokeSessionsOnEnter = true`, and MUST have `canRefresh = false`. (Rationale: a state that refuses login but tolerates continued sessions is a privilege-retention hazard.)
4. `restricted = true` means the project's host code MAY limit capabilities (e.g. unverified accounts); the core only exposes the flag on Principal resolution via `attributes.accountRestricted` (boolean) which the core MUST populate.
5. Default state machine (used when a project supplies none):

| State | canLogin | canRefresh | restricted | revokeSessionsOnEnter | Transitions to |
|---|---|---|---|---|---|
| `unverified` | true | true | true | false | `active`, `disabled` |
| `active` | true | true | false | false | `suspended`, `disabled` |
| `suspended` | false | false | false | true | `active`, `disabled` |
| `disabled` | false | false | false | true | (none) |

   `initial` is `unverified` when email verification is `required` or `optional`, and `active` when verification is `off`.

### 6.2 Transition operation

`setStatus(userId, to, expectedVersion, reason)`:

1. MUST fail with `STATE_TRANSITION_INVALID` if `to` is not in `transitions[current]`.
2. MUST fail with `PRECONDITION_FAILED` if `expectedVersion ≠ user.version`.
3. If the target has `canLogin = false` it MUST, **atomically with the status change**, (a) revoke all sessions and refresh families of the user and (b) increment `securityVersion`. Partial application (status changed, sessions not revoked) MUST NOT be observable by any subsequent read.
4. MUST emit audit event `account.state_changed` (see `storage/interfaces.md` §10).
5. Is NOT idempotent by version: a retry with the same `expectedVersion` after a successful transition MUST fail with `PRECONDITION_FAILED` (the version has advanced). Callers needing idempotency MUST re-read the user first.

---

## 7. Principal derivation — request resolution

`resolve(requestCredentials) → Principal | null` is the transport-agnostic operation by which a host turns the credentials of an incoming request into a Principal.

### 7.1 Inputs and outputs

* Input: an opaque `RequestCredentials` object supplied by an integration layer (e.g. a bearer string, a session cookie value). The core MUST NOT parse HTTP.
* Output: a `Principal`, or `null` meaning "no valid authentication present". Resolution MUST NOT throw for the conditions "absent", "malformed", "expired", "revoked", "unknown session", "bad signature", or "account state forbids". These MUST all yield `null` (the reason MAY be logged internally and MUST be audited as `auth.rejected` at most at a sampled rate; the reason MUST NOT be distinguishable by the caller).
* Infrastructure failures (store/cache unavailable, attribute provider failure) MUST NOT yield `null` (which would look like "logged out") **or** a Principal built without the failed check: they MUST surface as `STORAGE_UNAVAILABLE`/`INTERNAL` (fail closed, distinguishable from unauthenticated).

### 7.2 Steps (normative)

1. **Extract.** If no credential material is present → return `null`.
2. **Verify transport credential** per the configured transport (`tokens.md` §2 or §5). Any verification failure → `null`.
3. **Load session** by `sid`/session id from the authoritative `SessionStore` (`tokens.md` §2.5: no cache, no replica). Session absent, revoked, idle-expired, or absolute-expired → `null`. This step is never skipped.
4. **Revocation checks** (always; `tokens.md` §2.5): session not revoked **and** the token's `sv` equals the user's current `securityVersion`. Mismatch → `null`.
5. **Account state.** Load user status from the authoritative store (`tokens.md` §2.5). If the state's `canLogin = false` → `null`. (For `restricted` states, a Principal is still returned.)
6. **Build Principal** with `sessionId`, `authMethod`, `authenticatedAt`, `amr` copied from the **session record** (never from request input), `attributes` from the provider (§2.3).
7. **Touch** the session (sliding idle expiry) subject to the touch-throttle in `session.md` §5. A touch failure MUST NOT fail resolution but MUST be logged.
8. Return the Principal.

An implementation MUST NOT return a Principal if any mandatory step above (3–5 as applicable) fails to complete.
