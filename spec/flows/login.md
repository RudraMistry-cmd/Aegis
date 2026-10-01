# Aegis Spec — Flow: Login (and related unauthenticated flows)

Status: Draft 0.1 · Normative
Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** are as defined in RFC 2119 / RFC 8174 when in capitals.
Entities: `auth/*`. Ports: `storage/interfaces.md`. Errors: `errors.md`. Invariants: `invariants.md`.

Each flow below is expressed as numbered **steps**. Each step lists the **security checks** that MUST hold and the **failure** outcome. Step order is normative where stated "MUST precede"; otherwise an implementation MAY reorder steps provided every check still holds and externally visible behavior and side effects are identical.

## 1. Terminology

* **Strategy** — proves an identity (e.g. `password`). Produces a `VerifiedIdentity { userId, authMethod, amr, strategyData? }`.
* **Transport** — carries the resulting session (§2).
* **Throttle keys** — `K_id = ("login", normalizedIdentifier)`, `K_ip = ("login-ip", clientIp)`, `K_g = ("login-global")` (`storage/interfaces.md` §9.8). `clientIp` is supplied by the host and MUST be treated as opaque, host-trusted input; if absent, `K_ip` is skipped.
* **External outcome** — what the host/caller can observe: return value/error code, and (as far as the core controls) timing and side effects.

## 2. Transport contract (informative summary of the carrier abstraction)

```
SessionTransport {
  issue(session: Session, user: User, now: Timestamp)      -> IssuedCredentials          // tokens.md §7
  resolve(creds: RequestCredentials, now: Timestamp)       -> { sessionId: Id, subjectId: Id, securityVersion: Integer? } | null
  renew(presented: RefreshCredential, now: Timestamp)      -> IssuedCredentials | TOKEN_* | …  // flows/refresh.md; MAY be unsupported (opaque-session transport)
  describe()                                               -> { revocationMode: "eventual"|"strict", accessTtl?: Duration, ... }
}
```

A transport MUST NOT contain authorization logic and MUST NOT create or modify Sessions except through the session manager. The authorization layer MUST NOT call a transport (INV-ARCH-01).

## 3. Login — password strategy

### 3.1 Inputs

```
login({ identifier: String, password: String, device?: DeviceInfo, clientIp?: String, requestId?: String })
  -> Authenticated { principal: Principal, credentials: IssuedCredentials }
   | MfaChallenge  { challengeId: Id, methods: List<String>, expiresAt: Timestamp }      // RESERVED for MFA extension
   | Error
```

`password` MUST NOT be logged, audited, echoed in errors, or retained after the call returns. The function MUST NOT accept credentials in the form of a previously issued token as a substitute for the password.

### 3.2 Steps

| # | Step | Security checks | Failure outcome |
|---|---|---|---|
| 1 | **Shape validation.** `identifier` and `password` are strings; `identifier` length ≤ 320 scalars; `password` ≤ 1024 scalars. | Oversize `password` ⇒ treat as credential mismatch **without invoking the hasher** (`principal.md` §5.1.5.3) but still execute step 2 and step 5's failure bookkeeping. Wrong types ⇒ `VALIDATION_FAILED` (a programmer error, not credential-dependent). | `VALIDATION_FAILED` |
| 2 | **Throttle gate.** MUST precede any user lookup, any hashing, any credential read. `peek` `K_id`, `K_ip`, `K_g`. | If any is `blocked`, return immediately; MUST NOT perform lookup or verification (a blocked caller cannot learn whether a guess was correct). `retryAfter` is the max of blocked keys. If the limiter is unavailable: per `throttleFailMode` (§5.7). The `blocked` outcome MUST be the same regardless of whether the identifier exists. | `RATE_LIMITED` |
| 3 | **Normalize identifier** per type(s) (`principal.md` §4). Syntactically invalid after normalization ⇒ proceed down the *failure path* (step 5) as an unknown user. | Normalization failure MUST NOT yield a different external outcome than "unknown user" (no format oracle). | (to step 5) |
| 4 | **Lookup.** `IdentifierStore.findByNormalized` → user (R); `CredentialStore.get(userId,"password")`. | Both reads MUST be R-consistency. | `STORAGE_UNAVAILABLE` on infra failure |
| 5 | **Verify.** If the user and credential exist: `PasswordHasher.verify(password, payload)`. Else: `PasswordHasher.dummyVerify(password)`. | **Exactly one** hasher operation of equal cost MUST execute on every path that reaches this step (found/not found/no credential/invalid identifier), excluding the oversize-password path. Comparison MUST be constant-time. | — |
| 5a | **On mismatch / unknown:** `recordFailure(K_id)` and `recordFailure(K_ip)` **and** `K_g`; audit `login.failed` (reason `invalid_credentials`; no existence info; identifier only as keyed digest); return. | `recordFailure` MUST be invoked identically for unknown identifiers, so counters do not reveal existence. Response MUST be byte-for-byte identical in content (code and message) for: unknown identifier, wrong password, no password credential, invalid identifier format. | `INVALID_CREDENTIALS` |
| 6 | **Account-state gate** (only after a **correct** password). Re-read the user (R); look up the state definition. If `canLogin = false`: do **not** record a throttle failure; audit `login.failed` (reason `account_state`, severity notice); return. | State MUST be revealed only when the password was correct (no state oracle for guessing attackers). If `revealRestrictedState = false`, return `INVALID_CREDENTIALS` instead (and record a failure). Unknown state name in storage ⇒ treat as `canLogin = false`, audit `config.warning`. | `ACCOUNT_RESTRICTED` |
| 7 | **Rehash** if `needsRehash`: compute a new hash from the plaintext just verified and `CredentialStore.put` it. | A rehash failure MUST NOT fail the login (log `warn`). The put MUST NOT overwrite a *newer* credential written concurrently (compare-by-previous-payload or perform in the step-9 unit). | — (best effort) |
| 8 | **Additional factors (RESERVED).** If the strategy/policy requires further factors, return `MfaChallenge` and stop. | No Session MAY exist and no credentials MAY be issued until all required factors have verified. `amr` MUST list only verified factors. | — |
| 9 | **Create session** in one serializable `UnitOfWork`: read `User.securityVersion` and state again, then `SessionStore.createWithLimit(...)` (`session.md` §4, §6). New id generated unconditionally; any pre-existing session/token supplied by the caller is ignored. | Session fixation: the new session id MUST be freshly generated (INV-SESS-03). If the state changed to `canLogin = false` between steps 6 and 9, abort with `ACCOUNT_RESTRICTED`. | `SESSION_LIMIT_REACHED` (policy `reject`); `ACCOUNT_RESTRICTED`; `STORAGE_UNAVAILABLE` |
| 10 | **Issue credentials** via `Transport.issue`. | Tokens issued only after the session is durably committed. If issuing fails, revoke the new session (reason `logout`) before returning the error (`tokens.md` §7.3). | `INTERNAL`/`STORAGE_UNAVAILABLE` |
| 11 | **Post-commit effects:** `reset(K_id)` (not `K_ip`, not `K_g`); audit `login.succeeded`, `session.created`, and `session.evicted` per evicted session; optional `login_notice` via `Notifier` for new devices. | Effects occur only after commit; their failure MUST NOT fail the login. | — |
| 12 | **Build Principal** (`authMethod`, `authenticatedAt = session.createdAt`, `amr`, `sessionId`; attributes via provider) and return. | Attribute-provider failure here ⇒ revoke the new session and fail with `INTERNAL`/`STORAGE_UNAVAILABLE` (no Principal without attributes). | as stated |

### 3.3 Required external behaviors

1. **No enumeration.** Unknown identifier, wrong password, missing credential, and malformed identifier MUST be externally indistinguishable (same error code, same message, same shape). Timing MUST be equalized per step 5 (one hasher op); a conforming implementation MUST document measured timing parity (conformance `AUTH-TIM-*`).
2. **Throttling is by attempt, not by outcome knowledge.** The same sequence of attempts MUST produce the same throttle state whether or not the identifier exists.
3. **Idempotence.** `login` is not idempotent: each success creates a new Session. Replaying a request creates another session; limits (§session.md 6) bound it.
4. **No credential reuse.** A successful login MUST NOT reuse, extend, or reactivate any existing Session or token.
5. **Auth-method integrity.** `authMethod`/`amr` MUST derive solely from the strategy result.

## 4. Failure conditions summary

| Condition | Error | Counts toward throttle? | Audit |
|---|---|---|---|
| Wrong types / over-length identifier | `VALIDATION_FAILED` | No | none |
| Any throttle key blocked | `RATE_LIMITED` | No (already blocked) | `login.throttled` |
| Unknown identifier / wrong password / no credential / oversize password | `INVALID_CREDENTIALS` | **Yes** | `login.failed` |
| Correct password, `canLogin = false` | `ACCOUNT_RESTRICTED` | No | `login.failed` (`account_state`) |
| Session limit with `reject` | `SESSION_LIMIT_REACHED` | No | `login.failed` (`session_limit`) |
| Store/hasher unavailable | `STORAGE_UNAVAILABLE` | No | `login.failed` (`unavailable`) |
| Credential issue failure | `INTERNAL` | No | `login.failed` (`issue_failed`) |

## 5. Security checks (cross-cutting, MUST)

1. **5.1 Order:** throttle (2) MUST precede lookup (4) and verify (5).
2. **5.2 Constant work:** step 5 equal-cost rule.
3. **5.3 State oracle:** step 6 only after verification.
4. **5.4 Fixation:** new session id; ignore presented credentials.
5. **5.5 Secrets hygiene:** no password/hash/token in logs/audit/errors/Principal.
6. **5.6 Atomicity:** step 9 atomic; step 10 only after commit; no half-issued sessions.
7. **5.7 Throttle outage:** `throttleFailMode` is `"open-with-alert"` (default: proceed, audit `security.throttle_unavailable`) or `"closed"` (deny with `RATE_LIMITED`). The mode MUST be explicit in `describe()`.
8. **5.8 Backoff:** after `failures ≥ threshold` the limiter MUST impose increasing delay (default thresholds: `K_id` 5 failures / 15 min; `K_ip` 50 / 15 min). A hard, unbounded lockout of an identifier MUST NOT be the default (DoS against victims). A host MAY configure a `ChallengeHook` that, when satisfied, lifts a `K_id` block (never a `K_g` block).
9. **5.9 Timing of side effects:** `Notifier` calls MUST NOT be awaited on the login response path.

## 6. Related unauthenticated flows

These flows share enumeration and token requirements with login. Each MUST follow the stated checks.

### 6.1 Registration

`register({identifier(s), password, metadata?, clientIp?}) -> RegistrationAccepted | Error`

1. Validate and normalize identifiers; validate password policy (`principal.md` §5.1.5); validate `metadata` against the configured schema; reject any attempt to set privileged fields (`principal.md` §3.4) with `VALIDATION_FAILED`.
2. Throttle by `K_ip` (registration bucket); blocked ⇒ `RATE_LIMITED`.
3. Hash the password (always, before checking existence, so both paths pay the same cost).
4. In one `UnitOfWork`: `UserStore.create` (initial state per `principal.md` §6.1.5), `IdentifierStore.add` (store enforces uniqueness), `CredentialStore.put`.
5. On `Conflict` for the identifier: when `enumerationSafeRegistration = true` (**default**), return the **same** `RegistrationAccepted` as success, perform no state change, and (SHOULD) send a "someone tried to register with your address" notification to the existing owner via `Notifier`. When `false`, return `CONFLICT` (documented enumeration trade-off; MUST be an explicit opt-out).
6. On success: if email verification is enabled, issue an `email_verify` one-time token (`tokens.md` §4) and send via `Notifier` (not awaited).
7. `RegistrationAccepted` MUST NOT contain the new user id or any token when `enumerationSafeRegistration = true`. Role assignment at registration, if any, is a host-configured default role from the catalog applied by the system actor, never from request data.
8. Audit `account.registered` on actual creation only.

### 6.2 Email verification

`verifyEmail(token: String) -> Verified | Error`

1. Digest the token; `OneTimeTokenStore.consume(hash, "email_verify", now)`; `null` ⇒ `TOKEN_INVALID` (no reason distinguishable: unknown, expired, consumed, wrong purpose).
2. In one `UnitOfWork`: `IdentifierStore.markVerified` for `target`; if the user's state is the verification-pending state, transition it with `setStatus` using the version read in the same unit (retry on `PreconditionFailed` up to a bounded count).
3. Audit `email.verified`. Does **not** log the user in and does not create a session.
4. Changing a user's email (`changeIdentifier`) MUST add the new identifier as unverified, send verification to the **new** address and a notice to the **old** address, and MUST NOT switch the login identifier until verified.

### 6.3 Password reset — request

`requestPasswordReset({identifier, clientIp?}) -> ResetRequestAccepted`

1. Throttle by `K_ip` and by `("reset", normalizedIdentifier)`. Blocked ⇒ `RATE_LIMITED` (the throttle outcome MUST NOT depend on existence).
2. Normalize and look up. **The external result MUST be identical** whether or not the identifier exists, is verified, or the account is restricted: `ResetRequestAccepted` with no data.
3. If a reset is permitted for the account: in one unit `invalidate(userId,"password_reset",null)` then `put` a new token (≥ 256 bits, TTL per `tokens.md` §4.2, purpose-bound); then hand the raw token to `Notifier.send` **without awaiting**.
4. The raw token MUST NOT be returned, logged or audited. Response latency MUST NOT depend on whether a user was found nor on `Notifier` latency (queue or fire-and-forget; documented).
5. Audit `password.reset_requested` (internal; includes whether a user existed only in the audit sink, never in the response).

### 6.4 Password reset — completion

`resetPassword({token, newPassword}) -> PasswordResetCompleted | Error`

1. Validate `newPassword` against the policy **before** consuming the token (so a rejected password does not burn the token) — `VALIDATION_FAILED`. This check MUST NOT depend on whether the token is valid.
2. Throttle by `K_ip` (reset bucket).
3. Hash the new password (equal cost whether or not the token turns out valid: hash first, then consume).
4. In one **serializable** `UnitOfWork`: `OneTimeTokenStore.consume(hash, "password_reset", now)` (`null` ⇒ roll back, `TOKEN_INVALID`); `CredentialStore.put`; `UserStore.bumpSecurityVersion`; `SessionStore.revokeAllForUser(userId, null, "password_reset")` (with refresh families); invalidate other outstanding reset tokens for the user.
5. After commit: notify the user's verified identifiers (`password_changed`); audit `password.reset_completed`. The reset MUST NOT create a Session or issue credentials (`login` is required afterwards).
6. A reset token consumed twice concurrently MUST succeed exactly once (INV-TOK-08).
7. If the account state has `canLogin = false` the reset MAY succeed but MUST NOT change the state.

### 6.5 Change password (authenticated)

`changePassword(principal, currentPassword, newPassword) -> Changed | Error`

1. `principal` MUST be a freshly resolved Principal (not cached).
2. Throttle by `("pwchange", principal.id)`; verify `currentPassword` via `PasswordHasher.verify` (equal-cost path not required since the user is known; but failures MUST count toward the throttle and MUST be `INVALID_CREDENTIALS`).
3. Validate `newPassword` (policy; MUST differ from the current one).
4. In one serializable unit: `put`; `bumpSecurityVersion`; revoke all of the user's sessions **except the caller's current session**, or all sessions if `revokeCurrentOnPasswordChange = true`. If the current session is retained, subsequent credentials issued for it MUST carry the new `securityVersion`: the implementation MUST therefore re-issue the access token (and, where `sv` is embedded in the session, update `securityVersionAtIssue`), or rotate to a new session.
5. After commit: notify and audit `password.changed`.
