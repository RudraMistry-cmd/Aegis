# Aegis Spec — Flow: Revocation, Logout, and Session Invalidation

Status: Draft 0.1 · Normative
Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** are as defined in RFC 2119 / RFC 8174 when in capitals.
Entities: `auth/session.md`, `auth/tokens.md`. Ports: `storage/interfaces.md` §2, §5, §6, §8.4, §11.

## 1. Definitions

* **Revocation** — making a Session (and with it, its refresh tokens) permanently unusable.
* **Session invalidation** — revocation of one or more sessions *plus*, where specified, an increment of `User.securityVersion`.
* **Causes** (the `RevocationReason` values of `session.md` §2): `logout`, `logout_all`, `admin`, `password_changed`, `password_reset`, `account_state`, `credentials_invalidated`, `refresh_reuse_detected`, `evicted`, `expired_cleanup`.

## 2. Common procedure `terminate(sessionSelector, reason)` (normative)

All revocation paths in this specification (logout, remote revoke, state change, password change/reset, reuse detection, eviction, administrative) MUST be implemented by this procedure — directly or through the specific store operations it names — so that behavior is uniform.

1. **Open** a serializable `UnitOfWork` (`interfaces.md` §11).
2. **Revoke sessions:**
   * single: `SessionStore.revoke(sessionId, reason, now)` — returns whether *this* call revoked it;
   * all of a user: `SessionStore.revokeAllForUser(userId, except, reason, now)`.
3. **Revoke refresh families** of exactly the sessions affected: `RefreshTokenStore.revokeFamily(sessionId, reason)`; for the all-sessions form the store operation MUST cover every affected session in the same atomic step.
4. If the cause demands it (§4): `UserStore.bumpSecurityVersion(userId, now)`.
5. **Commit.** If the unit fails, **nothing** is revoked and the operation MUST report failure (`STORAGE_UNAVAILABLE`); it MUST NOT report success.
6. **Post-commit effects** (MUST NOT be inside the unit; their failure MUST NOT undo the revocation; failures logged):
   1. Invalidate session/principal cache entries for each revoked session id and, for user-wide operations, for the user (`Cache.delete`, `publishInvalidate`).
   2. If an explicit denylist is configured: `RevocationStore.add(sessionId, now + accessTtl + leeway)` for each session.
   3. Audit exactly one `session.revoked` event per session **newly** revoked (based on the boolean/count returned in step 2; never for already-revoked sessions) with the reason; plus the cause-specific event (`logout`, `logout.all`, `session.evicted`, `account.state_changed`, `password.*`).
   4. Optional notifications (`Notifier`), never awaited.

## 3. Operations

### 3.1 Logout (current session)

`logout({ principal? | refreshToken? | sessionToken? }) -> LoggedOut`

1. Identify the target session:
   1. From a resolved Principal: `principal.sessionId`.
   2. From a presented refresh token: digest and call `RefreshTokenStore.consume`; if the result carries a record (`consumed`, `reused`, `revoked`, `expired`), the target is `record.sessionId`; if `unknown`, there is no target.
   3. From an opaque session token: digest → session lookup.
2. If a target exists, run `terminate(session, "logout")`. If no target exists (unknown, already revoked, malformed): **succeed without effect**.
3. **Idempotent and oracle-free:** `logout` MUST return the same success result whether the credential was valid, expired, unknown, or already revoked. It MUST NOT require the credential to be currently valid. It MUST NOT throw for malformed input.
4. A `logout` that fails in step 2 because of infrastructure failure MUST return `STORAGE_UNAVAILABLE` rather than success (the host SHOULD still clear client-side credentials and tell the user the sign-out could not be confirmed).
5. A refresh token presented to logout is consumed; this is harmless as its family is revoked.
6. Authorization: logging out **one's own** session requires no permission.

### 3.2 Logout all / sign out other devices

`logoutAll(principal, { except?: sessionId, includeCurrent?: Boolean })`

1. Requires a freshly resolved Principal. Target user = `principal.id`.
2. `terminate(allOfUser except = (includeCurrent ? null : principal.sessionId), "logout_all")`.
3. Result includes the count revoked. Does **not** bump `securityVersion` (credentials unchanged) unless `includeCurrent = true` and the project configures `logoutAllBumpsSecurityVersion`.
4. Idempotent: a second call revokes 0 and succeeds.

### 3.3 Revoke a specific session (remote revoke)

`revokeSession(actor, sessionId, reason = "logout" | "admin")`

1. Look up the session (R). If it does not exist, or its `userId ≠ actor.id` and the actor lacks authorization, return `NOT_FOUND` — identical for both cases (`session.md` §7.4).
2. If the owner is another subject: `authorize(actor, "revoke", {type:"session", id, ownerId, tenantId})` MUST allow (permission `session:revoke`, subject to policies, in particular tenant walls). Reason recorded as `admin`.
3. `terminate(session, reason)`.
4. Revoking an already revoked session succeeds and changes nothing (idempotent).
5. A Principal MAY revoke its *own current* session through this operation; it is equivalent to logout.

### 3.4 Administrative invalidation of a user's credentials

`invalidateCredentials(actor, userId, { reason })`

1. `authorize(actor, "invalidate", {type:"account", id:userId, tenantId})` MUST allow (`account:setstatus` is reserved; projects MAY register a dedicated permission).
2. `terminate(allOfUser, "credentials_invalidated")` **with** step 4 (`bumpSecurityVersion`).
3. Subsequent logins are unaffected (the password is unchanged); the operation is for suspected token compromise.

### 3.5 Account state change

Defined in `principal.md` §6.2: entering a state with `canLogin = false` MUST run `terminate(allOfUser, "account_state")` **with** `bumpSecurityVersion`, in the **same** unit as `UserStore.setStatus`.

### 3.6 Password change / reset

Defined in `login.md` §6.4–6.5: uses `terminate(allOfUser [except current when permitted], "password_reset" | "password_changed")` with `bumpSecurityVersion`, in the same unit as the credential write.

### 3.7 Refresh-token reuse

Defined in `refresh.md` §3: `terminate(session, "refresh_reuse_detected")`.

### 3.8 Eviction

Defined in `session.md` §6: performed inside `createWithLimit` with reason `evicted`; its refresh families are revoked in the same atomic step.

### 3.9 Global emergency revocation

`revokeEverything(systemActor, { reason })` — MAY be offered. When offered:
1. It MUST be restricted to the reserved `system` actor or a Principal authorized with an explicit, separately registered permission and MUST emit a `high`-severity audit event.
2. It revokes every non-terminal session and refresh family in the store; it MAY be executed in batches, in which case each batch MUST follow §2 and the operation MUST be resumable and idempotent. Until it completes it MUST report `partial` status.
3. Signing-key compromise is handled by **key rotation** (`tokens.md` §6) — retiring the compromised `kid` immediately invalidates all access tokens signed with it; if refresh-token digests are also suspected leaked, run `revokeEverything`.

## 4. When `securityVersion` MUST be incremented

| Cause | Bump `securityVersion`? |
|---|---|
| Logout (single) | No |
| Logout all | No (default) |
| Remote revoke of one session | No |
| Password change / reset | **Yes** |
| Account enters `canLogin = false` state | **Yes** |
| Administrative `invalidateCredentials` | **Yes** |
| Refresh reuse for one session | No (only that session is revoked) — unless `reuseBumpsSecurityVersion = true` |
| Role / permission change | **No** (`principal.md` §3.2) |
| Eviction | No |

## 5. Visibility guarantees after a revocation call returns

Let *T* be the time at which the revoking call returned success.

1. **Refresh:** every refresh attempt that begins after *T* with any token of the revoked session(s) MUST fail (INV-TOK-06/07). This is **immediate**; it MUST NOT depend on cache TTLs.
2. **Access tokens and opaque session tokens:** a request that begins after *T* bearing any token of the revoked session(s) is rejected (`tokens.md` §2.5). This is **immediate**; there is no cache window and no `exp`-bounded grace. A request in progress when revocation commits MAY complete.
3. **Listing:** `listActiveByUser` after *T* MUST NOT include the revoked sessions.
4. **Idempotent replays** after *T* succeed without changes.

## 6. Failure modes

| Condition | Outcome |
|---|---|
| Storage failure during `terminate` | `STORAGE_UNAVAILABLE`; no partial revocation (atomic); caller may retry (`terminate` is idempotent) |
| Post-commit cache/denylist failure | Logged; revocation stands; staleness bounded by cache TTL |
| Audit sink failure | Logged; revocation stands (unless `auditFailureMode = fail-closed` for sensitive events, in which case the operation still revokes first, then reports failure of auditing) |
| Unauthorized remote revoke | `NOT_FOUND` (for non-existence/ownership) or `FORBIDDEN` (if the session is known visible but the permission lacks) — an implementation MUST choose one consistently; default `NOT_FOUND` |
| Target user does not exist | `NOT_FOUND` for admin operations; `logoutAll` by a Principal for a deleted user ⇒ success with 0 |

## 7. Security checks (cross-cutting, MUST)

1. **Atomicity:** session revocation and family revocation (and `securityVersion` bump where required) occur in one unit; there is no committed state where a session is revoked but one of its refresh tokens is usable (INV-TOK-05).
2. **No resurrection:** nothing in this flow, or any later flow, may reactivate a revoked session (INV-SESS-02).
3. **Idempotency / exactly-once audit:** repeated revocation produces exactly one `session.revoked` event per session.
4. **Authorization:** acting on others' sessions or credentials is evaluated by the authorization engine, including tenant walls; self-service needs no permission.
5. **No information leak:** results for non-owned/unknown sessions are indistinguishable.
6. **Fail closed:** any inability to confirm revocation is reported as failure, never success.
