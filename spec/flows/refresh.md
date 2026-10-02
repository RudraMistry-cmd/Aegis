# Aegis Spec — Flow: Refresh-Token Rotation

Status: Draft 0.1 · Normative
Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** are as defined in RFC 2119 / RFC 8174 when in capitals.
Entities: `auth/tokens.md` §3, `auth/session.md`. Ports: `storage/interfaces.md` §5–§6. Errors: `errors.md`.

Applies to transports that issue refresh tokens. A transport using only an opaque session token has no refresh flow (`SessionTransport.renew` unsupported).

## 1. Inputs and outputs

```
refresh({ refreshToken: String, clientIp?: String, device?: DeviceInfo, requestId?: String })
  -> { credentials: IssuedCredentials, principal: Principal }
   | Error
```

The refresh token is the **only** authenticator. An access token (even valid) MUST NOT be accepted in its place and MUST NOT be required.

## 2. Main procedure

| # | Step | Security checks | Failure outcome |
|---|---|---|---|
| 1 | **Shape.** `refreshToken` is a string of length 1..512, otherwise `TOKEN_INVALID`. MUST NOT throw or touch the store for malformed input. | Over-length/empty/non-string ⇒ immediate rejection; no store call. | `TOKEN_INVALID` |
| 2 | **Throttle (SHOULD).** Optional `("refresh-ip", clientIp)` limiter, `peek` then `recordFailure` on any failure at steps 4–8. | A blocked client is rejected before step 3. Throttling MUST NOT depend on token validity. | `RATE_LIMITED` |
| 3 | **Digest.** `h = digest(refreshToken)` (`tokens.md` §1.5). | The raw token is discarded after digesting and MUST NOT be logged. | — |
| 4 | **Consume (atomic).** `RefreshTokenStore.consume(h, now)`. | Single linearizable step (`interfaces.md` §6.1). The result decides the branch below. | `STORAGE_UNAVAILABLE` |
| 4a | `unknown` ⇒ reject. | No hint distinguishes "never existed" from other invalid states. | `TOKEN_INVALID` |
| 4b | `expired` ⇒ reject. The token record exists (so the caller possesses a genuine secret); the **session** is not touched (it may be revoked lazily by expiry). | May report expiry (the secret was already known to the caller). | `TOKEN_EXPIRED` |
| 4c | `revoked` ⇒ reject. If `revokedReason = superseded`: audit `refresh.superseded_presented` and DO NOT escalate. Otherwise audit `auth.rejected` (sampled). Idempotently ensure the family is revoked. | MUST NOT reveal why. | `TOKEN_INVALID` |
| 4d | `reused` ⇒ **reuse procedure** (§3). | See §3. | `TOKEN_INVALID` |
| 4e | `consumed` ⇒ continue at step 5. The presented token is now spent: on **any** failure from step 5 onward, no new token has been issued and the client MUST re-authenticate (the implementation MUST also leave the session revoked or the family without an active token — §2.1). | — | — |
| 5 | **Session check.** `SessionStore.get(token.sessionId)` (R). Must exist, `token.userId == session.userId`, `status(session, now) = active`. | Missing, revoked, idle- or absolute-expired ⇒ ensure `revokeFamily` (idempotent) and reject. Identity mismatch between token and session ⇒ treat as corruption: revoke the session, audit `refresh.reuse_detected`-class event `refresh.integrity_failure` (high), reject. | `TOKEN_INVALID` |
| 6 | **Account check.** `UserStore.getById` (R). State definition: `canRefresh` MUST be `true`. | If false: revoke the session (reason `account_state`) and family, audit, reject. A user that no longer exists ⇒ revoke the session, reject. | `ACCOUNT_RESTRICTED` (state known only to a holder of a genuine token) or `TOKEN_INVALID` when the user was deleted |
| 7 | **Security-version check.** `user.securityVersion` MUST equal `session.securityVersionAtIssue`. | Mismatch ⇒ credentials were invalidated after this session was issued without it being revoked (anomaly): revoke the session, audit `high`, reject. | `TOKEN_INVALID` |
| 8 | **Mint successor.** New refresh token = ≥ 256-bit CSPRNG; record `{ parentId = token.id, sessionId, userId, status = active, expiresAt = min(now + refreshIdleTtl, session.absoluteExpiresAt) }`. | Successor MUST NOT outlive `session.absoluteExpiresAt`. If `min(...) ≤ now` the session is expired ⇒ reject (`TOKEN_EXPIRED`). | `TOKEN_EXPIRED` |
| 9 | **Rotate (atomic).** In one `UnitOfWork`: `RefreshTokenStore.rotate(token.id, successor)` and `SessionStore.touch(session.id, now, newIdleExpiresAt)`. | `rotate` MUST fail if the session is revoked in the meantime (closes revoke-vs-refresh race, INV-TOK-07). `PreconditionFailed` ⇒ reject with `TOKEN_INVALID`; **no credentials issued**. | `TOKEN_INVALID` |
| 10 | **Issue access token** (`tokens.md` §2) with `sid = session.id`, `sv = user.securityVersion`, `ttl = accessTtl`. | `authMethod`, `amr`, `authenticatedAt` of the resulting Principal come from the **session**, never from the request, and MUST NOT change (`principal.md` §2.1). | `INTERNAL` (if signing fails; the successor token is then unreachable — revoke the family) |
| 11 | **Respond** with the new access token and the **new** refresh token. Audit `refresh.succeeded` (SHOULD be sampled). | The old refresh token MUST NOT be accepted again. | — |

### 2.1 State after a failed rotation

After step 4e, if the process cannot complete steps 9–11, the family MUST be left in one of: (a) revoked together with its session, or (b) no `active` token (the consumed token is `used`, and no successor exists). Case (b) is permissible: it forces re-authentication. The family MUST NOT end up with an `active` token that the client has never received *and* that is not recoverable — such a token is simply unreachable (only a digest exists), so this is a harmless but wasteful state; the implementation SHOULD revoke it.

## 3. Reuse procedure (step 4d)

Triggered when `consume` returned `reused`.

1. **Grace evaluation** (only when `reuseGrace > 0`; `tokens.md` §3.5):
   1. If `successorId` is unset and `now − usedAt ≤ reuseGrace` ⇒ *in-flight*: reject `TOKEN_INVALID` (flag `retryable = true`), no revocation.
   2. If `successorId` is set, `now − usedAt ≤ reuseGrace`, and the session is `active` and the account `canRefresh`: perform steps 6–8 and then `replaceActiveSuccessor(token.successorId, replacement, token.id)`; on `replaced` continue at step 10; on `not_active` ⇒ continue at 2 below.
2. **Revoke.** In one serializable `UnitOfWork`: `SessionStore.revoke(token.sessionId, "refresh_reuse_detected")` and `RefreshTokenStore.revokeFamily(token.sessionId, "reuse_detected")`.
3. **Alert.** Audit `refresh.reuse_detected` (severity `high`) with `sessionId`, `userId`, `tokenId` (never the token value). The implementation MAY also send a `security_alert` notification to the user via `Notifier` (not awaited).
4. **Respond** `TOKEN_INVALID`. The response MUST be identical to step 4a (no reuse hint).
5. Any access token already issued for that session is rejected on its next use (strict revocation, `tokens.md` §2.5).

## 4. Concurrency guarantees

1. **Exactly one winner.** If N ≥ 2 requests present the same active token concurrently, exactly one proceeds past step 4 (`consumed`). All others observe `reused` and follow §3. With `reuseGrace = 0` they cause the family to be revoked — including the winner's successor. Clients MUST therefore perform refresh as *single-flight*. (This is a deliberate trade for theft detection; deployments with unreliable clients MAY set `reuseGrace` up to 10 s.)
2. **Refresh vs revoke.** Under concurrent `refresh` and `revokeSession`/`logout`: whichever commits first wins; after the revoke commits, no refresh may return credentials (step 9 fails, INV-TOK-07). A refresh that committed before the revoke yields tokens that are immediately revoked; its access token is rejected on its next use (`tokens.md` §2.5).
3. **Refresh vs role change.** A role/permission change is independent of refresh; the new access token carries no permissions, so subsequent authorization reflects the new assignments (INV-AUTHZ-06).
4. **Refresh vs account state change.** If the state change to `canRefresh = false` commits before step 6, the refresh fails; if after step 9 it commits, the state change revokes the session and the new tokens (INV-SESS-06).
5. **Crash safety.** A crash between steps 4 and 9 loses availability for that session only (§2.1), never safety.

## 5. Security checks (cross-cutting, MUST)

1. Rotation on **every** successful refresh: a response MUST NOT reuse the presented token.
2. The refresh token MUST NOT be accepted as an access token or session token and vice versa (distinct digest namespaces/format; `typ` discrimination for self-describing tokens).
3. No refresh token is ever stored or logged in raw form; only digests (`tokens.md` §1.5).
4. All timestamps from the injected `Clock`; refresh MUST NOT extend `absoluteExpiresAt`.
5. Error responses MUST NOT distinguish `unknown`, `revoked`, `reused`, session-missing and user-missing (they all return `TOKEN_INVALID`); only the genuine-possession cases `expired` (`TOKEN_EXPIRED`) and `ACCOUNT_RESTRICTED` (step 6) are distinguishable, and only after the token was recognized.
6. The refresh flow MUST NOT change `authenticatedAt` or `amr`; step-up is a separate flow (extension).
7. Refresh MUST NOT create a new Session (the session id is invariant across the lifetime of the family).
