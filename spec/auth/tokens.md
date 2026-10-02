# Aegis Spec — Tokens and Credentials Carriers

Status: Draft 0.1 · Normative
Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** are as defined in RFC 2119 / RFC 8174 when in capitals.

## 1. General requirements

1. A **token** is a bearer credential. Possession is sufficient to act, so every token class below defines its entropy, lifetime, storage and invalidation rules.
2. The authorization layer MUST NOT depend on any token format (INV-ARCH-01). Token formats are confined to a `SessionTransport` (`flows/login.md` §2).
3. All randomness for tokens MUST come from a cryptographically secure source through the `Random` port. Deterministic sources are permitted only in test fixtures.
4. Secrets MUST be compared in constant time.
5. A server-stored representation of a bearer secret (refresh token, session token, one-time token, API key) MUST be a **keyed or unkeyed cryptographic digest** with ≥ 256-bit output (the reference choice is SHA-256) of the high-entropy secret; the secret itself MUST NOT be stored, logged or audited. Slow password hashes MUST NOT be required for these (they are high-entropy); a project MAY additionally key the digest with a server secret.
6. Token verification failures MUST be externally indistinguishable (see `errors.md` §3 — external code `TOKEN_INVALID`), except that "expired" MAY be reported as `TOKEN_EXPIRED` for access tokens to enable client refresh behavior.

## 2. Access token

### 2.1 Purpose

A short-lived bearer credential proving that a particular Session was authenticated. It never substitutes for the Session: every acceptance is subject to the session check of §2.5.

### 2.2 Provider contract

```
AccessTokenProvider {
  issue(input: AccessTokenInput, now: Timestamp) -> IssuedAccessToken
  verify(token: String, now: Timestamp)          -> VerifiedAccessToken | VerifyFailure
}

AccessTokenInput {
  subjectId : Id
  sessionId : Id
  securityVersion : Integer
  ttl       : Duration
}
IssuedAccessToken   { token: String, jti: Id, issuedAt: Timestamp, expiresAt: Timestamp }
VerifiedAccessToken { subjectId: Id, sessionId: Id, securityVersion: Integer,
                      jti: Id, issuedAt: Timestamp, expiresAt: Timestamp }
VerifyFailure       = "malformed" | "bad_signature" | "unknown_key" | "expired" | "not_yet_valid"
                    | "wrong_issuer" | "wrong_audience" | "wrong_type" | "unsupported_algorithm"
```

`verify` MUST NOT throw for any input (including 0-length, megabytes-long, non-text, or adversarial input); it MUST return a `VerifyFailure`. It MUST complete in time linear in the input length and MUST impose a maximum accepted token length (default 8 KiB; larger → `malformed`).

### 2.3 Logical claims (format-neutral)

| Claim | Meaning | Required |
|---|---|---|
| `iss` | issuer identifier (configured string) | MUST |
| `aud` | audience (configured string or list; verifier MUST require a configured audience to be present) | MUST |
| `sub` | subject id | MUST |
| `sid` | session id | MUST |
| `iat` | issued-at | MUST |
| `exp` | expiry | MUST |
| `nbf` | not-before | MAY (if present MUST be enforced) |
| `jti` | unique token id | MUST |
| `sv` | user's securityVersion at issue | MUST |
| `typ` | token type discriminator; MUST be a value distinct from every other token class (e.g. access vs. refresh) | MUST |

Constraints:

1. `exp − iat` MUST equal the configured access TTL (± 1 s). Default TTL **10 minutes**. Configured TTL MUST NOT exceed 60 minutes unless the project sets an explicit `allowLongAccessTtl` override, which MUST cause a `config.warning` audit event at start-up.
2. Claims MUST NOT include: PII (email, name), roles, permissions, tenant authorization data, or secrets.
3. `verify` MUST reject a token whose `typ`, `iss` or `aud` do not match configuration, even when the signature is valid.
4. `verify` MUST allow clock-skew leeway of at most 60 seconds for `exp`, `nbf`, and `iat`; the leeway MUST be configurable and MUST NOT exceed 60 s.
5. Unknown or duplicate claims in security-relevant positions (`sub`, `sid`, `exp`, `typ`, `aud`, `iss`) MUST cause rejection as `malformed`. Unknown *additional* claims MUST be ignored.
6. A token MUST NOT be accepted merely because it decodes; the signature (or MAC) MUST be verified *before* any claim is trusted or used for any lookup.

### 2.4 No authorization data in tokens

Access tokens MUST NOT carry roles or permissions by default. The authorization layer resolves roles and permissions server-side at decision time (`rbac/assignments.md` §6). Consequently, a role or permission change takes effect for existing sessions without re-issuing tokens (INV-AUTHZ-06). An implementation MAY offer an opt-in "roles hint" claim for *downstream non-authoritative use* but the authorization engine MUST NOT consult it.

### 2.5 Revocation Semantics

Aegis enforces **strict** revocation. There is exactly one mode.

1. **Revoked sessions invalidate tokens immediately.** Once a revocation has committed, every token
   bound to that session — access tokens and refresh tokens alike — is invalid for every request that
   begins afterwards. There is no exposure window bounded by `exp`.
2. **Tokens MUST NOT be accepted after session revoke.** A valid signature and an unexpired `exp` are
   necessary but never sufficient. After `verify`, request resolution MUST check, for every request,
   that (a) the session exists and is neither revoked nor expired, and (b) the token's `sv` equals
   the user's current `securityVersion` (`principal.md` §7.2).
3. **The Session is the single source of truth.** These checks MUST read the authoritative store. They
   MUST NOT be answered from a cache, a replica, or any other copy that can lag a committed
   revocation, and token contents MUST NOT stand in for the Session's state.
4. **Eventual revocation is NOT supported.** An implementation MUST NOT offer a mode in which a token
   of a revoked session is accepted until its `exp`. A configuration requesting any revocation mode
   other than `"strict"` MUST be rejected at construction with `CONFIG_INVALID`.

This is what `INV-SESS-01` requires ("a credential referring to a missing, revoked, or expired session
never yields a Principal") and extends to access tokens the immediacy that `INV-TOK-06` already
requires of refresh. `describe()` MUST report `revocation: "strict"`.

### 2.6 JWT profile (informative mapping, normative for implementations that offer a "JWT" provider)

An implementation advertising a JWT access-token provider MUST additionally:

1. Use a header `typ` of `at+jwt` and use `typ`-discrimination to reject refresh/other tokens.
2. Verify using an **allow-list of algorithms configured on the server**; the token header's `alg` MUST NOT select the algorithm. `none` MUST never be accepted. Symmetric and asymmetric algorithm families MUST NOT both be enabled for the same key id (algorithm-confusion prevention). Asymmetric (EdDSA, ES256) is RECOMMENDED; HMAC is permitted only for single-verifier deployments.
3. Select the verification key by `kid` from the configured `KeyProvider` (§6); an unknown `kid` MUST yield `unknown_key` and MUST NOT trigger any outbound fetch.
4. Reject tokens with `crit` header parameters, embedded keys (`jwk`, `jku`, `x5u`, `x5c`) and `zip`.

## 3. Refresh token

### 3.1 Properties

1. Refresh tokens are **opaque**: they MUST NOT encode user data, and verification MUST be by store lookup of the digest.
2. A refresh token MUST contain at least **256 bits** of CSPRNG output.
3. A refresh token is **single-use**: each successful use MUST invalidate it and issue exactly one successor (rotation).
4. A refresh token belongs to exactly one **family**; a family is the chain of tokens issued from one login. `familyId = sessionId`. Family and Session MUST be revoked together (INV-TOK-05).

### 3.2 Record

```
RefreshTokenRecord {
  id            : Id
  hash          : Bytes                   digest of the token (§1.5); UNIQUE
  sessionId     : Id                      = family id
  userId        : Id
  parentId      : Id?                     absent for the first token of a family
  successorId   : Id?                     set when status = used
  status        : "active" | "used" | "revoked"
  revokedReason : "family_revoked" | "superseded" | "session_revoked" | "reuse_detected" | "expired_cleanup" ?
  createdAt     : Timestamp
  expiresAt     : Timestamp               idle expiry of this token
  usedAt        : Timestamp?              set when status = used
}
```

1. Status transitions are `active → used`, `active → revoked`, `used → revoked`. `used` and `revoked` MUST NOT return to `active`. 
2. At any time, for a given family, **at most one** record has `status = active`, except as permitted by the grace procedure (§3.5) where the superseded successor is atomically revoked in the same step.
3. `expiresAt = min(now + refreshIdleTtl, session.absoluteExpiresAt)` at issue. Default `refreshIdleTtl` = 14 days. No token may outlive the session's `absoluteExpiresAt`.

### 3.3 Rotation (summary; full procedure in `flows/refresh.md`)

On presenting token `T`:

1. Compute `h = digest(T)`.
2. Perform one **atomic** `consume(h, now)` (`storage/interfaces.md` §6). Exactly one of N concurrent presentations of the same active token MUST obtain `consumed`; all others MUST observe `reused` (INV-TOK-02).
3. Only on `consumed` may the implementation proceed to issue a successor.

### 3.4 Reuse detection

If `consume` reports `reused` (the token had status `used`) the implementation MUST treat this as **possible theft**:

1. Unless the grace procedure (§3.5) applies, it MUST revoke the whole family **and** the Session (reason `refresh_reuse_detected`) before returning.
2. It MUST emit audit event `refresh.reuse_detected` with severity `high` including `sessionId`, `userId`, and the id of the reused token (never the token value).
3. It MUST return the external error `TOKEN_INVALID`. The response MUST NOT reveal that reuse was detected.

### 3.5 Optional reuse grace

Configuration `reuseGrace : Duration`, default **0** (disabled). Maximum permitted value: 10 000 ms.

Because only digests are stored, a lost response **cannot** be replayed bit-for-bit. The grace procedure therefore replaces, rather than replays, the successor:

1. Applies only if `reuseGrace > 0`, the token status is `used`, `now − usedAt ≤ reuseGrace`, and the family's session is still `active`, and the account state permits refresh.
2. The implementation MUST call `replaceActiveSuccessor(token.successorId, newRecord)` (atomic, `storage/interfaces.md` §6) which, in one step, marks the previous successor `revoked` with reason `superseded` **only if it is still `active`**, inserts `newRecord` as the new `active` successor with `parentId = token.id`, and sets `token.successorId = newRecord.id`.
3. If the previous successor is not `active` (it was already used — meaning the chain has advanced — or revoked), the grace does **not** apply and §3.4 applies in full.
3a. **In-flight case.** If the token is `used`, `now − usedAt ≤ reuseGrace`, and `successorId` is **unset** (the winning request has consumed the token but not yet completed rotation), the presentation MUST be answered with `TOKEN_INVALID` (flagged `retryable`) **without** revoking the family or Session. Once `now − usedAt > reuseGrace` with `successorId` still unset, §3.4 applies in full. With `reuseGrace = 0` there is no in-flight exemption: any presentation of a `used` token triggers §3.4, so clients MUST serialize refresh calls (single-flight).
4. A presentation of a token revoked with reason `superseded` MUST be rejected with `TOKEN_INVALID` and MUST NOT revoke the family or Session (benign race), but MUST be audited as `refresh.superseded_presented`.
5. Grace is a documented relaxation: an attacker who steals a token can obtain a successor if they replay within the window. Implementations MUST state this in their security documentation when enabling it.

### 3.6 Revocation

Revoking a family MUST (atomically with the session revocation, or such that no interval exists in which the session is revoked while a family token is usable) mark all of the family's `active` records `revoked` (`family_revoked`/`session_revoked`). Independent of that marking, the refresh procedure MUST check the **session** status (defense in depth; INV-TOK-06).

## 4. One-time tokens

Used for email verification, password reset, and future single-use flows.

```
OneTimeTokenRecord {
  hash      : Bytes          digest of the token; UNIQUE
  userId    : Id
  purpose   : "email_verify" | "password_reset" | (extension purposes)
  target    : String?        e.g. the identifier being verified
  createdAt : Timestamp
  expiresAt : Timestamp
  consumedAt: Timestamp?
}
```

1. Entropy MUST be ≥ 256 bits.
2. Default TTL: `email_verify` 24 h; `password_reset` 30 min. `password_reset` TTL MUST NOT exceed 60 min unless explicitly overridden with a `config.warning`.
3. A token is valid **only for its `purpose`**. Presenting it for another purpose MUST fail as `TOKEN_INVALID`.
4. **Single use, atomic**: `consume(hash, purpose, now)` MUST succeed for exactly one caller even under concurrency (INV-TOK-08). Subsequent presentations MUST fail as `TOKEN_INVALID`.
5. Issuing a new token for `(userId, purpose)` MUST invalidate previously issued unconsumed tokens for the same `(userId, purpose, target)`.
6. The raw token MUST be delivered only via the `Notifier` port; it MUST NOT be returned to the caller of the "request" operation (no oracle) and MUST NOT be audited or logged.

## 5. Opaque session token (server-side session transport)

1. The credential is a random string with ≥ 256 bits of entropy; the Session's server-side lookup key is its digest (§1.5). (The Session `id` MAY be a distinct, non-secret value.)
2. Each request resolution MUST consult the authoritative store, so revocation is immediate (§2.5).
3. Rotation of the session token on privilege change (e.g. step-up) MAY be offered; if offered it MUST invalidate the previous token atomically.
4. On login a **new** token MUST always be generated (INV-SESS-03).

## 6. Signing keys and key rotation

```
KeyProvider {
  active()       -> SigningKey                       // used to sign new tokens
  verification() -> List<VerificationKey>            // all keys currently acceptable for verify
  get(kid)       -> VerificationKey | null
}
SigningKey      { kid: String(1..64), algorithm: String, material: Secret }
VerificationKey { kid: String(1..64), algorithm: String, material: PublicOrSecret, notAfter: Timestamp? }
```

1. `active()` MUST be included in `verification()`.
2. Key rotation procedure (contract): (1) add the new key as verification-only, (2) after propagation delay make it active, (3) retain the previous key as verification-only for at least `accessTtl + leeway`, (4) remove it. No step may cause valid unexpired tokens to fail verification.
3. Key material MUST NOT appear in logs, audit events, errors, `describe()` output (shown as `[redacted]`), or serialized configuration.
4. At start-up the implementation MUST reject: key material shorter than the algorithm's recommended minimum (for HMAC: < 32 bytes); known placeholder values; a configuration with no active key. (`CONFIG_INVALID`.)
5. `kid` MUST be unique across the provider.

## 7. Credentials issued to clients

```
IssuedCredentials {
  accessToken?          : String          } present for access-token transports
  accessTokenExpiresAt? : Timestamp       }
  refreshToken?         : String          } present for access-token transports
  refreshTokenExpiresAt?: Timestamp       }
  sessionToken?         : String          } present for opaque-session transport
  sessionExpiresAt?     : Timestamp       }
}
```

1. Credentials are returned to the host **exactly once**, at issue. They MUST NOT be retrievable later from any API.
2. Issuance MUST be performed only after the Session is durably created.
3. If issuing any component fails after the Session was created, the implementation MUST revoke the newly created Session before reporting failure (no half-issued sessions).
