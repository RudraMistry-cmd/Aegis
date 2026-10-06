# Conformance report — Phases 1 to 3.5

This document maps the implemented tests to the case ids of [`spec/conformance.md`](../spec/conformance.md),
and records every place where the implementation deliberately deviates from the specification or
cannot verify a case.

- **Phase 1** (in-memory reference): `npm test` — 121 tests (60 unit, 61 conformance-labelled).
- **Phase 2** (PostgreSQL adapter): `npm run test:pg` — 103 tests against a real PostgreSQL 17,
  listed in §6. Design and guarantees: [POSTGRES.md](POSTGRES.md).

## 1. Claimed profiles

| Profile | Claim | Notes |
|---|---|---|
| **P-AUTHZ** | partial | RBAC, policy, scope, assignments, escalation guards and catalog validation are implemented and tested. Scoped (tenant) assignments and dynamic roles are not (D-4, D-5). |
| **P-AUTHN** | partial | Login, refresh, revoke and request resolution are implemented. Email verification, password reset and change-password are not (D-3). |
| **P-TRANSPORT-TOKEN** | **claimed** | JWT access tokens (RS256 or HS256) with `kid`-based key rotation, plus opaque rotating refresh tokens. See §7. |
| **P-TRANSPORT-SESSION** | not claimed | Only the token transport exists in Phase 1. |
| **P-STORE-FULL** | **claimed (PostgreSQL)** | The PostgreSQL adapter provides A1/A2 across processes and passes the storage-contract and race cases of §6. Isolation per spec §11.1: READ COMMITTED with ordered row locks; SERIALIZABLE optional. The in-memory adapter provides A1/A2 within one process only. |

Optional features: `hierarchy`, `deny`, `wildcards`, `multiRole` and `reuseGrace` are implemented.
`directGrants`, `dynamicRoles` and assignment `scope` are **inert** — configuring them is rejected,
which is the behaviour the spec requires of an unclaimed feature (`CFG-03`).

## 2. Implemented conformance cases

### P-AUTHZ — `test/conformance/authz.conformance.test.ts`

| Case | What it checks |
|---|---|
| `AZ-RBAC-01` | A flat role holds exactly its own permissions |
| `AZ-RBAC-02` | A subject with no assignments is denied everything |
| `AZ-RBAC-04` | Inheritance resolves transitively (admin → editor → viewer) |
| `AZ-RBAC-07` | `user:*` covers registered actions; an unregistered resource is `unknown_permission` |
| `AZ-RBAC-11` | Permission strings are never case- or whitespace-normalized |
| `AZ-RBAC-12` | An assignment to an unknown role contributes nothing |
| `AZ-RBAC-20` | `can`, `authorize`, `assert` and `permissionsFor` agree across the full product |
| `AZ-DENY-01` | A deny overrides a wildcard allow, for that permission only |
| `AZ-DENY-03` | A superuser is not exempt from an explicit deny |
| `AZ-DEF-01` | An unregistered permission denies with `unknown_permission` and is audited |
| `AZ-DEF-02` | A malformed action is a deny value from `can`/`authorize`, `FORBIDDEN` from `assert` |
| `AZ-DET-01` | 50 identical requests give an identical effect and reason |
| `POL-01` | The ownership rule allows only the owner |
| `POL-ERR-02` | A rule returning `undefined` denies with `policy_error` |
| `POL-WALL-01` | A wall denies even when a `rbacOrPolicy` resource policy would allow |
| `SCP-01` | Scope soundness and completeness against `authorize` over 60 resources |
| `SCP-08` | Absent-field semantics: `eq` false, `not(eq)` true, no type coercion |
| `ASG-01` | Assigning twice reports `unchanged` and audits once; unassign is idempotent |
| `ASG-04` | An assignment is inactive exactly at `expiresAt`; a past expiry is rejected |
| `ESC-02` | Self-assignment is `ESCALATION_DENIED` |
| `ESC-03` | The grant ceiling blocks assigning beyond the actor's own grants |
| `ESC-09` | The last superuser cannot be removed |
| `ESC-12` | Forged `roles`/`permissions` fields on a subject change no decision |
| `MID-01` | A role added mid-session is live on the next decision, same token |
| `MID-02` | A role removed mid-session denies immediately, although the token stays valid |
| `CFG-01` | One `CONFIG_INVALID` reports every violation with a path and a rule |

### P-AUTHN — `test/conformance/authn.conformance.test.ts`

| Case | What it checks |
|---|---|
| `AUTH-01` | A valid login yields credentials, one session and both audit events |
| `AUTH-05` | A second login creates an independent session |
| `AUTH-ENUM-01` | Unknown identifier, wrong password, malformed identifier and oversize password are byte-identical responses |
| `AUTH-ENUM-05` | The account state is revealed only after a correct password |
| `AUTH-TIM-01` | Exactly one hasher operation per attempt; none on the oversize-password path |
| `AUTH-THR-01` | A blocked identifier is rejected before any lookup or hashing, and the block expires |
| `AUTH-THR-03` | Throttle counters move identically for existing and unknown identifiers |
| `PRN-02` | A serialized Principal carries no password, hash or token |
| `PRN-04` | `resolve` returns `null` for every credential problem, never an error |
| `TOK-ACC-10` | Neither token kind is accepted in the other's place |
| `TOK-ACC-11` | A 17-input malformed-token battery always rejects and never throws |
| `TOK-ACC-12` | The claim set is exactly `iss aud sub sid iat exp jti sv typ` — no roles, no PII |
| `TOK-REF-02` | No raw refresh token exists in any table or audit event |
| `REF-04` / `REF-05` | Replaying a used token revokes the family and session, alerts `high`, kills the successor |
| `REF-06` | An expired refresh token reports `TOKEN_EXPIRED` and does not revive the session |
| `REF-17` | Reuse, unknown and revoked tokens produce identical responses |
| `REV-04` | After revocation returns, refresh fails immediately with no clock advance |
| `REV-05` | Revoking twice succeeds, changes nothing and audits once |
| `SESS-07` | The oldest session is evicted with its refresh token |
| `SESS-10` | Another user's session id is indistinguishable from an unknown one |
| `TIME-01` | Expiry boundaries are inclusive of the instant, with no housekeeping |
| `ERR-01` | Every code carries its fixed message and no variable data |
| `ERR-02` | A driver error surfaces as `STORAGE_UNAVAILABLE` with the cause stripped |

### RACE and storage atomicity — `test/conformance/race.conformance.test.ts`

| Case | What it checks |
|---|---|
| `RACE-01` / `STO-ID-02` | 20 concurrent registrations create exactly one user, identifier and credential |
| `RACE-02` / `REF-03` / `STO-RT-01` | Exactly one of 25 concurrent refreshes wins; the family ends revoked |
| `RACE-03` / `STO-RT-05` | Refresh racing revocation, 25 schedules: no token survives a revoked session |
| `RACE-06` / `STO-SES-01` | 30 parallel logins never exceed the session limit |
| `RACE-06b` | The `reject` limit policy never exceeds the limit either |
| `RACE-07` | Parallel logins racing a suspension leave no usable credential |
| `RACE-08` / `ESC-06` | Concurrent assign and authority-revoke cannot leave an escalated state |
| `RACE-09` / `STO-USR-03` | 100 concurrent `bumpSecurityVersion` calls lose no update |
| `STO-UOW-01` | A failure inside a unit of work persists nothing |
| `STO-RT-02` | `consume` follows the documented precedence and changes nothing but on success |
| `STO-SES-02` | `revoke` returns true once; the first reason and timestamp win |

Mandatory Phase 1 behaviours also have focused unit tests in `test/unit/`:
`login.test.ts`, `refresh.test.ts` (rotation and the reuse attack), `revoke.test.ts`,
`rbac.test.ts` (resolution, inheritance, deny precedence) and `policy.test.ts` (permission denial,
fail-closed policy errors, scope).

## 3. Deviations from the specification

Each deviation is also marked with an "Out of scope for Phase 1" note in the source file named below.

**D-1 — Access tokens: resolved in Phase 3, no longer a deviation.** The stub is gone.
`src/auth/jwt/` implements the JWT profile of `spec/auth/tokens.md` §2.6 and the key rotation of §6
(§7 below). The KeyProvider methods are named `getActiveKey` / `getKeyById` rather than the spec's
`active` / `get`; the contract is the same.

**D-2 — Revocation semantics: resolved, no longer a deviation.**
`spec/auth/tokens.md` §2.5 now specifies strict revocation only, consistent with `INV-SESS-01`.

- **Strict revocation enforced.** `resolve` checks the session and `securityVersion` on every
  request, reading the authoritative store.
- **Tokens invalid immediately after revoke.** Access and refresh tokens of a revoked session are
  rejected by the next request; there is no `exp`-bounded window.
- **No eventual consistency allowed.** There is no cache in front of the session check, and a
  configuration requesting `tokens.revocation: "eventual"` is rejected with `CONFIG_INVALID`.

**D-3 — One-time-token flows are absent.** Email verification, password reset and change-password
(`spec/flows/login.md` §6.2–§6.5) need the `Notifier` port, which the Phase 1 brief excludes. There
is no `OneTimeTokenStore` implementation, so `OTT-*`, `VER-*`, `RST-*` and `CHG-*` are not claimed.
The token contract itself (`spec/auth/tokens.md` §4) is unimplemented rather than violated.

**D-4 — Scoped assignments are rejected, not evaluated.** `spec/rbac/assignments.md` §3.2 allows an
implementation that does not support scopes, provided a non-null `scope` is rejected with
`VALIDATION_FAILED`; that is what `src/rbac/resolver.ts` and the assignment service do. `TEN-01`–
`TEN-05` are not claimed. The `scope` column exists in the record type, so adding support later is
additive.

**D-5 — `directGrants` and `dynamicRoles` are inert.** Configuring either is rejected at
construction (`CFG-03`). `ASG-11`, `ASG-12` and `ESC-11` are not claimed.

**D-6 — `countActiveHoldersOfSuperuserRoles` is computed, not a port method.**
`spec/storage/interfaces.md` §8.2 declares that method on `AssignmentStore`. Phase 1 computes the
same value from `listSubjectsByRole` inside the serialized unit of work, keeping the store free of
catalog knowledge; the last-superuser guarantee is unchanged. See `src/rbac/assignmentService.ts`.

**D-7 — Administrative credential invalidation requires `account:setstatus`.**
`spec/flows/revoke.md` §3.4 names that reserved permission and permits a project-specific one.
Phase 1 requires the reserved permission and does not add a new one.

**D-8 — No caching layer.** `spec/rbac/assignments.md` §7 permits a cache with a bounded TTL;
Phase 1 reads the store on every resolution. This is stricter than the spec (zero staleness), so
`MID-03`'s multi-instance staleness bound is not applicable and is not claimed.

**D-9 — Housekeeping deletions are not port methods.** `deleteTerminalBefore` /
`deleteExpiredBefore` (`spec/storage/interfaces.md` §5, §6, §7) are out of scope for Phase 1 and absent from the ports. The
PostgreSQL adapter offers `storage.housekeep(cutoff)` as an adapter-level operation (tested). Expiry
is always derived from timestamps at read time, so no behaviour depends on deletion.

**D-10 — PostgreSQL isolation: resolved, no longer a deviation.** `spec/storage/interfaces.md`
§11.1 now makes READ COMMITTED with `SELECT … FOR UPDATE` on critical rows and deterministic lock
ordering the default, and SERIALIZABLE optional with retry handling. The PostgreSQL adapter does
exactly that; POSTGRES.md §1 explains the strategy and the measured reason.

## 4. Atomicity: what the in-memory adapter can and cannot prove

`src/storage/memory/database.ts` documents the model. In short:

- **A1 (linearizable single-record) holds structurally.** Node runs the adapter on one thread and
  every store method performs its whole read-modify-write synchronously, never awaiting mid-way. Two
  callers therefore cannot interleave *inside* one operation. This is how `consume` can guarantee
  exactly one winner (`INV-TOK-02`).
- **A2 (atomic group) is simulated by serializing transactions** with a promise-chain mutex, plus a
  deep snapshot restored on failure. Nesting is detected per async context with `AsyncLocalStorage`,
  so an unrelated concurrent transaction never joins another's (and so cannot be rolled back with
  it). Serializing is stricter than the serializable isolation §11.3 asks for.
- **What cannot be proven here:** multi-process or multi-host contention, lost acknowledgements from
  a real driver, replica lag (`STO-CONS-01`), and the fault-injection cases of `STO-FAIL-02`/`-03`.
  Those need a real adapter; `STO-FAIL-01`, `-04` and `-05` are partially exercised by `ERR-02`.
- **Conservative behaviour where atomicity is uncertain:** any storage failure is reported as
  `STORAGE_UNAVAILABLE` and no credential is issued, and any inability to confirm a revocation is a
  failure rather than a success (`spec/flows/revoke.md` §6).

## 5. Bugs this exercise found

Two defects were found by the conformance cases rather than by review, which is the point of the
suite:

1. **`consume` and `rotate` had to be one unit of work.** With them separate, a losing concurrent
   refresh could trip reuse detection and revoke the session *before* the winner finished rotating,
   so `REF-03`/`RACE-02` saw zero winners instead of one. `src/auth/refresh.ts` now runs steps 4–9
   in a single transaction that returns a verdict instead of throwing, so a rejection cannot roll
   back the revocations it performed.
2. **The in-memory `UnitOfWork` detected nesting with an instance counter.** Any transaction started
   while another was in flight joined it, so a rollback in one discarded the other's committed
   writes — `RACE-03` caught a revocation being undone. It now uses `AsyncLocalStorage`.

## 6. Phase 2 — PostgreSQL adapter cases

All run by `npm run test:pg` against a real server, each file on its own fresh database.

### Storage contract, on both adapters — `test/postgres/contract.pg-test.ts` (25 × 2)

Each case runs against the in-memory adapter **and** PostgreSQL; a behavioural difference is a bug in
one of them: `STO-USR-01`, `STO-USR-02`, `STO-USR-04`, `STO-DATA-03`, `STO-ID-01/03`,
`STO-CRED-01`, `STO-SES-01`, `STO-SES-01b` (reject, duplicate id), `STO-SES-01c` (expired sessions
do not count), `STO-SES-02`, `STO-SES-03`, `STO-SES-04` (including no resurrection of an expired
session), `STO-SES-07`, `STO-RT-02`, `STO-RT-03`, `STO-RT-04`, `STO-RT-05`, `STO-RT-06`,
duplicate digest, `STO-ASG-01`, `STO-ASG-02`, `STO-ASG-03`, `STO-CAT-01`, `STO-UOW-01`,
`STO-UOW-03`.

### Concurrency, under READ COMMITTED and SERIALIZABLE — `test/postgres/concurrency.pg-test.ts` (13 × 2)

| Case | Concurrency | Invariant checked on committed state |
|---|---|---|
| `STO-RT-01` consume | 50 × one token | exactly 1 `consumed`, 49 `reused` |
| `REF-03` / `RACE-02` | 25 refreshes × one token | exactly 1 success; family revoked; 0 active tokens |
| `RACE-06` / `STO-SES-01` | 40 logins, limit 3, evict | exactly 3 active |
| `RACE-06b` | 30 logins, limit 3, reject | exactly 3 created, 27 `limit_reached` |
| `RACE-06c` | 20 full logins | no active token belongs to a revoked session |
| `RACE-03` / `STO-RT-05` | refresh ∥ logout, 40 rounds | session revoked; 0 active tokens; refresh only `OK` or `TOKEN_INVALID`; a winning refresh's token is already dead |
| `RACE-07` | 12 logins ∥ suspension | 0 active sessions, 0 active tokens |
| `RACE-01` | 20 registrations, one email | exactly 1 identifier |
| `ESC-09` race | remove both superusers at once | exactly 1 removal succeeds, 1 `ESCALATION_DENIED` |
| `RACE-08` / `ESC-06` | assign ∥ assigner losing authority | no escalated role |
| `STO-ASG-01` race | 30 identical assigns | 1 `created`, 29 `unchanged` |
| `RACE-09` / `STO-USR-03` | 100 `bumpSecurityVersion` | exactly +100 |
| `STO-USR-02` race | 20 `setStatus`, one version | exactly 1 applies |

Stable over repeated runs; READ COMMITTED needed 0 retries in every run, SERIALIZABLE 388–473.

### Transactions and integrity — `test/postgres/transactions.pg-test.ts` (16)

Rollback of every write; refusal to commit a unit that swallowed a database error (reporting the
first cause); retry of a serialization abort with `fn` re-executed; ambient routing without
self-deadlock; rejection of a query after its unit finished; error mapping with driver text stripped
(`ERR-02`); unreachable server gives `STORAGE_UNAVAILABLE`; bounded lock wait; schema refusals for
session resurrection (`INV-SESS-02`), immutable session fields (`INV-SESS-04`), token reactivation
and family forks (`INV-TOK-02`), and audit modification (`INV-AUD-02`); contained audit failures;
idempotent migrations; housekeeping; id non-reuse (`INV-ID-01`, which the in-memory adapter does not
provide).

### End-to-end flows — `test/postgres/flows.pg-test.ts` (11)

`AUTH-01`, `AUTH-ENUM-01`, `REF-01`, `REF-04/05`, `REV-04/05`, `SESS-07`, logout-all,
`MID-01/02`, `ESC-03/09`, `TIME-01` (exact to the millisecond) and `INV-CRED-01`, through
`createAuth`, with audit events persisted to PostgreSQL.

### Bugs Phase 2 found

1. **`AssignmentService` emitted audit events inside its unit of work** (§11.4). Harmless in memory,
   which never retries; on a real database a retried or rolled-back unit would duplicate or orphan
   the event. Now emitted after commit.
2. **The in-memory `touch` could extend an idle-expired session** (§5.5, INV-SESS-02). Found while
   writing the PostgreSQL query; fixed, and covered by the shared contract test.
3. **The PostgreSQL runner relabeled errors thrown by `fn` as `STORAGE_UNAVAILABLE`**, and reported
   the last `25P02` instead of the first real failure. Both caught by the transaction tests before
   release; the contract test now pins that a unit's own error propagates unchanged on both adapters.

## 7. Phase 3 — JWT access tokens and key rotation

`src/auth/jwt/`: `JwtAccessTokenProvider` (RS256 or HS256, `node:crypto` only, no new dependency) and
`InMemoryKeyProvider` (`kid`-indexed keys, statuses `pending` / `active` / `retired`). Every
existing suite now runs on real JWTs: the test fixtures and the PostgreSQL harness use the JWT
provider, so all 123 Phase 1/2 unit and conformance tests and all 104 PostgreSQL tests exercise
genuine signing and verification.

**The JWT is a transport, never the authority.** `verify` proves only that this server issued the
token and that it is unexpired. `resolve` / `authenticate` then apply strict revocation on every
request: the session must exist, must be neither revoked nor expired, and the token's `sv` must
equal the user's current `securityVersion` (`tokens.md` §2.5). Tested with tokens that are still
cryptographically valid.

### Cases — `test/unit/jwt.test.ts` (32)

| Area | Cases |
|---|---|
| Basics, run for **both** HS256 and RS256 | valid token and exact claim set (`TOK-ACC-01`, `-12`); expiry exactly at `exp` and leeway (`TOK-ACC-02`); other key under the same kid, altered payload, altered signature (`TOK-ACC-04`); unknown kid, and a known kid that did not sign it (`TOK-ACC-07`) |
| Hardening | `alg: none` (`TOK-ACC-05`); HMAC-over-public-key algorithm confusion (`TOK-ACC-06`); `jku`/`jwk`/`x5u`/`crit`/`zip` headers (`TOK-ACC-14`); issuer, audience (incl. arrays) and type (`TOK-ACC-08`/`-09`/`-10`); lifetime longer than the TTL, future `iat`/`nbf`, bad claim types; duplicate security claims; non-canonical base64url (two strings that decode to the same bytes); `verify` never throws |
| Strict revocation | valid JWT + revoked session → rejected; valid JWT + `sv` mismatch → rejected; valid JWT + expired session → rejected; `authenticate` maps to `UNAUTHENTICATED` / `TOKEN_EXPIRED` / `TOKEN_INVALID`; `TOKEN_EXPIRED` only for a genuine token (a forged expired token is `TOKEN_INVALID`); no internal detail in errors |
| Rotation (`TOK-ACC-15`) | old token valid after rotation, new tokens carry the new kid; a retired key verifies for exactly ttl + leeway, then is gone; a retired key cannot vouch for tokens issued after its retirement; two-phase stage → activate; removing a compromised key invalidates its tokens at once; kids are never reused; rotation can be disabled; key material never in metadata or errors |
| Configuration | every invalid setting reported at once; weak, placeholder, low-entropy, short or mismatched keys rejected (RSA < 2048 bits, HMAC < 32 bytes); exactly one active key; unique kids; core access TTL must equal the provider TTL |
| RS256 end to end | login → authenticate → refresh, and the token verifies with plain `node:crypto` and only the public key (interoperability) |

### Decisions

- **The server picks the algorithm.** A provider has one configured algorithm; a token whose `alg`
  differs is rejected before any key is touched, which rules out `none` and algorithm confusion.
- **Keys come only from this server.** Lookup is by `kid` among configured keys; `jku`, `jwk`, `x5u`
  and similar headers are rejected, never followed.
- **Signature before claims.** No claim is read until the signature verifies over the exact received
  bytes. `TOKEN_EXPIRED` is therefore only ever reported for a genuine token, so expiry is no oracle.
- **Retired keys have a bounded, backward-only life.** A retired key verifies for exactly
  `ttl + leeway` after retirement — every token it signed can live out its lifetime, and no longer
  (`tokens.md` §6.2) — and only for tokens issued before it was retired, so a leaked old key cannot mint
  new tokens. Kids are never reused.
- **Two-phase rotation for multiple processes.** `stage` (verify-only) everywhere, then `activate`
  (`tokens.md` §6.2 steps 1-2). A single process can `rotate`.
- **Standard NumericDate.** `iat`/`exp` are whole seconds (RFC 7519), so the TTL must be whole
  seconds; `createAuth` rejects a core `tokens.accessTtlMs` that differs from the provider's TTL.

### Test change

One Phase 1 test entry was specific to the stub's format: TOK-ACC-11's battery tampered with the
stub's `at1` prefix (`accessToken.replace('at1', 'AT1')`). A JWT has no such prefix, so the entry
became the untampered valid token. It now case-alters the JWT header segment, the equivalent tamper.

### Bug Phase 3 found (a Phase 2 race)

**A login could create an active session for an account suspended mid-login (INV-STATE-01).** The
login unit reads the account state with `users.getById` and only afterwards takes the per-user lock in
`createWithLimit`. Under READ COMMITTED a suspension could commit in that gap; the login then created
an active session, carrying the old `securityVersion`, for a suspended account. It was not
exploitable — `resolve` rejected the token on the `sv` mismatch and refresh on the account state — but
it broke the invariant and §11.1 rule 2. RACE-07 caught it intermittently after the change of token
provider shifted the timing (1 failure in about 20 runs). A new deterministic test in
`test/postgres/transactions.pg-test.ts` holds a login unit open in exactly that gap: it failed before
the fix (one active session) and passes after it. Fix, adapter only: inside a unit, `users.getById`
takes the user row lock. READ COMMITTED still needs zero retries.

---

## 8. Phase 3.5 — durable signing keys and JWKS

`KeyStore` port (`src/ports/index.ts`) with three adapters — PostgreSQL (`storage.keys`), a single-
process JSON file, and in-memory — plus `PersistentKeyProvider` and the JWKS handler
(`src/auth/jwt/`). Verification semantics are unchanged: signature first, then the session store on
every request. The existing Phase 3 suite (32 cases) passes unmodified against the refactored
`keyProvider.ts`.

### Cases

| File | Cases | What it proves |
|---|---|---|
| `test/unit/keystore.test.ts` | 28 | The shared contract (`test/support/keyStoreContract.ts`, 12 cases) on the memory and file adapters, plus file specifics: restart persistence, atomic replace with no temp files left, a failed `atomically` leaves the file untouched, a corrupt file is `STORAGE_UNAVAILABLE` and never overwritten |
| `test/unit/persistent-keys.test.ts` | 18 | Startup (generate only into an empty store; no active key → `CONFIG_INVALID`; rotation disabled; all config errors at once); tokens survive restart; rotate / retire / stage → activate / remove / prune; a second instance learns a rotation (unseen kid, refresh); no active key → signing fails closed and login leaves no session; strict revocation unchanged; encryption at rest, wrong/missing master key, ciphertext swap and public-half tampering detected, wrong key type refused |
| `test/unit/jwks.test.ts` | 7 | Exact members and headers; interoperability (a published JWK verifies a token with plain `node:crypto`); publication window (pending, active, retired-in-window, removed); no private material; static provider; HS256 refused; invalid path/TTL |
| `test/postgres/keys.pg-test.ts` | 23 | The contract on PostgreSQL; sign/verify across rotation; restart with a new pool; 8 concurrent first starts → one key; 10 instances rotating at once → one active, ten retired; concurrent activation of one kid; remove and prune; master key required; ciphertext only in `private_material`; schema guards (one active, frozen retired, no return to pending, no plaintext, no private members in the public column) |

Contract cases: pending on creation; kid never reused (also after `remove`); public-material
validation; activate retires the previous key at the same instant; activate idempotent / refuses
retired and unknown; activation instant before creation or before the current key's activation
refused; `markPending`; `retire` once; `remove` refuses the active key, `prune` only past the cutoff;
`atomically` all-or-nothing; 12 concurrent rotations → one active; 8 concurrent "create if empty" →
one key.

### Decisions

- **Fail closed at startup.** No active key, an undecryptable or mismatched key, more than one active
  key, a missing master key on PostgreSQL, or a malformed master key is `CONFIG_INVALID`.
  `generateIfMissing` generates only into a completely empty store.
- **Lifecycle is one-way:** pending → active → retired → (removed). New keys are always pending;
  nothing returns to pending; a retired key is never reactivated; a future `retiredAt` is refused.
- **Kids are registered forever**, in a registry that `remove` and `prune` never touch.
- **The JWKS publishes exactly what the server accepts**, pending keys included so caches warm before
  a key signs. HS256 is never published.
- **Clock skew is refused, not adjusted.** An activation instant earlier than the current key's
  activation would record an impossible lifecycle; it is `VALIDATION_FAILED` and changes nothing.
- **Deviations from the request:** the configuration lives under the existing top-level `keys`
  section (not `tokens.keys`); `keys.refreshIntervalMs` (default 30 s) was added because instances
  must learn rotations made elsewhere.

### Bugs Phase 3.5 found (in its own code, before release)

1. **Off-by-one in `prune`:** the store deletes `retiredAt < olderThan` while verification stops at
   `now ≥ retiredAt + grace`, so pruning with `now − grace` kept a dead key for one extra
   millisecond. Fixed (`now − grace + 1`); caught by `persistent-keys.test.ts`.
2. **Skewed activation:** the in-memory and file stores accepted an activation instant earlier than
   the current key's activation and recorded a retirement before activation; PostgreSQL's
   `time_order` CHECK refused the same call with a generic constraint error. Both now refuse it
   explicitly (contract case added); caught by the PostgreSQL contract run.
