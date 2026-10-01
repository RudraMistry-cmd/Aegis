# Conformance report — Phase 1

This document maps the implemented tests to the case ids of [`spec/conformance.md`](../spec/conformance.md),
and records every place where the Phase 1 reference implementation deliberately deviates from the
specification or cannot verify a case in memory.

Run them with `npm test` (121 tests: 60 unit, 61 conformance-labelled).

## 1. Claimed profiles

| Profile | Claim | Notes |
|---|---|---|
| **P-AUTHZ** | partial | RBAC, policy, scope, assignments, escalation guards and catalog validation are implemented and tested. Scoped (tenant) assignments and dynamic roles are not (D-4, D-5). |
| **P-AUTHN** | partial | Login, refresh, revoke and request resolution are implemented. Email verification, password reset and change-password are not (D-3). |
| **P-TRANSPORT-TOKEN** | partial | A MAC-protected stub access token plus opaque rotating refresh tokens. The JWT profile and key rotation are not implemented (D-1). |
| **P-TRANSPORT-SESSION** | not claimed | Only the token transport exists in Phase 1. |
| **P-STORE-FULL** | single-process only | The in-memory adapter provides A1 and A2 within one process (D-6). |

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

Each deviation is also marked with a `TODO` or a note in the source file named below.

**D-1 — Access tokens are a stub, not JWTs.** `src/auth/accessToken.ts` implements a compact
MAC-protected format (`at1.<payload>.<mac>`). It honours the normative parts of
`spec/auth/tokens.md` §2.2–§2.5 (claim set, type/issuer/audience discrimination, leeway bounds,
never throwing, verifying the MAC before trusting a claim) but not the JWT profile of §2.6 or the
`KeyProvider`/`kid` rotation of §6. `TOK-ACC-05`–`TOK-ACC-09`, `TOK-ACC-14` and `TOK-ACC-15` are
therefore not claimed. The Phase 1 brief asks for exactly this stub.

**D-2 — `eventual` revocation is not implemented; `strict` semantics always apply.**
`spec/auth/tokens.md` §2.5 lets `eventual` mode accept the access token of a revoked session until
its `exp`. That contradicts `INV-SESS-01` ("a credential referring to a missing, revoked, or expired
session never yields a Principal"). Phase 1 resolves the conflict in favour of the invariant and
fails closed: `resolve` always checks the session and `securityVersion`. The `tokens.revocation`
setting is accepted and reported by `describe()` for forward compatibility but changes no behaviour,
so `REV-11` and `TOK-ACC-16` are not claimed. See the class note in `src/auth/resolve.ts`.
**This conflict should be settled in the spec before Phase 2.**

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

**D-9 — Housekeeping deletions are unimplemented.** `deleteTerminalBefore` /
`deleteExpiredBefore` (`spec/storage/interfaces.md` §5, §6, §7) are marked `TODO`. Expiry is always
derived from timestamps at read time, so no behaviour depends on them; `SESS-06` and `STO-RT-07`
are not claimed.

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
