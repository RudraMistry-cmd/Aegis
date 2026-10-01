# Aegis Spec — Invariants

Status: Draft 0.1 · Normative
Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** are as defined in RFC 2119 / RFC 8174 when in capitals.

An **invariant** is a property that MUST hold in **every reachable state** of a conforming implementation, under every interleaving of concurrent operations, every configuration permitted by this specification, and every failure listed in `storage/interfaces.md` §1.1 — not merely in the happy path. Invariants are *testable*: each lists the conformance groups (`conformance.md`) that attack it.

Notation: `INV-<AREA>-<NN>`. Severity: **SC** = security-critical (a violation is a vulnerability); **IC** = integrity-critical (a violation corrupts data/behavior); **OP** = operational guarantee.

An implementation that cannot uphold an invariant in some configuration MUST refuse to start in that configuration (`CONFIG_INVALID`) rather than run degraded.

---

## 1. Architecture and dependency invariants

| ID | Sev | Invariant | Tests |
|---|---|---|---|
| INV-ARCH-01 | SC | The authorization decision path (`rbac`, `policy`, decision engine) consumes **only** a `Subject` (`principal.md` §1). No authorization decision can depend on a token format, transport, session record, cookie, or authentication strategy. Replacing the transport MUST NOT change any `Decision` for the same Subject/state. | AZ-ARCH-01, X-SWAP-01 |
| INV-ARCH-02 | IC | The core depends only on the ports of `storage/interfaces.md`. No core behavior requires a specific database, framework, cache, cryptographic library or HTTP concept. | (structural; verified by dependency analysis in CI) |
| INV-ARCH-03 | SC | There is exactly **one** definition of "is permission *p* allowed for subject *s*" (`roles.md` §5, `allows`) and exactly one decision procedure (`policy.md` §5). Guards, `can`, `assert`, `authorize`, `permissionsFor`, and `authorizeScope` agree. | AZ-RBAC-20, SCP-01 |

## 1a. Principal invariants

| ID | Sev | Invariant | Tests |
|---|---|---|---|
| INV-AUTH-01 | SC | A Principal is produced only by successful authentication or request resolution, is immutable, is never cached across requests, and its `authMethod`, `amr`, `authenticatedAt` derive solely from the session record. It never carries a secret. | PRN-02, PRN-03, PRN-06, PRN-10 |

## 2. Identity and credential invariants

| ID | Sev | Invariant | Tests |
|---|---|---|---|
| INV-ID-01 | IC | A `User.id` is never reissued to a different identity, including after deletion. | ID-05 |
| INV-ID-02 | IC | `(identifier.type, identifier.normalized)` is unique across all users at all times, including under concurrent registration. | ID-02, STO-ID-02, RACE-01 |
| INV-ID-03 | IC | Normalization is deterministic and identical at every call site; two spellings that normalize equally are one identifier. | ID-01 |
| INV-CRED-01 | SC | Plaintext passwords are never persisted, logged, audited, returned, or placed in a Principal, error, or trace. Password hashes and credential payloads are never exposed outside the identity component. | AUTH-SEC-01, AUD-03 |
| INV-CRED-02 | SC | Every stored password hash is salted with a unique random salt and produced by an algorithm meeting `principal.md` §5.1. Two hashes of the same password differ. | CRED-01 |
| INV-CRED-03 | SC | A user has at most one `password` credential; a replacement never leaves a window with none or two visible to readers. | STO-CRED-01 |
| INV-STATE-01 | SC | An account in a state with `canLogin = false` has **no** active session and no usable refresh token, from the instant the state change commits (atomic). | STATE-03, RACE-07 |
| INV-STATE-02 | IC | Only transitions in the configured transition table are applied; each is version-checked. | STATE-01, STATE-02 |

## 3. Token invariants

| ID | Sev | Invariant | Tests |
|---|---|---|---|
| INV-TOK-01 | SC | No bearer secret (refresh token, session token, one-time token, API key) is stored in recoverable form; only digests (`tokens.md` §1.5). | TOK-REF-02 |
| INV-TOK-02 | SC | A refresh token is accepted **at most once**. For N concurrent presentations of one active token, exactly one obtains a successor; no two successors descend from one token (outside the defined grace replacement, which supersedes the earlier). | RACE-02, REF-03, STO-RT-01 |
| INV-TOK-03 | SC | Presentation of a `used` refresh token outside the grace procedure results in revocation of the entire family **and** session, plus a `high` audit event. | REF-04, REF-05 |
| INV-TOK-04 | SC | No token outlives the absolute expiry of its session; no operation extends `absoluteExpiresAt`. | SESS-04, REF-11 |
| INV-TOK-05 | SC | There is never a committed state in which a session is revoked while any refresh token of that session is `active` (and, conversely, family revocation implies session revocation). | REV-02, RACE-05 |
| INV-TOK-06 | SC | After a revoking operation returns, every subsequent refresh attempt with any token of the revoked session fails, immediately and independent of caches. | REV-04 |
| INV-TOK-07 | SC | No refresh token can be minted for a revoked session, even by an operation that began before revocation (`rotate`/`replaceActiveSuccessor`/`insert` reject revoked sessions). | RACE-03, STO-RT-05 |
| INV-TOK-08 | SC | A one-time token is consumable at most once, only for its own purpose, only before expiry; under concurrency exactly one consumer succeeds. | OTT-01..04, RACE-04 |
| INV-TOK-09 | SC | Access tokens are verified (signature, algorithm allow-list, `typ`, `iss`, `aud`, `exp`/`nbf`) **before** any claim is trusted. A token of one class is never accepted as another class. | TOK-ACC-01..14 |
| INV-TOK-10 | SC | Access tokens carry no roles, permissions, or PII; they never confer more than the bound session confers. | TOK-ACC-12 |
| INV-TOK-11 | SC | The key material used for signing/verification/pepper never appears in any log, audit event, error, `describe()` output, or serialized config. | AUD-04, CFG-06 |
| INV-TOK-12 | SC | Raw token values are never retrievable after issuance. | TOK-REF-03 |

## 4. Session invariants

| ID | Sev | Invariant | Tests |
|---|---|---|---|
| INV-SESS-01 | SC | A credential referring to a missing, revoked, or expired session never yields a Principal. Deleting terminal sessions never makes an old credential valid. | SESS-06, SESS-09 |
| INV-SESS-02 | SC | `revoked` and `expired` are terminal. No operation (touch, refresh, login, state change, retry) returns a session to `active`. | SESS-05, REV-06 |
| INV-SESS-03 | SC | Every successful login creates a **new** session with a **new** identifier and a **new** credential; no pre-login session/token is promoted (no fixation). | AUTH-SEC-05, SESS-01 |
| INV-SESS-04 | IC | `idleExpiresAt ≤ absoluteExpiresAt` always; `absoluteExpiresAt`, `authMethod`, `amr`, `authenticatedAt`, `userId` are immutable. | SESS-03, SESS-04 |
| INV-SESS-05 | SC | The number of `active` sessions of a user never exceeds a configured finite limit, even under parallel logins. | RACE-06, SESS-07 |
| INV-SESS-06 | SC | No session can survive a user-wide revocation that began after its creation; no session can be created "in the gap" of a user-wide revocation so as to escape it. | RACE-07, REV-03 |
| INV-SESS-07 | SC | Revocation is idempotent and audited exactly once per session. | REV-05, AUD-02 |

## 5. Authorization invariants

| ID | Sev | Invariant | Tests |
|---|---|---|---|
| INV-AUTHZ-01 | SC | **Deny precedence:** a matching RBAC deny overrides every allow (any role, depth, wildcard, direct grant, superuser) and cannot be overridden by any policy or mode. | AZ-DENY-01..06 |
| INV-AUTHZ-02 | SC | **Default deny:** absent an explicit allow from the engine, the effect is `deny`. A subject with no roles, an unknown role, an unregistered permission, an invalid resource type/action, a policy error, a timeout, an invalid policy result, or an unavailable data source is denied. | AZ-DEF-01..10 |
| INV-AUTHZ-03 | IC | **Determinism:** identical inputs and state ⇒ identical `Decision.effect` and `Decision.reason`. | AZ-DET-01 |
| INV-AUTHZ-04 | SC | **Walls hold:** global policies (`resource = "*"`) apply to every request after Stage 1, and no mode bypasses them. | POL-WALL-01..03 |
| INV-AUTHZ-05 | SC | **Fail closed:** no exception, timeout, cache failure, or store failure ever produces `allow`. | AZ-DEF-05..10, POL-ERR-01..05 |
| INV-AUTHZ-06 | SC | **Role changes are live:** after an assignment/grant mutation completes (and local invalidation ran), the next authorization on the *same session, without re-login* reflects it; role removal is never delayed by token validity. Staleness across processes is bounded by `subjectTtl` (or the invalidation channel). | MID-01..06 |
| INV-AUTHZ-07 | SC | **No escalation by race:** guard checks and assignment writes are atomic; concurrent changes cannot yield an assignment the assigner could not have made, nor remove the last superuser. | ESC-06, RACE-08 |
| INV-AUTHZ-08 | SC | `grantedBy`/audit actor are derived from the authenticated actor, never from input. | ESC-08 |
| INV-AUTHZ-09 | SC | No authorization-relevant field (roles, status, ids, `securityVersion`) can be set through registration or metadata input. | ESC-07 |
| INV-AUTHZ-10 | SC | A scope result never admits a resource that `authorize` denies, and never omits one it allows (for declared scopes); a missing/failed scope is `none`/`unsupported`, never `all`; walls are never silently dropped from a scope. | SCP-01..08 |
| INV-AUTHZ-11 | SC | Role definitions of a published catalog are immutable; an evaluation uses a single catalog version from start to end. | CAT-01..03 |
| INV-AUTHZ-12 | SC | Scoped (tenant/org) assignments never apply to an evaluation whose scope context does not include their scope; tenant context comes only from trusted sources. | TEN-01..05 |
| INV-AUTHZ-13 | SC | Expired assignments and direct grants never contribute to a decision, irrespective of cache state or housekeeping. | ASG-04, ASG-05 |

## 6. Time, ordering, and consistency invariants

| ID | Sev | Invariant | Tests |
|---|---|---|---|
| INV-TIME-01 | IC | All time-dependent behavior derives from the injected `Clock`; no code path reads ambient time. Backward clock movement MUST NOT extend any expiry nor un-expire any token/session already observed expired within one process. | TIME-01..05 |
| INV-STORE-01 | SC | Security-critical reads (`consume`, session/user state used for decisions, revocation checks) and writes are linearizable on the primary; no replica or lagging cache serves them. | STO-CONS-01 |
| INV-STORE-02 | SC | A failed or timed-out storage operation never results in issuance of credentials or an `allow` decision on the basis of the unknown outcome. | STO-FAIL-01..05 |
| INV-STORE-03 | IC | `UnitOfWork` effects are all-or-nothing and invisible until commit. | STO-UOW-01..03 |

## 7. Information-disclosure invariants

| ID | Sev | Invariant | Tests |
|---|---|---|---|
| INV-LEAK-01 | SC | **No account enumeration:** unknown identifier, wrong password, missing credential, malformed identifier produce identical external outcomes and equalized observable work; reset-request, registration (default), and logout responses are independent of existence/validity. | AUTH-ENUM-01..08, AUTH-TIM-01 |
| INV-LEAK-02 | SC | Account state is disclosed only after a correct password (or token possession). | AUTH-ENUM-05 |
| INV-LEAK-03 | SC | Error messages are fixed per code and contain no identifiers, secrets, internal state, or driver text. | ERR-01..04 |
| INV-LEAK-04 | SC | Session lookup for non-owned ids is indistinguishable from unknown ids. | SESS-10 |
| INV-LEAK-05 | SC | Audit events and logs contain no secrets and no resource field values (§`storage/interfaces.md` 10.4). | AUD-03..05 |
| INV-LEAK-06 | SC | Counts, totals and pagination cursors for scoped listings never reveal unauthorized resources. | SCP-07 |

## 8. Throttling and abuse invariants

| ID | Sev | Invariant | Tests |
|---|---|---|---|
| INV-THR-01 | SC | The throttle gate precedes lookup and verification; a blocked caller never learns whether a guess was correct. | AUTH-THR-01 |
| INV-THR-02 | SC | Throttle counters change identically for existing and non-existing identifiers. | AUTH-THR-03 |
| INV-THR-03 | SC | By default, repeated failures against one identifier impose bounded, expiring delay and never an unbounded lock that a third party can trigger permanently. | AUTH-THR-05 |
| INV-THR-04 | OP | The hasher's concurrency is bounded. | AUTH-DOS-01 |

## 9. Audit invariants

| ID | Sev | Invariant | Tests |
|---|---|---|---|
| INV-AUD-01 | SC | Every authorization deny, every session revocation, every reuse detection, every role/grant change, every account-state change, and every credential change emits exactly one audit event of the required type. | AUD-01, AUD-02 |
| INV-AUD-02 | SC | The core exposes no operation to alter or delete audit events. | AUD-06 |
| INV-AUD-03 | SC | Audit failure never converts a deny into an allow, nor an allow into a silent success of a sensitive operation under `fail-closed`. | AUD-07 |

## 10. Configuration invariants

| ID | Sev | Invariant | Tests |
|---|---|---|---|
| INV-CFG-01 | SC | A configuration violating any MUST of this specification fails at construction, reporting **all** violations; no partially valid system starts. | CFG-01..08 |
| INV-CFG-02 | SC | Every insecure relaxation (long access TTL, `rbacOrPolicy`, wildcards, `*:*`, direct grants, no session limit, `reuseGrace > 0`, `enumerationSafeRegistration = false`, throttle fail-open) is explicit, named, and emits a `config.warning` at start-up. | CFG-04, CFG-05 |
| INV-CFG-03 | IC | Configuration is immutable after construction; `describe()` reflects effective settings with secrets redacted. | CFG-06, CFG-07 |

## 11. Meta-invariants (apply to the whole system)

1. **Monotonic safety:** no allowed extension (hook, plugin, adapter, strategy) can weaken any invariant above. Hooks MAY veto; they MUST NOT bypass (`DESIGN.md` §12).
2. **Atomic security transitions:** any transition listed as atomic in this specification (state change + revocation + securityVersion; password reset; refresh rotation; assignment with guards; session limit) is observed by every reader either entirely or not at all.
3. **No ambient authority:** every operation acts on an explicit Subject/Principal or the reserved `system` actor; no thread-local/global "current user".
4. **Reproducibility:** with a fake clock and deterministic random source, a test run is fully reproducible (INV-TIME-01).
