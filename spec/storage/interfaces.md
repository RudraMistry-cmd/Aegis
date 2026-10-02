# Aegis Spec — Storage and Supporting Ports

Status: Draft 0.1 · Normative
Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** are as defined in RFC 2119 / RFC 8174 when in capitals.
Entity shapes: `auth/principal.md`, `auth/session.md`, `auth/tokens.md`, `rbac/*`.

This document defines **ports**: the abstract contracts the core requires from persistence and infrastructure. Nothing here prescribes a database, driver, query language, or schema. A conforming *adapter* implements these ports; the core MUST depend only on these contracts (INV-ARCH-02).

Signature notation: `name(arg: Type, …) -> Result`, where `Result` MAY be `Type | Failure`. All operations are asynchronous in effect (they MAY block). `T?` = optional.

---

## 1. Conventions

### 1.1 Failure modes

Every port operation MAY fail with exactly the following adapter-level failures, and MUST NOT leak raw driver/database errors across the port boundary:

| Failure | Meaning | Maps to (`errors.md`) |
|---|---|---|
| `Conflict(key)` | A uniqueness constraint was violated. | `CONFLICT` |
| `PreconditionFailed` | A supplied expected-version/expected-state did not match. Nothing was changed. | `PRECONDITION_FAILED` |
| `NotFound` | The target does not exist (only for operations that document it). | `NOT_FOUND` |
| `Unavailable` | The backing system could not be reached or the operation timed out. State is **unknown** unless the operation is declared *idempotent*. | `STORAGE_UNAVAILABLE` |
| `Invalid(field)` | An argument violated a port-level constraint (length, null). | `VALIDATION_FAILED` |

1. An adapter MUST NOT return partial success. An operation either has its full documented effect or none (`Unavailable` excepted: see rule 2).
2. After `Unavailable` on a **non-idempotent** operation the caller MUST NOT assume the operation did or did not take effect; the core MUST treat the enclosing flow as failed (fail closed) and MUST NOT issue credentials on the basis of it.
3. Operations MUST NOT block indefinitely; adapters MUST support a configurable operation timeout, and a timeout is `Unavailable`.

### 1.2 Consistency and atomicity classes

| Class | Guarantee |
|---|---|
| **A1** *(linearizable single-record)* | The operation behaves as an indivisible read-modify-write on its target record(s) in the same primary store. Under any number of concurrent callers (threads, processes, hosts), outcomes are as if executed one at a time in some order consistent with real time. |
| **A2** *(atomic group)* | Several A1 effects on different records/ports inside one `UnitOfWork` (§11) are committed together or not at all; no reader (including concurrent callers) may observe a partial result. |
| **R** *(read-primary)* | The read reflects all writes committed before it began (read-your-writes **and** cross-process). Replicas/caches that may lag MUST NOT serve R reads. |
| **E** *(eventually consistent OK)* | May be served from a lagging replica/cache. |

Every operation below is labeled. **Security-critical reads and writes are A1/A2/R and MUST NOT be weakened by the adapter.**

### 1.3 Idempotency labels

`[idempotent]` — repeating the call with identical arguments, any number of times, leaves the store in the same state as one call and returns a success result each time (unless otherwise stated).
`[non-idempotent]` — repeating may change the outcome; the operation documents what a replay returns.

### 1.4 Common types

```
Page<T>   { items: List<T>, nextCursor: String? }          cursor is opaque; ordering MUST be stable (documented per operation)
PageReq   { limit: Integer 1..1000, cursor: String? }
```

### 1.5 Data handling requirements (all ports)

1. Timestamps MUST be stored and returned without loss of millisecond precision and without time-zone ambiguity (UTC).
2. Secrets (digests, password hashes) MUST be treated as sensitive: adapters MUST NOT log them, MUST NOT include them in exceptions, and MUST NOT return them through any operation not designated to.
3. Adapters MUST NOT silently truncate any field. Over-length input MUST fail with `Invalid`.
4. Adapters MUST NOT interpret `metadata`/`Json` content.
5. Equality for unique keys on string fields MUST be exact (binary, case-sensitive); normalization is done by the core before the call (`principal.md` §4.1).

---

## 2. UserStore

```
create(user: NewUser) -> User | Conflict                                         [A1]  [non-idempotent]
getById(id: Id) -> User | null                                                   [R]
setStatus(id: Id, to: StateName, expectedVersion: Integer, now: Timestamp)
     -> User | NotFound | PreconditionFailed                                     [A1]  [non-idempotent]
bumpSecurityVersion(id: Id, now: Timestamp) -> Integer (new value) | NotFound    [A1]  [non-idempotent]
updateMetadata(id: Id, patch: Map<String,Json>, expectedVersion: Integer?, now: Timestamp)
     -> User | NotFound | PreconditionFailed                                     [A1]
delete(id: Id) -> void                                                           [A2 via §11]  [idempotent]
```

Guarantees:

1. `create` MUST fail with `Conflict` if `id` exists. `NewUser.version` MUST be 0 and `securityVersion` 0 at creation (the adapter MUST NOT accept caller-set values).
2. `setStatus` MUST compare `expectedVersion` to the stored `version`, apply the change and increment `version` in one A1 step. The *state-machine transition validity* is enforced by the core before the call; the store enforces only the version check.
3. `bumpSecurityVersion` MUST be a monotonic atomic increment (no lost updates under concurrency: N concurrent bumps ⇒ final value increases by exactly N).
4. Every mutation MUST increment `version` and set `updatedAt`.
5. `getById` used for resolution/authentication decisions MUST be R unless a documented cache with TTL is configured (`principal.md` §7.2).
6. `delete` MUST, atomically with the user's removal, remove or tombstone the user's identifiers, credentials, sessions, refresh tokens, assignments, direct grants and one-time tokens (cascade), within one `UnitOfWork`. The deleted `Id` MUST NOT be reissued (INV-ID-01).

## 3. IdentifierStore

```
add(userId: Id, type: String, value: String, normalized: String, verified: Boolean, now: Timestamp)
     -> Identifier | Conflict | NotFound(user)                                   [A1]  [non-idempotent]
findByNormalized(type: String, normalized: String) -> Identifier | null          [R]
listByUser(userId: Id) -> List<Identifier>                                       [R]
markVerified(identifierId: Id, now: Timestamp) -> void | NotFound                [A1]  [idempotent]
remove(identifierId: Id) -> void                                                 [A1]  [idempotent]
```

Guarantees:

1. `(type, normalized)` uniqueness MUST hold globally and MUST be enforced by the store (not by check-then-insert in the core): two concurrent `add` calls with the same key ⇒ exactly one succeeds, the other receives `Conflict` (INV-ID-02).
2. A user MUST NOT be left with zero identifiers by `remove` when the project configuration requires at least one login identifier; the core enforces this using a `UnitOfWork`.
3. `findByNormalized` MUST return the same identifier the unique index would admit; there MUST NOT be two matches.

## 4. CredentialStore

```
get(userId: Id, type: String) -> Credential | null                               [R]
put(userId: Id, type: String, payload: Opaque, now: Timestamp) -> Credential     [A1]  [idempotent for equal payload; replaces]
touch(credentialId: Id, at: Timestamp) -> void                                   [A1]  [idempotent]
delete(userId: Id, type: String) -> void                                         [A1]  [idempotent]
```

Guarantees:

1. `put` MUST replace atomically: at no instant may a reader observe zero credentials of that type (when a previous one existed) nor two.
2. `get` is the only operation that returns `payload`, and only to the `identity` component; the port MUST NOT be exposed to host code (INV-CRED-01).
3. `put` MUST be usable inside a `UnitOfWork` together with `OneTimeTokenStore.consume`, `UserStore.bumpSecurityVersion` and session revocation (password reset/change).

## 5. SessionStore

```
createWithLimit(session: NewSession, limit: Integer | null, policy: "evict-oldest" | "reject", now: Timestamp)
     -> { session: Session, evicted: List<Id> } | LimitReached                   [A1 per user]  [non-idempotent]
get(id: Id) -> Session | null                                                    [R]
listActiveByUser(userId: Id, page: PageReq, now: Timestamp) -> Page<Session>     [R]   ordering: createdAt DESC, id DESC
revoke(id: Id, reason: RevocationReason, now: Timestamp) -> boolean (true if this call revoked it)   [A1]  [idempotent]
revokeAllForUser(userId: Id, except: Id | null, reason: RevocationReason, now: Timestamp) -> Integer (number newly revoked)   [A1 per user]  [idempotent]
touch(id: Id, now: Timestamp, newIdleExpiresAt: Timestamp) -> boolean (true if applied)   [A1]  [idempotent]
countActive(userId: Id, now: Timestamp) -> Integer                               [R]
deleteTerminalBefore(cutoff: Timestamp) -> Integer                               [housekeeping]  [idempotent]
```

Guarantees:

1. **`createWithLimit` is the only conforming way to create a session when a limit is configured.** It MUST, atomically per user: count that user's `active` sessions (by derived status at `now`); if the count `≥ limit`: with `evict-oldest` revoke the oldest ones (by `createdAt`, then `id`) with reason `evicted` — **and, in the same atomic step, revoke their refresh tokens** (§6, via the same `UnitOfWork`) — then insert; with `reject` return `LimitReached` and change nothing. Concurrent calls for one user MUST serialize so the active count never exceeds `limit` (INV-SESS-05).
2. `limit = null` means unlimited; implementations MUST accept it only when explicitly configured.
3. `revoke`: the first successful call sets `revokedAt`/`revokedReason` and returns `true`; later calls return `false`, MUST NOT modify the record, and MUST NOT error. The caller uses the boolean to decide whether to emit the audit event exactly once.
4. `revokeAllForUser` MUST revoke every non-revoked session of the user (`except` excluded) in one A1 step with respect to concurrent `createWithLimit` for the same user: a session created *before* the call began MUST be revoked by it; a session created *after* it completes is unaffected; no session may be created in a window that escapes both (INV-SESS-06). It MUST also revoke the associated refresh families (via `UnitOfWork`).
5. `touch` MUST apply only if the session is not revoked and `newIdleExpiresAt ≥` the stored `idleExpiresAt` and `≤ absoluteExpiresAt`; otherwise it MUST return `false` and leave the record unchanged. A touch MUST NOT resurrect or extend beyond bounds.
6. `get` MUST return revoked/expired sessions (until deleted) so that callers can distinguish; it MUST return `null` only for non-existent or deleted.
7. `deleteTerminalBefore(cutoff)` MUST delete only sessions that are revoked or expired **and** whose terminal instant `< cutoff`.

## 6. RefreshTokenStore

```
insert(record: NewRefreshToken) -> void | Conflict(hash)                         [A1]  [non-idempotent]

consume(hash: Bytes, now: Timestamp) -> ConsumeResult                            [A1]  [non-idempotent]
ConsumeResult =
    { kind: "consumed", token: RefreshTokenRecord }      // status was active, now used; usedAt = now
  | { kind: "reused",   token: RefreshTokenRecord }      // status was used
  | { kind: "revoked",  token: RefreshTokenRecord }      // status was revoked
  | { kind: "expired",  token: RefreshTokenRecord }      // status active but expiresAt ≤ now
  | { kind: "unknown" }

rotate(consumedTokenId: Id, successor: NewRefreshToken) -> void | PreconditionFailed   [A1]  [non-idempotent]
    // atomically: set consumed.successorId = successor.id AND insert successor (status active) — only if
    // consumed.status == used AND consumed.successorId is unset AND the session is not revoked.

replaceActiveSuccessor(oldSuccessorId: Id, replacement: NewRefreshToken, parentId: Id)
     -> "replaced" | "not_active"                                                [A1]  [non-idempotent]
    // atomically: if old successor.status == active → set it revoked(reason superseded),
    // insert replacement (active, parentId), set parent.successorId = replacement.id.

revokeFamily(sessionId: Id, reason: String) -> Integer (number of records changed)   [A1]  [idempotent]
getById(id: Id) -> RefreshTokenRecord | null                                     [R]
deleteTerminalBefore(cutoff: Timestamp) -> Integer                               [housekeeping]  [idempotent]
```

Guarantees:

1. **`consume` is the linchpin of replay protection.** It MUST be one A1 step that evaluates the record by this precedence and, only for the first case, changes state:
   1. no record with `hash` ⇒ `unknown`;
   2. `status = revoked` ⇒ `revoked` (no change);
   3. `status = used` ⇒ `reused` (no change);
   4. `status = active ∧ expiresAt ≤ now` ⇒ `expired` (no change);
   5. otherwise (`active`, unexpired) ⇒ set `status = used`, `usedAt = now`, return `consumed`.
2. For any set of N ≥ 1 concurrent `consume` calls with the same `hash` on an active, unexpired token, **exactly one** MUST return `consumed`; the other N−1 MUST return `reused` (INV-TOK-02). This MUST hold across processes and hosts.
3. `consume` MUST NOT read from a replica or any lagging store.
4. `hash` comparison MUST NOT leak timing information through early exit on partial match when the adapter exposes comparison logic (database index lookups are acceptable).
5. `rotate` completes the rotation after `consume`. Between `consume` and `rotate` the family has *no* active token; if the process fails there, the user MUST re-authenticate (acceptable: availability loss, never security loss). The core MUST NOT issue the client a new refresh token unless `rotate` has succeeded.
6. `revokeFamily` MUST mark every `active` record of the family `revoked` in one A1 step, MUST be applied in the same `UnitOfWork` as the session revocation when invoked via `flows/revoke.md`, and MUST be a no-op returning 0 on a family with nothing active.
7. A record inserted by `rotate`/`replaceActiveSuccessor`/`insert` for a session that is already revoked MUST be rejected with `PreconditionFailed` (no token may be minted for a revoked session — closing the revoke-vs-refresh race; INV-TOK-07).
8. `deleteTerminalBefore` MUST NOT delete a `used` record while its family is still active and the record's `usedAt` is within the retention window (`session.md` §8); doing so would defeat reuse detection.

## 7. OneTimeTokenStore

```
put(record: NewOneTimeToken) -> void | Conflict(hash)                            [A1]  [non-idempotent]
consume(hash: Bytes, purpose: String, now: Timestamp) -> OneTimeTokenRecord | null    [A1]  [non-idempotent]
invalidate(userId: Id, purpose: String, target: String | null) -> Integer        [A1]  [idempotent]
deleteExpiredBefore(cutoff: Timestamp) -> Integer                                [housekeeping]  [idempotent]
```

Guarantees:

1. `consume` MUST return the record **and mark it consumed in one A1 step** iff: the hash exists, `purpose` equals the stored purpose, `expiresAt > now`, and `consumedAt` is unset. Otherwise it MUST return `null` without distinguishing the reason, and without modifying state. Concurrent consumers: exactly one receives the record (INV-TOK-08).
2. `consume` MUST be composable inside a `UnitOfWork` so the effect (e.g. setting a password) can be made atomic with the consumption: if the transaction rolls back, the token MUST remain unconsumed (so a failed reset can be retried) — **or**, where the adapter cannot roll back, the core MUST order operations so that a failure after consumption never leaves the user with an unusable *and* unrecoverable state (re-request is always possible).
3. `put` for a `(userId, purpose, target)` MUST be preceded by `invalidate` for the same triple in the same unit (`tokens.md` §4.5).

## 8. Authorization and revocation stores

### 8.1 RoleCatalogStore

```
sync(catalog: CatalogSnapshot, now: Timestamp) -> void                           [A1]  [idempotent]
getCatalogVersion() -> String | null                                             [R]
listDynamicRoles(tenant: Id | null, page: PageReq) -> Page<Role>                 [R]   // dynamicRoles only
putDynamicRole(role: Role, expectedVersion: Integer | null) -> Role | PreconditionFailed | Conflict   [A1]
deleteDynamicRole(name: RoleName, tenant: Id | null) -> void                     [A1]  [idempotent]
```

1. `sync` MUST mirror the catalog's roles and permission registry for referential integrity/administration. It MUST NOT be able to change what the engine evaluates for a `catalog` role (`roles.md` §3.3). Syncing the same catalog twice MUST be a no-op.
2. Multiple processes starting concurrently with the same catalog MUST NOT error or duplicate.

### 8.2 AssignmentStore

```
assign(a: RoleAssignment, now: Timestamp) -> "created" | "unchanged" | "updated"      [A1]  [idempotent]
unassign(subjectId: Id, roleName: RoleName, scope: Scope | null) -> boolean (true if removed)   [A1]  [idempotent]
listActive(subjectId: Id, now: Timestamp) -> List<RoleAssignment>                [R]  // excludes expired (assignments.md §4)
listSubjectsByRole(roleName: RoleName, page: PageReq, now: Timestamp) -> Page<Id>   [R]  ordering: subjectId ASC
countActiveHoldersOfSuperuserRoles(now: Timestamp) -> Integer                    [R]
removeAllForSubject(subjectId: Id) -> Integer                                    [A2 via §11]  [idempotent]
```

1. Uniqueness of `(subjectId, roleName, scope)` MUST be enforced by the store. Concurrent identical `assign` calls: one returns `created`, the others `unchanged`; none fails.
2. For the escalation guards of `assignments.md` §6 the core MUST be able to perform *check and write atomically*: the adapter MUST provide `UnitOfWork` isolation such that the last-superuser count and the write are consistent (serializable for those operations; INV-AUTHZ-07).
3. `listActive` MUST apply the `now` filter in the query (not in caller code after pagination).

### 8.3 DirectGrantStore (only if `directGrants`)

```
put(g: DirectGrant, now: Timestamp) -> "created" | "unchanged" | "updated"       [A1]  [idempotent]
remove(subjectId: Id, permission: String, effect: String, scope: Scope | null) -> boolean   [A1]  [idempotent]
listActive(subjectId: Id, now: Timestamp) -> List<DirectGrant>                   [R]
```

### 8.4 RevocationStore (only if a strict-revocation feature needs an explicit denylist)

```
add(key: String, expiresAt: Timestamp) -> void                                   [A1]  [idempotent]
has(key: String, now: Timestamp) -> boolean                                      [R]
```

1. `key` is a session id or token id. Entries MUST be retained at least until `expiresAt`; after `expiresAt` they MAY be dropped. `has` for an unexpired entry MUST return `true`.
2. Implementations are OPTIONAL: the Session record's `revokedAt` is the authority (`session.md`). A denylist is permitted purely as a latency optimization, and MUST NOT be able to *un*-revoke anything.

---

## 9. Supporting (non-storage) ports

### 9.1 Clock
```
now() -> Timestamp
```
MUST return UTC time. Production implementations SHOULD be monotonic-corrected so that consecutive calls in one process do not decrease. Tests MUST be able to supply a controllable fake. (INV-TIME-01)

### 9.2 Random
```
bytes(n: Integer) -> Bytes
```
MUST return `n` bytes from a cryptographically secure source. MUST NOT block unbounded. Fakes are allowed in tests only and MUST be impossible to select via production configuration without an explicit `unsafe` name.

### 9.3 IdGenerator
```
newId() -> Id
```
MUST return an `Id` unique with overwhelming probability and not predictable from previous values (≥ 122 bits of entropy). Time-ordered ids are permitted provided the unpredictable part is ≥ 74 bits.

### 9.4 PasswordHasher
```
hash(password: String) -> String                    // self-describing encoded hash; fresh salt each call
verify(password: String, encoded: String) -> Boolean  // constant-time wrt digest; MUST NOT throw on malformed `encoded` (returns false)
needsRehash(encoded: String) -> Boolean
dummyVerify(password: String) -> void              // does work equal in cost to a real verify at current parameters
```
1. `hash`/`verify` MUST implement `principal.md` §5.1 requirements.
2. `dummyVerify` exists for enumeration/timing resistance (`flows/login.md`); its execution cost MUST be within ±20% of `verify` of a hash made at the current parameters on the same hardware (documented, tested statistically).
3. The hasher MUST bound concurrency (configurable, default = number of CPU cores) so that a login flood cannot exhaust memory; excess requests MUST queue with a timeout and fail with `RATE_LIMITED`/`STORAGE_UNAVAILABLE`-class infrastructure failure rather than run unbounded.

### 9.5 Notifier
```
send(message: { kind: "email_verify" | "password_reset" | "password_changed" | "login_notice" | (ext),
                to: String, userId: Id, token: String?, expiresAt: Timestamp? }) -> void | Unavailable
```
1. The core MUST NOT assume delivery. Success means "accepted for delivery".
2. The core MUST NOT make the **response** of `requestPasswordReset`/`register` depend on the outcome of `send` or on its latency in a way observable by the caller (`flows/login.md` §6 no-oracle rule): `send` failure MUST be logged/audited and MUST NOT change the external result.

### 9.6 AttributeProvider
```
attributesFor(userId: Id, now: Timestamp) -> { tenantId: Id?, attributes: Map<String, Json> } | Unavailable
```
Defined contract: `principal.md` §2.3.

### 9.7 Cache
```
get(key: String) -> Bytes | null
set(key: String, value: Bytes, ttl: Duration) -> void
delete(key: String) -> void
deletePrefix(prefix: String) -> void                  // OPTIONAL
publishInvalidate(keys: List<String>) -> void         // OPTIONAL shared invalidation channel
subscribeInvalidate(handler) -> Subscription          // OPTIONAL
```
1. A cache MUST NOT be the source of truth for any security-critical fact. Failure of any cache operation MUST be treated as a miss (reads) or ignored-with-log (writes), never as an allow (`assignments.md` §7.6).
2. Values for different tenants/subjects MUST NOT be reachable via key collisions: keys MUST be built from length-delimited components.
3. TTLs MUST be honored; an entry MUST NOT be returned after `ttl` has elapsed.

### 9.8 RateLimiter (login throttling)
```
peek(key: String, now: Timestamp) -> { blocked: Boolean, retryAfter: Duration?, failures: Integer }
recordFailure(key: String, now: Timestamp) -> void
reset(key: String) -> void
```
1. `recordFailure` MUST be atomic (no lost increments under concurrency).
2. Keys MUST be derived by the core from `("login", normalizedIdentifier)` and `("login-ip", clientIp)` and a global bucket; the raw identifier MUST NOT be stored in clear if the store is shared/external (use a keyed digest).
3. A limiter outage MUST NOT be treated as "not blocked" **if** `throttleFailMode = "closed"`; the default is `"open-with-alert"` (availability) and MUST be documented; either way `config.warning`/`security.throttle_unavailable` MUST be audited.

### 9.9 BreachChecker (optional)
```
isBreached(password: String) -> Boolean | Unavailable
```
MUST NOT transmit the password or its full hash to third parties (k-anonymity or local list only). `Unavailable` MUST NOT block password setting unless configured `breachCheckFailMode = "closed"`.

### 9.10 Logger
```
log(level: "debug"|"info"|"warn"|"error", event: String, fields: Map<String, Json>) -> void
```
The core MUST NOT pass secrets in `fields`. The logger MUST NOT throw into the caller.

---

## 10. Audit

### 10.1 Port
```
AuditSink.write(event: AuditEvent) -> void
```
1. `write` MUST NOT throw into callers' control flow except in `fail-closed` configurations (`policy.md` §7.3). Sinks SHOULD be non-blocking or bounded-blocking.
2. Sinks MUST be **append-only** from the core's viewpoint: the core has no operation to modify or delete events.

### 10.2 Event envelope
```
AuditEvent {
  id        : Id
  type      : String                       // from §10.3
  at        : Timestamp
  severity  : "info" | "notice" | "warning" | "high"
  actor     : { id: Id?, type: String?, sessionId: Id? }
  target    : { type: String?, id: Id? }
  outcome   : "success" | "failure" | "denied"
  reason    : String?                      // machine-readable code, never free text with data
  context   : { requestId: String?, ip: String?, userAgent: String? }
  details   : Map<String, Json>            // type-specific; MUST pass redaction (§10.4)
}
```
### 10.3 Required event types
`login.succeeded`, `login.failed`, `login.throttled`, `logout`, `logout.all`, `session.created`, `session.revoked`, `session.evicted`, `refresh.succeeded`, `refresh.reuse_detected` (severity high), `refresh.superseded_presented`, `refresh.integrity_failure` (severity high), `account.registered`, `account.state_changed`, `password.changed`, `password.reset_requested`, `password.reset_completed`, `email.verified`, `role.assigned`, `role.revoked`, `role.defined`, `role.deleted`, `grant.assigned`, `grant.revoked`, `authz.denied`, `authz.policy_error`, `auth.rejected`, `config.warning`, `security.throttle_unavailable`.

### 10.4 Redaction (MUST)
Events MUST NOT contain: passwords, password hashes, any token or token digest, signing/pepper key material, one-time token values, full request bodies, resource field values (other than `resourceId`), attribute values. `login.failed` MUST NOT include whether the identifier exists. The raw login identifier SHOULD be recorded only as a keyed digest unless the project opts in to cleartext.

---

## 11. UnitOfWork

```
UnitOfWork.run(fn: (tx: StoreSet) -> T, options?: { isolation: "serializable" | "default" }) -> T
```
`StoreSet` exposes the stores of §2–§8 bound to one transaction.

1. All store operations performed through `tx` MUST be **A2**: committed together or rolled back together when `fn` completes normally or fails.
2. If `fn` fails (throws/returns failure) **no** effect MUST persist.
3. Isolation MUST follow §11.1. Whatever the level, the following flows MUST have serializable outcomes: assignment with escalation checks, last-superuser protection, session limit enforcement, password reset/change, account state changes. Adapters that cannot provide that for these flows MUST NOT claim conformance for them.
4. `fn` MUST NOT perform non-storage side effects (notifications, audit emission, hashing) — the core performs those *after* commit. Adapters MAY retry `fn` on serialization conflict; therefore `fn` MUST be free of external side effects and idempotent in memory.
5. Nested `run` MUST join the outer transaction.
6. An adapter that cannot provide multi-record atomicity (e.g., a document store without transactions) MUST declare which compound operations it supports and MUST NOT be used for flows depending on the rest (`conformance.md` adapter profile `A-LITE` vs `A-FULL`).

### 11.1 Isolation Level Requirement

1. **Default: READ COMMITTED.** Transactional (SQL) adapters MUST run units of work, and their own
   multi-statement operations, at READ COMMITTED unless configured otherwise.
2. **Critical rows MUST be locked with `SELECT … FOR UPDATE`** (or the weaker `FOR NO KEY UPDATE`
   where foreign-key checks must not be blocked) before they are read for a decision that the same
   transaction then acts on. Critical rows are at least: the refresh-token row in `consume`, `rotate`
   and `replaceActiveSuccessor`; and the owning user's row, which serializes every operation that
   creates, revokes or limits that user's sessions and tokens. Every read that decides the outcome
   MUST be a statement issued *after* the lock is granted, so it sees all work committed by the
   transaction it waited for. Where the protected state has no single row (e.g. the set of holders of
   a superuser role, `rbac/assignments.md` §6.5), a transaction-scoped lock on an equivalent key
   MUST be used instead.
3. **Lock ordering MUST be deterministic.** An adapter MUST define one global lock order, document
   it, and acquire locks only as a prefix of it, so no two transactions can wait on each other in a
   cycle. Multiple rows of one kind MUST be locked in a fixed order (e.g. ascending key).
4. **SERIALIZABLE is optional but requires retry handling.** An adapter MAY offer SERIALIZABLE. If it
   does, it MUST re-run the whole unit from the start on a serialization failure or a detected
   deadlock, with a bounded number of attempts and backoff, and then fail with `Unavailable`. It
   MUST NOT retry on connection loss or any other error whose commit outcome is unknown (§1.1.2).
5. Every lock wait MUST be bounded (§1.1.3).
6. An adapter whose engine has no isolation levels (e.g. the single-process in-memory reference,
   which serializes all units) satisfies this section by providing at least the same guarantees.

## 12. Adapter conformance

An adapter claims one of:

| Profile | Meaning |
|---|---|
| `A-FULL` | Implements all ports with A1/A2 guarantees and the isolation requirement of §11.1. Required for production multi-instance deployments. |
| `A-LITE` | Implements all ports with A1 guarantees but not cross-record A2 (e.g. a single-document store). Flows needing A2 MUST be implemented through documented single-record equivalents; the adapter MUST list unsupported compound operations. Not suitable where `revokeSessionsOnEnter`-atomic semantics are required unless the equivalents are proven. |

Both profiles MUST pass the storage-contract groups of `conformance.md` (`STO`).
