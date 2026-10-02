# PostgreSQL storage adapter — design and guarantees

Phase 2 adds a PostgreSQL implementation of every storage port in
[`spec/storage/interfaces.md`](../spec/storage/interfaces.md). Domain logic is unchanged; the same
`createAuth` runs on either adapter. This document explains **how each guarantee is achieved and
why it holds under real concurrency**, with the SQL that achieves it.

- Code: [`src/storage/postgres/`](../src/storage/postgres/) — published as `aegis-core/postgres`, so
  the core package keeps zero runtime dependencies and only adapter users need the `pg` driver.
- Schema: [`migrations/001_init.sql`](../migrations/001_init.sql) (tables, constraints, triggers),
  [`migrations/002_indexes.sql`](../migrations/002_indexes.sql) (indexes).
- Tests: [`test/postgres/`](../test/postgres/), run with `npm run test:pg` against a real server.

```ts
import { createPostgresStorage, PostgresAuditSink } from 'aegis-core/postgres';

const storage = createPostgresStorage({ connectionString: process.env.DATABASE_URL! });
await storage.migrate();                                   // idempotent; safe on every start
const auth = createAuth({ storage, audit: new PostgresAuditSink(storage.client), /* … */ });
```

---

## 1. Isolation Strategy

This implements `spec/storage/interfaces.md` §11.1.

**Default: READ COMMITTED + row-level locking.** Critical rows are locked with `SELECT … FOR UPDATE`
(`FOR NO KEY UPDATE` for the user row, so foreign-key checks are not blocked), always in the one
deterministic order of §2, and every deciding read is a statement issued after the lock is granted.
**Optional: SERIALIZABLE** (`isolation: 'serializable'`), with automatic retry.

### Why SERIALIZABLE was rejected as the default: retry overhead

Both were implemented, and the full concurrency suite runs under both. Every invariant holds under
both. The difference is liveness, and it was measured on PostgreSQL 17 (four runs of
`test/postgres/concurrency.pg-test.ts`, 13 race scenarios each):

| | READ COMMITTED + locks | SERIALIZABLE |
|---|---|---|
| Transaction retries per run | **0** (every run) | **388 – 473** |
| 40 parallel logins, one user, limit 3 | 175 ms | 1,405 ms |
| 40 rounds of refresh racing logout | 590 ms | 3,345 ms |
| 40 parallel logins with the default 10-attempt retry budget | always succeed | **flaky**: some logins fail with `STORAGE_UNAVAILABLE` after exhausting retries |

**Why SERIALIZABLE struggles here.** A login unit's first statement reads the user (issue.ts),
which fixes the transaction's snapshot *before* it queues for the per-user lock. When the login ahead
of it commits a new session, the waiter's snapshot is already stale; SSI detects the read/write
conflict and aborts it. With N logins queued for one user, each commit invalidates every waiter, so
contention costs O(N²) attempts. The outcome is always correct (an abort, never an over-allocated
limit), but under a burst a legitimate user can be refused.

### Guarantees achieved

Under READ COMMITTED every *statement* takes a fresh snapshot. Each flow first takes the lock that
serializes it, and every statement after the lock grant therefore sees everything committed by the
transaction it waited for. The flows that need serializable outcomes (spec §11 rule 3) get them from
the lock, deterministically, without aborts:

| Guarantee | Achieved by |
|---|---|
| **Atomic refresh** — a token is consumed exactly once | per-user row lock, then token row `FOR UPDATE` + `status = 'active'` CAS; consume and rotate in one unit (§3) |
| **Correct session limits** — never exceeded under parallel logins | per-user row lock; the count runs after the grant (§4) |
| **Immediate revocation** — no token of a revoked session is minted or accepted | revoke and refresh take the same per-user lock; resolution reads the primary on every request (§5) |
| Last-superuser protection (two removals both count 2 holders) | per-role advisory lock held across count and delete (§2) |
| Concurrent account-state changes | `version` compare-and-set in one `UPDATE` (re-evaluated after the lock wait) |
| Escalation guard reading stale grants | reads join the unit's transaction (ambient routing, §6) |

SERIALIZABLE remains available for deployments that want SSI as a second safety net; it passes the
same suite given a larger retry budget (`maxTransactionAttempts`) for bursty same-user traffic.

**Retry strategy.** A transaction is re-run from the start only when the server reports it aborted
it: `40001 serialization_failure` or `40P01 deadlock_detected`. Those guarantee nothing committed, so
re-running cannot double-apply. Backoff is exponential with full jitter (5 ms base, 250 ms cap), up to
`maxTransactionAttempts` (default 10), then `STORAGE_UNAVAILABLE` (retryable). Connection errors are
**never** retried: a socket lost during `COMMIT` leaves the outcome unknown, and §1.1.2 requires
treating that as failed rather than guessing. Under READ COMMITTED retries do not occur in practice:
the lock order (§2) rules out deadlocks, and nothing raises serialization failures.

---

## 2. Lock order and deadlock freedom

Every flow acquires a prefix of one global order, never out of order (`src/storage/postgres/locks.ts`):

1. **`users` row** — `SELECT … FOR NO KEY UPDATE` — the per-user mutex
2. **`sessions` rows** of that user — `UPDATE` / `SELECT … FOR UPDATE`
3. **`refresh_tokens` rows** — `UPDATE` / `SELECT … FOR UPDATE`

Every store operation that changes a session or a refresh token locks the owning user's row
**first**, even when it only needs one token. Inside a unit of work, **reading** a user
(`users.getById`) also takes this lock, because that read is what a per-user flow decides on —
login checks the account state and copies the `securityVersion` into the new session from it — and
under READ COMMITTED a deciding read must hold the lock (spec §11.1 rule 2). Without it, a suspension
could commit between that read and the session insert (found in Phase 3; see CONFORMANCE.md). Two transactions on the same user therefore queue at
step 1 and can never hold steps 2–3 in opposite orders. Different users share no locks, and no flow
ever locks two users. Hence no cycle, hence no deadlock.

`FOR NO KEY UPDATE` rather than `FOR UPDATE`: inserting a session or token takes `FOR KEY SHARE` on
the user row for the foreign key, which `NO KEY UPDATE` does not block.

One operation deliberately skips the user lock: `touch`, a single conditional `UPDATE` on one
session row, called on the hot request path. It is safe because it holds exactly one row lock and
never waits for another: a transaction can wait *for* it, but it never waits for anything, so it
cannot close a cycle. (`bumpSecurityVersion` is a single `UPDATE` of the user row itself, i.e. it
takes exactly lock step 1.)

**Role-holder locks** (`pg_advisory_xact_lock(hashtextextended('aegis.role:' || name, 0))`) are a
second domain. Only `assign` holds a user lock (its target, read first) while it acquires a role
lock, always in the order user → role; no transaction holding a role lock ever waits for a user,
session or token lock, and the session flows never take role locks. Multiple roles are always locked in ascending name order (the
catalog's sorted role list). A hash collision only adds serialization, never incorrectness.

Every lock wait is bounded by `lock_timeout` (default 5 s) and every statement by
`statement_timeout` (default 10 s); exceeding either is `STORAGE_UNAVAILABLE` (§1.1.3: nothing blocks
indefinitely). Tested: a held lock makes `createWithLimit` fail in ~150 ms with `lockTimeoutMs: 150`.

---

## 3. Refresh-token consume race — how exactly one wins

`RefreshTokenStore.consume(hash, now)` (`refreshTokenStore.ts`), one transaction:

```sql
-- 1. find the owner (plain read; a token's user never changes)
SELECT user_id FROM aegis.refresh_tokens WHERE hash = $1;
-- 2. per-user mutex                                        (lock order step 1)
SELECT 1 FROM aegis.users WHERE id = $user FOR NO KEY UPDATE;
-- 3. lock the token row and read its latest committed state (lock order step 3)
SELECT … FROM aegis.refresh_tokens WHERE hash = $1 FOR UPDATE;
-- 4. apply the precedence of spec §6.1; only for an active, unexpired token:
UPDATE aegis.refresh_tokens SET status = 'used', used_at_ms = $now
 WHERE id = $id AND status = 'active'
RETURNING …;
```

**How exactly one wins.** Step 3's row lock is granted to one transaction at a time. Under READ
COMMITTED, a transaction that was waiting gets the lock only after the winner commits, and the
`SELECT … FOR UPDATE` then returns the *latest committed* row version — `used` — so it reports
`reused`. Under SERIALIZABLE the waiter instead receives `40001` (the row changed after its
snapshot), is rolled back and re-run, and then sees `used`. Either way, once one transaction has
committed `used`, no other can observe `active`.

**A second, independent guarantee in the schema:** a partial unique index allows at most one active
token per family —
`CREATE UNIQUE INDEX … ON aegis.refresh_tokens (session_id) WHERE status = 'active'` — and a trigger
forbids any token from returning to `active`. Even a bug in this adapter could not fork a family.

**What happens to the losers.** Each receives `{kind: 'reused'}`, and the refresh flow
(`spec/flows/refresh.md` §3) treats that as possible theft: it revokes the session and the whole
family and emits `refresh.reuse_detected` (severity high), then returns `TOKEN_INVALID`, identical to
an unknown token. With `reuseGrace = 0` this also kills the winner's fresh successor. That is the
specified trade-off (clients must refresh single-flight), and it is what conformance REF-03 requires.

**The winner's rotation is atomic with its consume.** The refresh flow runs consume → session and
account checks → `rotate` → `touch` in **one unit of work**, so the per-user lock is held from the
consume until the successor exists. A loser's revocation, which needs the same lock, waits until
then. Measured: of 25 concurrent refreshes of one token, exactly 1 returns credentials and 24 return
`TOKEN_INVALID`, in both isolation modes, in every run.

---

## 4. Session-limit enforcement under concurrency

`SessionStore.createWithLimit(session, limit, policy, now)` (`sessionStore.ts`), one transaction:

```sql
SELECT 1 FROM aegis.users WHERE id = $user FOR NO KEY UPDATE;           -- per-user mutex
SELECT id FROM aegis.sessions
 WHERE user_id = $user AND revoked_at_ms IS NULL
   AND idle_expires_at_ms > $now AND absolute_expires_at_ms > $now        -- "active at now"
 ORDER BY created_at_ms, id COLLATE "C";                                  -- oldest first
-- reject:        if count >= limit  → return limit_reached (nothing written)
-- evict-oldest:  revoke the oldest (count − limit + 1), and their families, then insert
UPDATE aegis.sessions SET revoked_at_ms = $now, revoked_reason = 'evicted'
 WHERE id = ANY($victims) AND revoked_at_ms IS NULL;
UPDATE aegis.refresh_tokens SET status = 'revoked', revoked_reason = 'session_revoked'
 WHERE session_id = ANY($victims) AND status = 'active';
INSERT INTO aegis.sessions (…) VALUES (…);
```

**Why the limit cannot be exceeded.** Every `createWithLimit` for a user begins by locking that
user's row, so concurrent logins for one user run one at a time. Under READ COMMITTED the counting
`SELECT` is a *new statement after the lock grant*, so it sees every session committed by the logins
ahead in the queue: the count is never stale. Expiry is evaluated against the caller's `now` inside
the query, so an expired session never occupies a slot. Evicted sessions lose their refresh tokens in
the same transaction (session.md §6.6), so no live token can belong to an evicted session.

Measured, both isolation modes: 40 parallel `createWithLimit` with limit 3 → exactly 3 active;
30 parallel with `reject` → exactly 3 `created`, 27 `limit_reached`; 20 parallel full logins → no
active token belongs to a revoked session.

---

## 5. Revocation visibility — revoked sessions are immediately invalid

`SessionStore.revoke(id, reason, now)`:

```sql
SELECT user_id FROM aegis.sessions WHERE id = $1;
SELECT 1 FROM aegis.users WHERE id = $user FOR NO KEY UPDATE;
UPDATE aegis.sessions SET revoked_at_ms = $now, revoked_reason = $reason
 WHERE id = $1 AND revoked_at_ms IS NULL;                 -- compare-and-set: first reason wins
UPDATE aegis.refresh_tokens SET status = 'revoked', revoked_reason = 'session_revoked'
 WHERE session_id = $1 AND status = 'active';             -- family, same transaction (INV-TOK-05)
```

**Immediate invalidity, no stale reads.**

1. *Refresh* reads the session inside the same unit that holds the per-user lock, and `rotate`
   re-checks it under that lock (`assertSessionUsable`). A revocation needs the same lock, so it
   commits either entirely before the refresh (which then sees it and fails) or entirely after the
   successor exists (and then revokes that successor too). There is no interleaving in which a token
   is minted for a revoked session (INV-TOK-07). Measured over 40 rounds × 2 modes of refresh racing
   logout: the session always ends revoked, no active token ever survives, the refresh outcome is
   always `OK` or `TOKEN_INVALID` (never `PRECONDITION_FAILED` or `STORAGE_UNAVAILABLE`), and a
   refresh that "won" has its new token already dead.
2. *Request resolution* (`resolve`) reads the session and the user's `securityVersion` from the
   database on every request — there is no cache in front of it — with a fresh READ COMMITTED
   statement snapshot, so a revocation is visible to the very next request. This is the strict
   revocation that `spec/auth/tokens.md` §2.5 requires; eventual revocation is not supported.
3. **Operational requirement:** point `connectionString` at the **primary**. A lagging read replica
   would serve stale session state, which spec §1.2 class R forbids for these reads.
4. The schema makes revocation terminal: a trigger rejects any change to a revoked session row, and
   any change to a revoked token (INV-SESS-02).

---

## 6. Ambient transactions

While a unit of work runs, **every** store call made in its async context executes on that unit's
connection, inside its transaction — including calls made through the *non-transactional* store
handles (`postgresClient.ts`, `AsyncLocalStorage`). The in-memory adapter has the same property
implicitly (one database), and on a real server it matters for two reasons:

- **Correctness.** The grant-ceiling and last-superuser guards (`AssignmentService`) resolve the
  actor's roles and count superuser holders through the non-transactional handles. Without routing,
  those reads would run on another connection, outside the transaction and its locks — a
  time-of-check/time-of-use race against INV-AUTHZ-07.
- **Liveness.** A second connection opened inside a transaction can wait forever for a row lock its
  own transaction holds, while pinning a pool slot. Tested: inside a unit that has locked a user, a
  `sessions.revoke` through the non-transactional handle completes instead of deadlocking.

Nested `uow.run` joins the outer transaction (§11.5). A query issued after its unit has finished
(a promise that outlived the unit) is rejected with `INTERNAL` rather than run on a connection that
may now belong to another caller. The audit sink deliberately **bypasses** routing (see §9).

---

## 7. Query design, operation by operation

Every value is a bound parameter; nothing is interpolated. Every query that decides validity uses the
caller's `now` (INV-TIME-01); the database clock (`now()`) is never used for domain decisions.

| Operation | Statements | Why it is safe | Index |
|---|---|---|---|
| `users.create` | `INSERT` registry; `INSERT` users | registry PK makes ids single-use forever (INV-ID-01); 1 txn | PK |
| `users.setStatus` | `UPDATE … WHERE id AND version = $expected RETURNING` | CAS; a waiter re-evaluates the `WHERE` after the lock and misses | PK |
| `users.bumpSecurityVersion` | `UPDATE … SET security_version = security_version + 1` | in-place increment, row-locked; 100 concurrent → exactly +100 | PK |
| `users.delete` | lock `FOR UPDATE`; delete assignments; delete user (FK cascades) | one txn; registry row kept | FK indexes |
| `identifiers.add` | `INSERT` | unique `(type, normalized)` decides races (INV-ID-02) | unique |
| `credentials.put` | `INSERT … ON CONFLICT (user_id, type) DO UPDATE` | single statement: never zero or two rows | unique |
| `sessions.createWithLimit` | see §4 | user lock; fresh count after grant | `sessions_user_live_idx` |
| `sessions.revoke` / `revokeAllForUser` | see §5 | user lock; CAS on `revoked_at_ms IS NULL`; family in same txn | PK / `sessions_user_live_idx` |
| `sessions.touch` | one `UPDATE … WHERE live at $now AND bounds` | single row, never resurrects an expired or revoked session | PK |
| `sessions.listActiveByUser` | keyset `(created_at, id) <` cursor | stable under concurrent inserts | `sessions_user_live_idx` |
| `refreshTokens.consume` | see §3 | user lock + token row lock + CAS | `hash` unique |
| `refreshTokens.rotate` | lock owner; parent `FOR UPDATE`; session re-check; `INSERT`; link | parent must be `used` with no successor; partial unique index | PK |
| `refreshTokens.replaceActiveSuccessor` | lock owner; old `FOR UPDATE`; revoke old; `INSERT`; relink | revoke-then-insert respects one-active-per-family | PK |
| `refreshTokens.revokeFamily` | lock owner; `UPDATE … WHERE session_id AND status='active'` | idempotent | partial unique |
| `assignments.assign` | role lock; `INSERT … ON CONFLICT DO NOTHING`; optional `UPDATE` expiry | N identical concurrent → 1 `created`, N−1 `unchanged` | PK |
| `assignments.listSubjectsByRole` | role lock (in a txn); keyset on `subject_id COLLATE "C"` | count-then-delete is atomic under the lock | `role_assignments_role_idx` |
| `roles.sync` | upsert singleton; lock it `FOR UPDATE`; replace sets | concurrent starters serialize; same version is a no-op | PK |

`COLLATE "C"` on id ordering makes it byte-wise, matching the in-memory adapter regardless of the
database locale.

---

## 8. Schema

Tables (`migrations/001_init.sql`): `user_id_registry`, `users`, `identifiers`, `credentials`,
`sessions`, `refresh_tokens`, `catalog_state`, `roles`, `permissions`, `role_assignments`,
`audit_events`, plus `schema_migrations` maintained by the runner.

**Time.** Instants are `BIGINT` epoch milliseconds in columns named `*_at_ms`. The domain passes
`now` from its injected clock (INV-TIME-01), so the database clock is never consulted; `BIGINT` keeps
that value exact, with no float or time-zone rounding at the millisecond expiry boundaries the
conformance suite tests (`TIME-01` passes on PostgreSQL to the millisecond).

**Invariants enforced by the database itself**, so a defect fails loudly instead of corrupting state:

| Mechanism | Invariant |
|---|---|
| `aegis.ident` domain (Id grammar), `aegis.epoch_ms` domain (≥ 0) | principal.md §0 |
| `UNIQUE (type, normalized)` on identifiers | INV-ID-02 |
| `user_id_registry`, never deleted from | INV-ID-01 |
| `UNIQUE (user_id, type)` on credentials | INV-CRED-03 |
| CHECK `created < idle ≤ absolute`; revoked-at/reason paired | INV-SESS-04, session.md §2.2 |
| trigger `sessions_guard`: revoked row frozen; immutable fields; idle never shrinks | INV-SESS-02, INV-SESS-04 |
| partial unique index: one active refresh token per family | INV-TOK-02, tokens.md §3.2.2 |
| trigger `refresh_tokens_guard`: no return to active; revoked frozen; `usedAt` write-once | tokens.md §3.2.1 |
| CHECK used ⇒ `used_at`; revoked ⇒ reason; active ⇒ no successor | tokens.md §3.2 |
| trigger `users_guard`: versions never decrease; id immutable | principal.md §3.1-§3.2 |
| triggers on `audit_events`: no `UPDATE`, `DELETE` or `TRUNCATE` | INV-AUD-02 |

There is deliberately **no** foreign key from `role_assignments` to `roles`: an assignment may outlive
its role and then contributes nothing (roles.md §5.2), and assignments are keyed by subject id so
service subjects can hold roles. Refresh-token lineage (`parent_id`, `successor_id`) is not a foreign
key either: a family is always deleted with its session, and a `SET NULL` cascade would have to
update frozen revoked rows.

**Expiry / TTL strategy.** Correctness never depends on deleting anything: every query evaluates
expiry against `now` at read time, so an expired row is already unusable. `storage.housekeep(cutoff)`
deletes sessions that became terminal before `cutoff` (their tokens go by cascade). Choose `cutoff`
no later than `now − retention`, where retention ≥ `max(accessTtl, reuseGrace) + 24h`
(session.md §8.1), so reuse detection and audit still work for recently ended sessions. The partial
index `sessions_expiry_idx` serves it.

---

## 9. Audit sink

`PostgresAuditSink` inserts into `aegis.audit_events`. It is **non-blocking** (`write` enqueues and
returns; `flush` awaits in-flight inserts) and **never joins a unit of work**: an audit insert inside a
business transaction could abort it, and an audit failure must never change an outcome
(policy.md §7.3). Failures are counted and reported to an optional `onError`, never thrown. Trade-off:
events accepted but not yet flushed are lost if the process dies; call `flush()` on shutdown.

---

## 10. Error mapping

Driver errors never cross the port boundary (`errors.ts`). The original is kept only as the internal
cause, which `toJSON()` omits — tested: no SQL, constraint name or driver text reaches the wire.

| SQLSTATE | Meaning | Adapter failure | Spec code |
|---|---|---|---|
| `23505` | unique_violation | Conflict | `CONFLICT` |
| `23503` | foreign_key_violation | NotFound | `NOT_FOUND` |
| `23502`, `23514`, `22xxx` | not-null / check / data | Invalid | `VALIDATION_FAILED` |
| `AE0xx` | Aegis integrity trigger fired | defect | `INTERNAL` |
| `40001`, `40P01` | serialization / deadlock | retried, then Unavailable | `STORAGE_UNAVAILABLE` |
| `55P03`, `57014` | lock / statement timeout | Unavailable | `STORAGE_UNAVAILABLE` |
| `08xxx`, `53xxx`, `57Pxx`, socket errors | connection / resources / shutdown | Unavailable | `STORAGE_UNAVAILABLE` |
| `25P02` | statement in an aborted transaction | Unavailable | `STORAGE_UNAVAILABLE` |
| anything else | unknown — outcome unknown | Unavailable | `STORAGE_UNAVAILABLE` |

Errors thrown by the domain inside a unit propagate **unchanged**; only database errors are mapped.

**A unit that swallows a database error cannot commit.** After a failed statement PostgreSQL aborts
the transaction and silently turns a later `COMMIT` into `ROLLBACK`. The runner records the *first*
failure (later statements only report `25P02`) and, if `fn` returns normally anyway, rolls back and
raises that first failure instead of reporting success. Tested.

---

## 11. Testing

`npm run test:pg` starts a throwaway PostgreSQL 17 (`embedded-postgres`, prebuilt binaries, no
Docker) unless `AEGIS_PG_URL` points at a server; CI uses a `postgres:17` service container. Each test
file creates and drops its own database, so files run in parallel without interfering.

| File | Cases | What it proves |
|---|---|---|
| `contract.pg-test.ts` | 25 × 2 | Identical storage-contract behaviour on **both** adapters (memory and PostgreSQL) |
| `concurrency.pg-test.ts` | 13 × 2 | Every race invariant, on parallel connections, under **both** isolation levels |
| `transactions.pg-test.ts` | 16 | Rollback, swallowed-error refusal, retry on `40001`, ambient routing, error mapping, lock timeout, triggers, audit append-only, migrations, housekeeping, INV-ID-01 |
| `flows.pg-test.ts` | 11 | Phase 1 conformance flows end to end through `createAuth`, audit persisted to PostgreSQL |
| `keys.pg-test.ts` | 23 | KeyStore contract (12), sign/verify across rotation, restart persistence, concurrent startup and rotation from separate pools, master key required, ciphertext-only storage, schema guards (§13) |

The Phase 1 suite (`npm test`, 121 tests) still runs against the in-memory adapter, unchanged.

---

## 12. Changes outside the adapter

Three, each required for the spec to hold on a real database, each behaviour-preserving for every
Phase 1 test:

1. **`AssignmentService` emitted audit events inside its unit of work** (spec §11.4 violation). With
   a database that can retry or roll back a transaction, that produces duplicate or orphan events.
   The events are now emitted after commit; the unit contains storage work only.
2. **The in-memory `touch` could extend an idle-expired session** (§5.5 "a touch MUST NOT resurrect",
   INV-SESS-02). It now refuses, matching the PostgreSQL adapter; the shared contract test covers it.
3. **The refresh flow passed a store-level `PRECONDITION_FAILED` from `rotate` through unmapped.**
   Fixed: `RefreshService.refresh` maps it to `TOKEN_INVALID` at its public boundary
   (errors.md §3), covered by a unit test. The adapter's lock order also makes that path unreachable
   (§5), so this is defence in depth.

---

## 13. Signing keys (Phase 3.5) — `PostgresKeyStore`

`storage.keys` persists JWT signing keys so that every instance signs and verifies with the same
keyring and keys survive restarts. Wiring, rotation and the JWKS endpoint are described in
[`JWKS.md`](JWKS.md); this section covers the schema and its guarantees.

### Schema (`migrations/003_create_keys_table.sql`)

| Table | Columns | Notes |
|---|---|---|
| `signing_key_registry` | `kid` PK, `registered_at_ms` | Every kid ever created. Never deleted from, so a kid can never be reused, not even after `remove` (`CONFLICT`). |
| `signing_keys` | `kid` PK → registry, `type` `RSA`\|`HMAC`, `status` `pending`\|`active`\|`retired`, `created_at_ms`, `activated_at_ms`, `retired_at_ms`, `public_material` jsonb, `private_material` bytea, `metadata` jsonb | One row per live key; `remove` and `prune` delete rows here only. |

**Invariants enforced by the database itself:**

| Mechanism | Invariant |
|---|---|
| partial unique index `signing_keys_one_active ON ((true)) WHERE status = 'active'` | at most one active key, whatever the application does |
| CHECK `signing_keys_private_sealed`: `private_material` starts with `AEK1` | no plaintext private key is ever stored in PostgreSQL |
| CHECK on `public_material`: NULL for HMAC; for RSA exactly `{kty, n, e}` | private members (`d`, `p`, …) cannot be stored in the public column |
| CHECKs `status_times`, `time_order` | timestamps match the status; `created ≤ activated ≤ retired` |
| trigger `signing_keys_guard` | a retired key is frozen (`AE030`); no key returns to pending (`AE031`); kid, type, material and `created_at_ms` are immutable (`AE032`) |

`private_material` is an AES-256-GCM envelope (`AEK1 | nonce(12) | tag(16) | ciphertext`) sealed in
the application under the master key, with `aegis-signing-key:v1:<kid>` as additional data. The
database never sees the master key or a plaintext private key. Opening the provider with
`storage: 'postgres'` and no master key is `CONFIG_INVALID`.

### Concurrency: the keyring lock

Every mutation runs in `keys.atomically`, a transaction that first takes
`pg_advisory_xact_lock(hashtextextended('aegis.keyring', 0))`. It serialises rotations and makes
"create a key if the store is empty" (first start of several instances) produce exactly one key.
`activate` retires the current active key and activates the new one in that same transaction, the
old one first so the one-active index is never violated mid-way; an activation instant earlier than
the current key's activation (clock skew between instances) is refused with `VALIDATION_FAILED` and
changes nothing.

This is a **third lock domain**: key operations take no user, session, token or role lock, and no
authentication flow takes the keyring lock, so it cannot join a deadlock cycle with §2. Signing and
verification never touch the database; they use each instance's in-memory copy of the keyring.

### Reads and pruning

The provider reloads the whole keyring (`listKeys`) every `refreshIntervalMs` and on an unseen kid.
The table holds a handful of rows; `signing_keys_status_idx` serves `getActiveKey` and
`signing_keys_retired_at_idx` (retired rows only) serves `prune(olderThan)`, which deletes retired
keys whose `retired_at_ms < olderThan`. The provider prunes only keys that can no longer verify
anything (`retiredAt + ttl + leeway ≤ now`).

### Master key handling

The master key comes from one environment variable (`AEGIS_MASTER_KEY` by default). Distributing it
to instances — a cloud secret manager, Kubernetes Secrets, Vault — is the deployment's job and is not
implemented here; see [`JWKS.md`](JWKS.md) §7. Keep it out of the database and its backups: a
database dump then contains only ciphertext.
