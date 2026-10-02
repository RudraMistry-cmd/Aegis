# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow semantic versioning, where
the major version also tracks the major version of the specification in `spec/`.

## [0.4.0] — 2026-10-02

Phase 3.5: durable signing keys and a JWKS endpoint, so tokens stay verifiable across restarts and
instances. Verification semantics are unchanged: signature first, then the session store.

### Added

- **`KeyStore` port** with PostgreSQL (`storage.keys`), single-process file (`FileKeyStore`) and
  in-memory (`InMemoryKeyStore`) adapters, sharing one contract test suite. Lifecycle pending →
  active → retired; at most one active key; kids registered forever.
- **`migrations/003_create_keys_table.sql`**: `signing_key_registry`, `signing_keys`; the schema
  itself enforces one active key, sealed-only private material, public-only public material and a
  one-way lifecycle.
- **Encryption at rest** (`src/auth/jwt/keySealing.ts`): AES-256-GCM under the master key from
  `AEGIS_MASTER_KEY` (configurable name), bound to the kid. Required for PostgreSQL; file/memory
  without it log an explicit "unencrypted" warning.
- **`openJwtAccessTokens` / `PersistentKeyProvider`**: loads the keyring at startup
  (`keys.generateIfMissing` for an empty store), reloads it every `keys.refreshIntervalMs` and on an
  unseen kid; `stage`, `activate`, `rotate`, `retire`, `remove`, `prune`. Fails startup with
  `CONFIG_INVALID` when there is no usable active key.
- **JWKS** (`src/auth/jwt/jwks.ts`): `createJwksHandler` serves `/.well-known/jwks.json` (configurable)
  with `kty kid alg use n e` only, `Cache-Control: max-age=keys.jwks.cacheTtlSec`. Publishes active,
  pending and in-window retired RSA keys; HS256 is refused.
- **Docs**: `docs/JWKS.md` (wiring, verifier caching, multi-instance rollout, compromise, secret
  managers and HSMs); `docs/POSTGRES.md` §13 (key schema and lock domain).
- Tests: 28 key-store, 18 persistent-provider, 7 JWKS unit tests; 23 PostgreSQL key tests.

### Changed

- `KeyProvider` gained `verificationKeys(now)`; `keyProvider.ts` exports `importKey` and
  `canVerifyAt` (behaviour-preserving refactor; the 32 Phase 3 tests are unchanged).

## [0.3.0] — 2026-10-02

Phase 3: real JWT access tokens with key rotation. The JWT is a transport; the session remains the
single source of truth.

### Added

- **`JwtAccessTokenProvider`** (`src/auth/jwt/jwtProvider.ts`): RS256 or HS256 via `node:crypto` (no
  new dependency); `kid` in the header; claims `iss aud sub sid iat exp jti sv typ` and nothing
  else. Verification never throws, checks the signature before any claim, rejects `alg: none`,
  algorithm confusion, key-selecting headers (`jku`, `jwk`, `x5u`, `crit`, …), duplicate claims and
  non-canonical base64url.
- **`InMemoryKeyProvider`** (`src/auth/jwt/keyProvider.ts`): `getActiveKey`, `getKeyById`, and
  rotation (`rotate`, or two-phase `stage` → `activate`), `remove` for compromised keys, `prune`.
  Retired keys verify for exactly ttl + leeway and only for tokens issued before retirement.
- **`authn.authenticate`**: like `resolve`, but raises `UNAUTHENTICATED`, `TOKEN_EXPIRED` or
  `TOKEN_INVALID` instead of returning null.
- **Configuration**: `tokens.{algorithm, issuer, audience, ttl, leewayMs}` and
  `keys.rotationEnabled`, validated at construction; `createAuth` rejects a core access TTL that
  differs from the provider's.
- 32 tests in `test/unit/jwt.test.ts`, plus a deterministic regression test for the race below.

### Changed

- The stub access-token provider is removed. Test fixtures, the PostgreSQL harness and the demo use
  the JWT provider, so every existing suite now runs on real JWTs.

### Fixed

- **PostgreSQL: a login could create an active session for an account suspended mid-login**
  (INV-STATE-01). Inside a unit of work, `users.getById` now takes the user row lock, so the state a
  login decides on cannot change before its session is created.

## [0.2.0] — 2026-10-02

Phase 2: a PostgreSQL storage adapter that keeps every invariant under real concurrency.

### Added

- **PostgreSQL adapter** (`src/storage/postgres/`, published as `aegis-core/postgres`) implementing
  every storage port: users, identifiers, credentials, sessions, refresh tokens, assignments and the
  role-catalog mirror, plus a non-blocking append-only audit sink.
- **Transaction runner**: a real `UnitOfWork` with nested-join semantics, ambient-transaction
  routing (store calls made inside a unit always run in it), refusal to commit a unit that swallowed a
  database error, and bounded jittered retry on `40001`/`40P01` only.
- **Concurrency design**: READ COMMITTED by default with row locks in one global order (per-user row
  lock, then sessions, then tokens) and per-role advisory locks for last-superuser accounting;
  SERIALIZABLE available as an option. Measured trade-offs in `docs/POSTGRES.md`.
- **Schema** (`migrations/001_init.sql`, `002_indexes.sql`): constraints and triggers that make the
  database itself refuse to resurrect a revoked session, reactivate or fork a refresh-token family,
  change immutable session fields, reuse a deleted user id, or modify an audit event. Idempotent
  migration runner with an advisory lock.
- **Tests** (`test/postgres/`, `npm run test:pg`): 103 cases against a real PostgreSQL 17 — the
  storage contract on both adapters, 13 race scenarios under both isolation levels, transaction and
  integrity cases, and end-to-end flows. CI runs them against a `postgres:17` service container.
- `docs/POSTGRES.md`: the consume race, session-limit enforcement, revocation visibility, isolation
  choice, lock order, per-operation SQL and error mapping.

### Fixed

- `AssignmentService` emitted audit events inside its unit of work (spec §11.4); a retried or
  rolled-back transaction could duplicate or orphan them. They are now emitted after commit.
- The in-memory `touch` could extend an idle-expired session (spec §5.5, INV-SESS-02).

### Documented

- Deviation D-10: the default isolation provides serializable outcomes by locking rather than the
  SERIALIZABLE level that spec §11.3 names, for measured liveness reasons; SERIALIZABLE is supported.

## [0.1.0] — 2026-10-02

First release: the Phase 1 reference implementation of the Aegis core domain. Pure TypeScript with
no runtime dependencies, no framework, no database and no network access.

### Added

- **Specification** (`spec/`, frozen before implementation): authentication contracts
  (`auth/principal.md`, `session.md`, `tokens.md`), RBAC (`rbac/*`), policy and list scoping
  (`policy/*`), storage and supporting ports (`storage/interfaces.md`), the login, refresh and
  revoke flows (`flows/*`), plus `errors.md`, `invariants.md` and `conformance.md`.
- **Domain models** (`src/domain/`): `Subject`, `Principal`, `User`, `Identifier`, `Credential`,
  `Session`, `RefreshTokenRecord`, `RoleAssignment`, the permission grammar and the account-state
  machine, all immutable and framework-free.
- **Errors** (`src/errors/`): the 17-code catalog of `spec/errors.md` with fixed messages, a factory
  and the internal-reason mapping. Internal causes are never serialized.
- **RBAC** (`src/rbac/`): an immutable versioned catalog with full validation and lint, role and
  permission resolution with inheritance and deny precedence, and an assignment service carrying the
  escalation guards (self-assign, grant ceiling, last superuser, tenant boundary).
- **Policy** (`src/policy/`): the six-stage decision engine (validate, RBAC deny, RBAC allow, walls,
  resource policy, combine), four combination modes, fail-closed error handling, and the
  `authorizeScope` constraint language for list endpoints.
- **Authentication** (`src/auth/`): the login flow with throttling, equal-cost hashing and
  enumeration-safe responses; refresh-token rotation with reuse detection and an optional grace
  window; the common `terminate` revocation procedure with logout, logout-all, remote revoke and
  credential invalidation; and request resolution to a `Principal`.
- **Ports and defaults** (`src/ports/`): port interfaces for storage plus `Clock`, `Random`,
  `IdGenerator`, `PasswordHasher`, `RateLimiter`, `AttributeProvider`, `AuditSink` and
  `AccessTokenProvider`, with simple reference implementations including a controllable clock and an
  in-memory audit sink.
- **In-memory storage adapter** (`src/storage/memory/`): every store port with simulated A1/A2
  atomicity, an atomic `createWithLimit` for session limits, an atomic refresh-token `consume`, and
  a serializing `UnitOfWork` with snapshot rollback.
- **Tests**: 121 tests — unit coverage of login, refresh rotation, the reuse attack, revocation,
  RBAC resolution and permission denial, plus 61 cases labelled with their `spec/conformance.md`
  ids, including token reuse, concurrency races and mid-session permission changes.
- **Demo** (`examples/in-memory-demo.ts`), a CI workflow, and `docs/CONFORMANCE.md` recording the
  implemented cases, the nine documented deviations and the limits of in-memory atomicity.

### Known gaps

Database adapters, HTTP and framework integration, a real JWT provider with key rotation, a caching
layer, the `Notifier`-dependent flows (email verification, password reset, change-password), MFA,
OAuth/OIDC, passkeys, API keys and scoped multi-tenant assignments are all out of Phase 1 scope.
Each is marked with a `TODO` naming its specification section and listed in `docs/CONFORMANCE.md`.
