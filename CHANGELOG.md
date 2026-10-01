# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow semantic versioning, where
the major version also tracks the major version of the specification in `spec/`.

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
