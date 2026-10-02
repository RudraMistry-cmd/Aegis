# Aegis Core — Phase 1 reference implementation

Aegis is a reusable authentication and authorization foundation designed to be dropped into many
applications instead of being rebuilt each time. This repository contains the **specification**
(`spec/`) and the **Phase 1 reference implementation** of its core domain (`src/`): pure TypeScript
with no framework, no database, no HTTP layer and no network calls. Its job is to prove the
specification is implementable and self-consistent, so later phases can add adapters (PostgreSQL,
Express, FastAPI) without redesigning anything.

Authentication produces a `Principal`; authorization consumes only a `Subject`. RBAC decides broad
permissions, policies add contextual constraints, and every decision is deny-by-default.

## Quick start

```bash
npm install
npm run build
npm test
npm run test:pg
npm run start-demo
```

- `npm run build` — type-checks and compiles `src/`, `test/` and `examples/` to `dist/`.
- `npm test` — builds, then runs the unit and conformance suites with the Node test runner.
- `npm run test:pg` — runs the PostgreSQL adapter suite against a real PostgreSQL 17. It starts a
  throwaway server itself (prebuilt binaries via `embedded-postgres`, no Docker), or uses
  `AEGIS_PG_URL` when set. `npm run test:all` runs both suites.
- `npm run lint` — ESLint plus a Prettier format check.
- `npm run start-demo` — runs [`examples/in-memory-demo.ts`](examples/in-memory-demo.ts): register,
  login, authorize, refresh with rotation, replay detection, logout, and the resulting audit trail.

Node 22 or newer is required. The core has no runtime dependencies and no native builds; the
PostgreSQL adapter needs only the pure-JavaScript `pg` driver (an optional peer dependency).

## PostgreSQL

```ts
import { createPostgresStorage, PostgresAuditSink } from 'aegis-core/postgres';

const storage = createPostgresStorage({ connectionString: process.env.DATABASE_URL! });
await storage.migrate(); // applies migrations/*.sql once each; safe on every start
const auth = createAuth({ storage, audit: new PostgresAuditSink(storage.client), /* … */ });
```

The adapter keeps every invariant under real concurrency: a refresh token is consumed exactly once,
the session limit holds under parallel logins, and a revoked session is invalid on the very next
request. [`docs/POSTGRES.md`](docs/POSTGRES.md) explains how — lock order, isolation choice (with
measurements), the SQL for each operation, and error mapping. Point `connectionString` at the
primary, not a read replica.

## Using it

```ts
import {
  createAuth, createMemoryStorage, defineCatalog, definePolicy,
  ScryptHasher, StubAccessTokenProvider, SystemClock, CryptoRandom, CryptoIdGenerator,
} from 'aegis-core';

const catalog = defineCatalog({
  permissions: ['post:read', 'post:update'],
  features: { hierarchy: true },
  roles: {
    reader: { permissions: ['post:read'] },
    author: { inherits: ['reader'], permissions: ['post:update'] },
  },
});

const postPolicy = definePolicy({
  name: 'post-ownership',
  resource: 'post',
  rules: { update: ({ subject, resource }) => resource.authorId === subject.id },
  scope: { update: ({ subject }) => ({ op: 'eq', field: 'authorId', value: subject.id }) },
});

const ids = new CryptoIdGenerator();
const auth = createAuth({
  storage: createMemoryStorage(),
  hasher: new ScryptHasher(),
  accessTokens: new StubAccessTokenProvider({
    secret: process.env.TOKEN_SECRET!, issuer: 'my-api', audience: 'my-api', ids,
  }),
  clock: new SystemClock(), random: new CryptoRandom(), ids,
  catalog, policies: [postPolicy],
});

await auth.authn.register({ identifier: 'ada@example.com', password: 'a-long-enough-password' });
const { principal, credentials } = await auth.authn.login({
  identifier: 'ada@example.com', password: 'a-long-enough-password',
});

await auth.authz.can(principal, 'update', { type: 'post', authorId: principal.id }); // true
await auth.authz.assert(principal, 'update', somePost);                              // throws FORBIDDEN
const scope = await auth.authz.authorizeScope(principal, 'update', 'post');           // filter for lists

const rotated = await auth.authn.refresh({ refreshToken: credentials.refreshToken });
await auth.authn.logout({ principal });
```

Every public call takes an explicit `Subject` or `Principal` — there is no ambient "current user".
Authorization decisions are values (`authorize`, `can`); only `assert` throws.

## Where the specification lives

`spec/` is the normative source and was frozen before implementation:

| Area | Files |
|---|---|
| Authentication contracts | `spec/auth/principal.md`, `session.md`, `tokens.md` |
| RBAC | `spec/rbac/permissions.md`, `roles.md`, `assignments.md` |
| Policy and list scoping | `spec/policy/policy.md`, `scope.md` |
| Storage and supporting ports | `spec/storage/interfaces.md` |
| Flows | `spec/flows/login.md`, `refresh.md`, `revoke.md` |
| Errors, invariants, conformance | `spec/errors.md`, `invariants.md`, `conformance.md` |

Every source file names the specification section it implements in its first comment, and
[`docs/DESIGN.md`](docs/DESIGN.md) holds the architecture rationale behind it all.

## How the tests map to the specification

- `test/unit/` — the mandatory Phase 1 behaviours: login, refresh rotation, the refresh reuse
  attack, revocation, RBAC resolution and permission denial.
- `test/conformance/` — 61 cases taken from `spec/conformance.md`, each labelled with its case id
  (for example `REF-04`, `AZ-DENY-01`, `RACE-06`) and the GIVEN / WHEN / THEN of the spec.
  [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md) lists them and records where this implementation
  deliberately deviates or cannot verify a case in memory.
- `test/postgres/` — 103 cases on a real PostgreSQL: the storage contract run against **both**
  adapters, 13 race scenarios under two isolation levels, transaction and integrity cases, and the
  storage-dependent conformance flows end to end.

## Layout

```
spec/              normative specification (input to this phase, unchanged by it)
src/domain/        pure types: Subject, Principal, User, Session, RefreshToken, Permission, Assignment
src/errors/        the error catalog and factory of spec/errors.md
src/ports/         port interfaces (storage + Clock, Hasher, RateLimiter, Audit) and simple defaults
src/rbac/          catalog, role and permission resolution, assignment service with escalation guards
src/policy/        policy definitions, the decision engine, and the list-scope constraint language
src/auth/          login, refresh, revoke, request resolution, session and token issuance
src/storage/memory in-memory reference adapter with simulated atomicity
src/storage/postgres PostgreSQL adapter: stores, transaction runner, locks, error mapping, audit sink
migrations/        SQL schema: 001 tables, constraints and integrity triggers; 002 indexes
test/              unit and conformance suites; test/postgres/ for the PostgreSQL adapter
examples/          runnable in-memory demo
```

Dependencies point inward: `src/policy` and `src/rbac` never import `src/auth`, and only
`src/storage/postgres` imports a database driver. The package root does not import it, so core
users never load `pg`.

## Status and scope

Phase 1 implemented the core domain; Phase 2 adds the PostgreSQL storage adapter. Not implemented,
by design: other databases, HTTP or framework integration, a real JWT provider and key rotation, a
caching layer, email delivery and the verification/password-reset flows that need it, MFA,
OAuth/OIDC, passkeys, API keys, and multi-tenant scoped assignments. Each gap is marked with a `TODO` naming the spec section, and
`docs/CONFORMANCE.md` lists them in one place.

License: [MIT](LICENSE).
