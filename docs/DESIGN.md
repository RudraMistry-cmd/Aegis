# Aegis — Reusable Authentication & Authorization: Architecture Design

Status: architecture rationale for the system specified in [`../spec/`](../spec/).
Project name: **Aegis**. Package namespace: `@aegis/*`.

> **Where to look for what**
>
> - **Normative contracts** live in [`../spec/`](../spec/), not here. That is what implementations
>   must satisfy: `spec/auth/*`, `spec/rbac/*`, `spec/policy/*`, `spec/storage/interfaces.md`,
>   `spec/flows/*`, `spec/errors.md`, `spec/invariants.md`, `spec/conformance.md`.
> - **This document** records the *reasoning*: goals and non-goals, the module boundaries, the
>   threat model and the decision log with the alternatives that were rejected. Read it to
>   understand why the spec says what it says.
> - **Phase 1 implementation status**, including every deliberate deviation from the spec, is in
>   [`CONFORMANCE.md`](CONFORMANCE.md).
>
> Phase 1 implements the core domain in `../src/` (no framework, no database, no HTTP). The package
> layout below describes the eventual multi-package shape; the current tree is a single package with
> the same internal boundaries (`src/domain`, `src/rbac`, `src/policy`, `src/auth`, `src/ports`,
> `src/storage/memory`).
>
> **Minimal usage** (full example in [`../README.md`](../README.md) and
> [`../examples/in-memory-demo.ts`](../examples/in-memory-demo.ts)):
>
> ```ts
> const auth = createAuth({ storage, hasher, accessTokens, clock, random, ids, catalog, policies });
> await auth.authn.register({ identifier: 'ada@example.com', password });
> const { principal, credentials } = await auth.authn.login({ identifier: 'ada@example.com', password });
> await auth.authz.assert(principal, 'update', post);        // throws FORBIDDEN on deny
> await auth.authn.refresh({ refreshToken: credentials.refreshToken });
> await auth.authn.logout({ principal });
> ```

---

## 0. Executive summary (the decisions in one page)

| Question | Decision | One-line why |
|---|---|---|
| Core idea | **Authentication produces a `Principal`; authorization consumes a `Subject`.** They meet only at a tiny interface (`Subject`). | Lets you swap JWT/sessions/API keys without touching RBAC/policies. |
| Shape | Library of small packages (ports + engines), no framework, no DB, no `AuthService` god class | Composition, testability |
| Reference language | **TypeScript/Node first.** Python later, driven by a **language-neutral contract spec + conformance vectors** | One good implementation beats two half ones; the spec keeps ports honest |
| Reference DB | **PostgreSQL** (production), **in-memory** (tests/conformance), **SQLite** (dev/college). MongoDB: supported by contract, not first-party v1 | RBAC is relational; atomic token rotation needs real transactions/CAS |
| Default authn transport | **Short-lived signed access token (10–15 min) + opaque rotating refresh token, backed by a server-side session record** | Revocable, theft-limiting, multi-device |
| Alternate transport | Server-side opaque session cookie (same `SessionStore`) | Best default for first-party web apps |
| Password hashing | **Argon2id** (PHC string, per-hash random salt, rehash-on-login, optional pepper); scrypt/bcrypt as pluggable fallbacks | Current OWASP guidance |
| RBAC default | Multi-role, **allow-only**, flat; hierarchy / direct grants / deny are **opt-in** features | Predictability; every power feature is a misconfiguration surface |
| Permission format | `resource:action` (e.g. `user:read`, `auction:bid`), wildcards only by explicit opt-in | Greppable, lintable, structured |
| Permissions in tokens | **No** by default (token carries `sub`+`sid`; roles resolved server-side via cache) | Stale privilege after role change is the classic RBAC+JWT bug |
| Policy layer | Pure, typed functions per (resourceType, action). RBAC is the **gate**, policy is the **refinement**. Deny by default | "Broad permission by RBAC, contextual constraint by policy" |
| Lists | First-class `authorizeScope()` returns a query *constraint*, not N× `can()` | Without it, policies force N+1 loads / leaks |
| Multi-tenancy | Not v1 feature, but schema + types carry optional `scope` / `tenantId` from day one | Retrofit is the expensive part |

---

## 1. System goals and non-goals

### Goals
1. **Reusable foundation**: a project configures roles, permissions, policies, lifetimes, password rules, account states, and metadata **without editing the library**.
2. **Strict separation** between (a) *who are you / is this session valid* and (b) *may you do this*.
3. **Dependency inversion**: the core defines ports (interfaces); Postgres/Redis/Express/FastAPI/JWT libraries are adapters.
4. **Secure by default**: every default is the safe one; every unsafe option has a loud name (`allowInsecure…`) and an audit/boot warning.
5. **Predictable authorization**: deny-by-default, deterministic evaluation order, explainable decisions (`decision.reason`, `decision.trace`).
6. **Testability**: all time, randomness, IDs, and I/O injected; an in-memory adapter implements every port; a public **conformance suite** validates third-party adapters.
7. **Extensible** to MFA, passkeys, OIDC, API keys, service accounts, tenants, ABAC — via extension points, not rewrites.
8. **Small API surface**: 1 factory, a handful of verbs, framework middleware as thin shims.

### Non-goals (v1)
- Being an identity *provider* (no hosted login UI, no OIDC server, no SAML IdP).
- Shipping UI components.
- Implementing MFA/WebAuthn/OAuth/SSO/API keys/tenants (only **not blocking** them).
- Replacing infrastructure: WAF, DDoS protection, TLS termination, secret managers, email delivery.
- A policy *language* (Rego/Cedar). Policies are code in v1; a declarative engine can plug into the same port later.
- Cross-language single binary / sidecar. (Possible later; not the default.)
- Dynamic runtime-editable policy rules stored in DB (roles/assignments are dynamic; policy logic is code).

---

## 2. Recommended architecture

### 2.1 Layers

```
┌────────────────────────────────────────────────────────────────────────┐
│ Host application (routes, controllers, UI, business logic)             │
└───────────────▲───────────────────────────────▲────────────────────────┘
                │ middleware / decorators        │ direct calls
┌───────────────┴──────────────┐   ┌─────────────┴──────────────────────┐
│ INTEGRATIONS (thin shims)    │   │ FACADE  createAuth(config)         │
│ express, fastify, (fastapi*) │   │ wires modules, validates config    │
└───────────────┬──────────────┘   └─────────────┬──────────────────────┘
                │                                 │
   ┌────────────┴─────────────┐        ┌──────────┴──────────────┐
   │  AUTHENTICATION          │        │  AUTHORIZATION          │
   │  authn (flows)           │ Subject│  authz (decision engine)│
   │  credentials/password    ├───────►│   ├─ rbac engine        │
   │  tokens (access/refresh) │        │   └─ policy engine      │
   │  sessions                │        │                         │
   └────────────┬─────────────┘        └──────────┬──────────────┘
                │                                  │
                └───────────────┬──────────────────┘
                        ┌───────┴────────┐
                        │  CORE          │  domain types, ports (interfaces),
                        │  (zero deps)   │  errors, Result, Clock/Random/Id ports
                        └───────▲────────┘
                                │ implemented by
   ┌────────────┬───────────────┼───────────────┬──────────────┬─────────┐
   │ storage-   │ storage-      │ cache-redis / │ hasher-      │ token-  │
   │ postgres   │ sqlite/memory │ cache-memory  │ argon2/scrypt│ jwt/... │
   └────────────┴───────────────┴───────────────┴──────────────┴─────────┘
                    ADAPTERS (all depend inward on core only)
```

Rule: **dependencies point inward.** `core` imports nothing. `rbac` and `policy` import only `core`. `authn` imports `core`. `authz` imports `core`, `rbac`, `policy`. **`authz` never imports `authn`/`tokens`/`sessions`** (enforced by a lint/dependency-cruiser rule in CI). The facade is the only place that wires both.

### 2.2 The seam between authN and authZ

```ts
// core: the ONLY thing authorization knows about "who"
interface Subject {
  readonly id: string;
  readonly type: string;               // "user" | "service" | "apikey" ... (extensibility)
  readonly tenantId?: string;          // optional, for tenancy
  readonly attributes?: Readonly<Record<string, unknown>>; // ABAC fuel, project-defined
}

// authn output; extends Subject, adds authentication facts
interface Principal extends Subject {
  readonly sessionId?: string;
  readonly authMethod: string;         // "password" | "oidc:google" | "apikey"
  readonly authenticatedAt: Date;
  readonly amr?: string[];             // e.g. ["pwd","totp"] — lets policies require step-up
  readonly claims?: Record<string, unknown>;
}
```

Because `authz` takes a `Subject`, a policy can check `principal.amr.includes("totp")` for step-up without authz knowing what MFA is, and an API-key authenticator can produce a `Subject{type:"service"}` and reuse all RBAC/policies.

**Why this over a single `AuthService`:** a god class couples token format, DB access, and permission logic, so you can't unit-test a policy without a token, or swap JWT for sessions without touching authorization.

### 2.3 Why library-of-packages rather than alternatives
| Alternative | Why not default |
|---|---|
| Standalone auth microservice | Operational cost (deploy, network hop, HA) for college/internal projects; kills "just plug it in". Remains possible later by wrapping the facade in HTTP. |
| One monolithic package | Pulls Postgres+Redis+JWT deps into every consumer; hard to enforce boundaries. |
| Wrap Passport/Auth.js/Lucia/Casbin | They solve slices with their own models; RBAC+policy+session+rotation guarantees and a conformance spec wouldn't be ours. We *borrow ideas* (Casbin enforcer, Lucia sessions, Cedar decisions), and can adapt them behind ports. |

---

## 3. Module responsibilities

Proposed packages (names are deliberately by *responsibility*, not by technology):

| Package | Responsibility | Depends on | Key public exports |
|---|---|---|---|
| `@aegis/core` | Domain types, **ports**, error taxonomy, `Result`, `Clock`/`Random`/`IdGenerator`/`Logger` ports, `Subject`/`Principal`, config schema types | — | types/interfaces only + tiny helpers |
| `@aegis/identity` | User lifecycle, identifiers (email/username), account state machine, credential management, password policy, hashing orchestration (`PasswordHasher` port), verification & reset flows | core | `createIdentityService`, `AccountStateMachine`, `PasswordPolicy` |
| `@aegis/authn` | Authentication **flows** (login, refresh, logout, verify, reset) composed from small use-case functions; the `Authenticator`/`Strategy` registry; throttling hooks | core, identity | `createAuthenticator`, `AuthStrategy` |
| `@aegis/tokens` | `AccessTokenProvider` + `RefreshTokenService` contracts; key management (`KeyProvider`); default implementations: JWT (EdDSA/ES256), opaque tokens | core | `JwtAccessTokenProvider`, `OpaqueTokenProvider`, `KeyProvider` |
| `@aegis/sessions` | Session (device) lifecycle: create, touch, list, revoke, revoke-all, limits (max concurrent), refresh-family rotation & reuse detection | core | `createSessionManager` |
| `@aegis/rbac` | Role/permission registry (catalog), hierarchy resolution, effective-permission computation, deny rules, assignment service, caches, config linter | core | `createRbac`, `definePermissions`, `defineRoles` |
| `@aegis/policy` | Policy registry & evaluator, decision combining, scope (list) constraints, built-in policy helpers (`isOwner`, `sameTenant`, `withinTime`) | core | `definePolicy`, `createPolicyEngine` |
| `@aegis/authz` | **The authorization decision engine**: composes rbac + policy into `can/authorize/authorizeScope`, explanations, audit emission | core, rbac, policy | `createAuthorizer` |
| `@aegis/audit` | Typed audit events, `AuditSink` port, redaction, default sinks (console/JSON/memory) | core | `AuditEvent`, sinks |
| `@aegis/ratelimit` | `RateLimiter` port + in-memory sliding-window impl; login throttle policy (per identifier + per IP + global) | core | `createLoginThrottle` |
| `@aegis/auth` (facade) | `createAuth(config)`: validates config, wires modules, returns the one public object | all above | `createAuth` |
| `@aegis/express`, `@aegis/fastify` | Request → credentials extraction, cookie/header transport, middleware, error mapping, CSRF helper | auth facade (peer) | `authMiddleware`, `requireAuth`, `requireRole`, `requirePermission`, `authorizeResource` |
| `@aegis/storage-memory` / `-postgres` / `-sqlite` | Implement storage ports; ship migrations | core | `createXStorage` |
| `@aegis/cache-memory` / `-redis` | Implement `Cache`/`RevocationCache`/`RateLimiter` ports | core | |
| `@aegis/hasher-argon2` (+ `-scrypt`, `-bcrypt`) | Implement `PasswordHasher` | core | |
| `@aegis/mailer-*` | Implement `Notifier` port (email OTP/reset). Library never sends mail itself | core | |
| `@aegis/testkit` | Fake clock, deterministic RNG, in-memory everything, **port conformance suites**, security test helpers | core | `runStorageConformance`, `fakeClock` |

Why split `identity` / `authn` / `sessions` / `tokens`: they change for different reasons (account rules, flow orchestration, device policy, token format). `tokens` has no knowledge of users; `sessions` has no knowledge of passwords. This is what lets "JWT or server sessions or something else" be a config choice.

---

## 4. Domain model

```
User ───< Identifier (email|username|phone|external)         many identifiers per user
User ───< Credential (password | totp* | passkey* | ...)     typed, one table via `type`+opaque payload
User ───< Session ───< RefreshToken (family: one active, rest rotated/used)
User ───< RoleAssignment >─── Role ───< RolePermission >─── Permission
User ───< DirectGrant (optional; allow|deny)  >─── Permission
Role  ───< RoleInheritance (parent → child)                  optional
User ───< OneTimeToken (email_verify | password_reset | ...) hashed
          AuditEvent                                         append-only
          RevokedToken (jti/sid denylist, TTL)               only if access-token revocation enabled
* = future extension, schema-compatible
```

Key modelling choices:

- **`User` is minimal**: `id`, `status`, `createdAt`, `updatedAt`, `securityVersion` (int, bump to invalidate everything), plus `metadata` (typed per-project via generics; stored as JSON column or side table). The core never reads project metadata except what the host maps into `Subject.attributes`.
- **Identifiers separate from User**: allows email+username login, change of email, and later phone/external IDs. Stored **normalized** (`NFKC`, lowercase for email) with a uniqueness constraint on `(type, normalized_value)`.
- **Credential separate from User**: password hash is never on the user row/DTO; `Credential{id,userId,type,payload,createdAt,lastUsedAt}`. MFA/passkeys = new `type`.
- **Session = a device login = a refresh-token family.** Even in "JWT mode" a session row exists. This is the one deliberate departure from "stateless JWT purity" and is the reason revocation, device lists, and reuse detection work. (See ADR-04.)
- **Account state** is a configurable state machine, not an enum baked in: 

  ```ts
  states: {
    unverified: { canLogin: true,  canRefresh: true,  restricted: true },
    active:     { canLogin: true,  canRefresh: true },
    suspended:  { canLogin: false, canRefresh: false, revokeSessionsOnEnter: true },
    disabled:   { canLogin: false, canRefresh: false, revokeSessionsOnEnter: true },
  },
  transitions: { unverified:["active","disabled"], active:["suspended","disabled"], suspended:["active","disabled"] },
  initial: "unverified" // or "active" if verification not required
  ```
  Projects add states (e.g. `pending_approval`, `banned`, `graduated`). Entering a `revokeSessionsOnEnter` state revokes all sessions atomically.
- **IDs**: opaque strings generated via `IdGenerator` port (default UUIDv7 / ULID — sortable, non-guessable enough combined with auth; never expose sequential ints).
- **Permission/Role catalog vs assignments**: the *definition* of roles/permissions lives in **code (registry)**, synced to DB on boot (for FK integrity & admin UIs); *assignments* live in DB. (See §7.)

---

## 5. Authentication flow

### 5.1 Pluggable strategy model

```ts
interface AuthStrategy<TInput> {
  readonly id: string;                                   // "password", "oidc:google", "apikey"
  authenticate(input: TInput, ctx: AuthContext): Promise<Result<VerifiedIdentity, AuthError>>;
}
// Strategy proves "this is user X" → authn then applies account-state check, creates session, issues tokens.

interface SessionTransport {                              // how a session is *carried*
  issue(session, ctx): Promise<IssuedCredentials>;        // tokens or cookie
  resolve(requestCredentials, ctx): Promise<Principal | null>; // verify on each request
  revoke(...)
}
```
Two orthogonal axes — **how you prove identity** (`AuthStrategy`: password, OAuth, passkey…) and **how the session is carried** (`SessionTransport`: JWT+refresh, opaque cookie…). That orthogonality is what makes "choose JWT, sessions, or a future thing" a config choice, and "add OAuth later" an adapter.

### 5.2 Login (password strategy)

```
1. Normalize identifier. Check throttle(identifier, ip) → 429-style `RateLimited` (before any DB work that leaks existence).
2. Look up identifier → user + password credential.
   If not found: verify against a DUMMY hash of equal cost (constant-ish time), return generic InvalidCredentials.
3. hasher.verify(password, hash). Fail → record failure, audit `login.failed`, generic InvalidCredentials.
4. Account state gate: state.canLogin? If not → (see §11.4: reveal only AFTER correct password) AccountRestricted{state}.
5. If hash params outdated → rehash & store (transparent upgrade).
6. If MFA required for this user/state (future) → return `MfaChallenge` instead of session.
7. SessionManager.create(user, device meta, authMethod) → enforces maxSessions (evict oldest or reject per config).
8. Transport.issue → access token (short) + refresh token (opaque, hashed at rest).
9. Audit `login.succeeded`; reset throttle counters for identifier.
```

### 5.3 Per-request authentication (`resolve`)
- **JWT mode**: verify signature (alg allow-list, `kid` lookup), `iss`, `aud`, `exp`/`nbf` (with small leeway), `typ`; load nothing from DB on the hot path. Optional **revocation check** (config): compare `sid` against revocation cache and `sv` (security-version claim) against cached `User.securityVersion`. Trade: stricter = 1 cache lookup/request.
- **Session mode**: look up hashed session id in `SessionStore` (via cache with short TTL), check idle + absolute expiry, slide idle timer (throttled writes).
- Output: `Principal` or `null`. Never throws for "not logged in"; throws only for infrastructure errors.

### 5.4 Refresh with rotation and reuse detection

```
refresh(presentedToken):
  h = hash(presentedToken)
  atomically (single CAS/transaction):
     row = RefreshTokenStore.consume(h)    // UPDATE ... SET status='used', usedAt=now WHERE hash=h AND status='active' RETURNING *
  case consumed OK:
     check session not revoked, family not expired (absolute lifetime), account state.canRefresh
     issue NEW refresh token (same family, parentId = row.id), new access token
  case row exists but status='used'  → REUSE DETECTED:
     if within `reuseGraceWindow` (default 0–10s, for flaky networks/races) and same family and
        the successor is still unused → return same successor result (idempotent retry)
     else revoke entire family/session, audit `refresh.reuse_detected` (high severity), return InvalidToken
  case not found / expired → InvalidToken (generic)
```
Why rotation + reuse detection: a stolen refresh token is single-use; whichever party (attacker or victim) uses it second trips the alarm and kills the family. Honest limitation: if the attacker uses it *first*, the victim's next refresh trips the alarm — theft is detected at the next victim use, not prevented. Short absolute family lifetime and session lists in UI bound the damage.

### 5.5 Logout / revocation
- `logout(session)` → mark session revoked, mark family tokens revoked, optionally add `sid` to denylist until access-token `exp` (only if stricter revocation enabled).
- `logoutAll(user, {except?: sessionId})`, `revokeSession(id)`, "sign out other devices".
- Password change / reset / account suspension → `logoutAll` + bump `securityVersion`.

### 5.6 Optional flows (all built on `OneTimeTokenStore` + `Notifier` port)
- **Email verification**: 256-bit random token, **hash stored**, TTL 24h, single use; transitions `unverified → active`.
- **Password reset**: request always returns the same response (no enumeration), token 256-bit, hash stored, TTL 15–60 min, single use, invalidates all sessions on success, notifies old email. Reset does *not* log the user in by default.
- **Notifier port** sends; library never speaks SMTP.

---

## 6. Authorization flow

```
authorize(subject, action, resource?)        // "can this subject do action on resource?"
 1. Resolve target: resourceType (from string or resource.__type / registered resolver) + action
 2. RBAC gate:  perm = "resourceType:action"
       effective = rbac.effectivePermissions(subject)   // cached closure
       deny rules (if enabled) evaluated first → explicit DENY wins
       if !effective.allows(perm)  → DENY(reason: "missing permission", perm)   [unless policy mode says otherwise]
 3. Policy refinement (if a policy is registered for (resourceType, action) or resourceType):
       decision = policy(subject, action, resource, ctx)
       combine per `mode`
 4. Default: if no policy registered → RBAC result stands (configurable: `requirePolicyFor: [...]` forces deny-if-missing)
 5. Emit audit (deny always; allow optionally/sampled), return Decision
```

```ts
type Decision = { effect: "allow"|"deny"; reason: string; permission: string;
                  matchedBy?: string[]; trace?: TraceStep[] };   // trace only when explain: true

auth.can(subject, "update", post): Promise<boolean>                // convenience
auth.authorize(subject, "update", post): Promise<Decision>         // rich
auth.assert(subject, "update", post): Promise<void>               // throws ForbiddenError
auth.authorizeScope(subject, "read", "post"): Promise<Scope>      // list filtering (see §8.4)
```

Combination modes (per policy registration, default `rbacAndPolicy`):
| Mode | Semantics | Use |
|---|---|---|
| `rbacAndPolicy` (default) | need permission AND policy allow | owner-only edit, tenant isolation |
| `rbacOrPolicy` | permission OR policy allow | "owners may edit even without `post:update`" |
| `policyOnly` | permission ignored | fully contextual resources |
| `rbacOnly` | no policy | simple resources |

Why default to AND: failing closed. A policy can only *narrow* what RBAC granted unless the developer explicitly opts into `OR`, which the linter flags for review.

---

## 7. RBAC model

### 7.1 Concepts
- **Permission**: `resource:action` string, validated against a registry (`^[a-z][a-z0-9_-]*:[a-z][a-z0-9_*-]*$`). Wildcards (`user:*`, `*:read`, `*:*`) only if `allowWildcards: true`; `*:*` additionally requires the role to be marked `superuser: true`.
- **Role**: named bundle of permissions; may declare `inherits: [...]`.
- **Assignment**: `(subjectId, roleId, scope?, expiresAt?, grantedBy)`. `scope` is null (global) in v1 but exists in schema (tenant/org/resource) for extensibility. `expiresAt` supports temporary elevation.
- **Direct grant** (optional feature flag): `(subjectId, permission, effect: allow|deny, scope?, expiresAt?)`.

### 7.2 Resolution algorithm
```
effective(subject):
  roles   = directRoles(subject) ∪ implied roles via hierarchy closure (DAG, cycle-checked at boot/assign)
  allow   = ⋃ permissions(role) ∪ directAllow(subject)
  deny    = ⋃ denyPermissions(role) ∪ directDeny(subject)       // only if feature enabled
  result  = allow − deny   (deny > allow, always; wildcard-aware)
```

### 7.3 Tradeoffs and selected defaults

| Feature | Pros | Cons / risks | Default |
|---|---|---|---|
| Multiple roles per user | Real-world necessity; avoids role explosion | Union grows silently | **ON** |
| Role hierarchy (inheritance) | DRY (`admin ⊃ moderator ⊃ user`) | Hidden grants, cycles, harder audits, perf | **OFF**; opt-in, DAG-validated, max depth 5 |
| Direct user permissions | Fast exceptions | Bypasses role model → audit nightmare, permission sprawl | **OFF** |
| Deny overrides | Revoke one capability from a broad role; compliance | Order confusion, "why can't they?" debugging | **OFF**; if ON: *deny always wins*, no ordering games |
| Wildcard permissions | Compact superuser | Accidentally broad; new permissions auto-granted | **OFF** |
| Dynamic roles (DB-editable) | Admin UI for role editing (SaaS) | Privilege-escalation surface, runtime misconfig | **Code-defined catalog** is default; `dynamicRoles: true` allows tenant-defined roles composed *only from existing registered permissions* |
| Roles in token | No lookup | Stale after change; token bloat | **OFF** |

Rationale for "code-defined catalog + DB assignments": permissions are *API of the application* — they must exist in code to be enforced anyway, so declaring them in code lets the linter, TypeScript types, and tests see them. Roles are code-defined for the same reason (reviewable in PRs), with dynamic roles as an opt-in layering for products that need it.

### 7.4 Caching
- **L1 (in-process)**: `compiledRole → Set<permission>` closure, rebuilt when the **catalog version** (hash of role definitions) changes. Immutable; no invalidation bugs because code is the source.
- **L2 (per-subject)**: `subjectId → effective permissions` with short TTL (default 30–60 s) and **explicit invalidation** on assignment change (local + `Cache.publishInvalidate` for multi-instance via Redis pub/sub or version key). Staleness window is bounded and documented: *role removal takes effect within TTL or immediately if invalidation channel configured.*
- `securityVersion` bump bypasses caches (checked in L2 key).
- Cache is behind the `Cache` port; absence of a cache is valid (always compute).
- Tradeoff chosen: **bounded staleness over per-request DB hit**; configurable to 0 for high-sensitivity apps.

### 7.5 Anti-misconfiguration (built-in)
- `auth.doctor()` / boot-time linter: undefined permission referenced by a role; role with no permissions; cycles; wildcard use; roles that can assign roles without matching `role:assign` ceilings; permissions never referenced by any role/route; `rbacOrPolicy` usage; `*:*` on non-superuser.
- Snapshot-test helper: `expectRoleMatrix(auth).toMatchSnapshot()` → role×permission table in PRs so changes are visible.
- **Escalation guardrails** (library-enforced in the assignment service): assigner must hold `role:assign`; **grant ceiling** — cannot assign a role containing permissions the assigner lacks (configurable); cannot modify own roles; "last superuser" protection; every assignment audited with `grantedBy`.

---

## 8. Policy model

### 8.1 Shape
```ts
type PolicyFn<S extends Subject, R> = (args: {
  subject: S; action: string; resource: R; ctx: PolicyContext
}) => PolicyResult | Promise<PolicyResult>;

type PolicyResult = boolean | { effect: "allow"|"deny"; reason?: string };

definePolicy<Post>({
  resource: "post",
  mode: "rbacAndPolicy",
  rules: {
    update: ({subject, resource}) => resource.authorId === subject.id,
    delete: ({subject, resource}) => resource.authorId === subject.id || subject.attributes?.isModerator,
    "*":    ({subject, resource}) => resource.tenantId === subject.tenantId,   // applies to all actions, ANDed
  },
});
```
- Policies are **pure functions of (subject, action, resource, ctx)**. They must not do ad-hoc DB calls; if data is needed it is either on the resource object (host loads it) or fetched through an explicit, injectable `ctx.loaders` (declared in config) so authorization I/O is visible and mockable. This directly satisfies "no database calls scattered through authorization logic".
- Evaluation order within a resource: action-specific rule AND wildcard rule(s). Any explicit `deny` wins. Errors thrown in a policy → **deny + audit** (fail closed), never allow.
- `ctx` carries `now` (from `Clock` — time-based policies are testable), request metadata (ip, optional), and loaders.

### 8.2 Resource typing
`authorize(user, "update", post)` — resource type is found by (1) explicit string: `authorize(user,"update",{type:"post", ...})`, (2) a `resourceType` resolver registered in config (`resolveType: r => r.__type ?? r.constructor.name`). Never inferred magically; unknown type with no registered policy → RBAC-only (or deny if `strictPolicies: true`).

### 8.3 Covering the required scenarios
| Scenario | Mechanism |
|---|---|
| Edit only own resource | `resource.ownerId === subject.id` rule |
| Team access | `subject.attributes.teamIds.includes(resource.teamId)` — host maps team membership into `Subject.attributes` (or a `ctx.loaders.teams`) |
| Org admin manages users only in their org | RBAC: `user:update` held via `org_admin` role **scoped to org**; policy: `resource.orgId === subject.tenantId` |
| Moderator on certain resource states | `resource.state in ["reported","pending"]` |
| Time-based | `ctx.now` between window; helper `withinTime({days, hours, tz})` |
| Custom business rule | Any pure function, composed with helpers `allOf/anyOf/not` |
| Step-up | `subject.amr?.includes("totp")` for sensitive actions |

### 8.4 List/scope authorization (important and commonly missed)
`can(user,"read",post)` per row doesn't work for listing 10k rows. Policies may optionally declare a **scope**:
```ts
scope: { read: ({subject}) => ({ any: [ {eq:["authorId", subject.id]}, {eq:["published", true]} ] }) }
```
`authorizeScope(subject,"read","post")` returns a small, adapter-neutral constraint AST (`{all|any|eq|in|not}`) that storage adapters translate to SQL `WHERE` / Mongo filter. Policies that declare no scope → `authorizeScope` returns `{ unsupported }` and the host must filter in memory (explicit, never silently permissive). A test helper asserts `scope` and `rules` agree on sample data (consistency property test).

### 8.5 Future ABAC / external engines
`PolicyEngine` is a port. The built-in is function-based; an adapter for Cedar/OPA/Casbin can implement the same `evaluate()` contract. ABAC is thus "more attributes on Subject/resource + more policies", not a new subsystem.

---

## 9. Storage abstraction

### 9.1 Principles
- Core defines **small, purpose-specific ports** (interface segregation), not a generic `Repository<T>` and not one `AuthStorage` mega-interface.
- Ports express **intent and atomicity** (e.g. `consumeRefreshToken`), not CRUD. The adapter chooses SQL/Mongo ops.
- Ports return plain domain objects (no ORM entities); timestamps as `Date`; IDs as strings.
- Transactions via a `UnitOfWork` port: `storage.transaction(async tx => …)`. Adapters that can't do multi-doc txns must document which operations are individually atomic (and rotation/consume **must** be).

### 9.2 Ports
```ts
interface UserStore {
  create(u: NewUser): Promise<User>;                       // unique-violation → DuplicateError
  getById(id): Promise<User|null>;
  setStatus(id, status, expectedVersion?): Promise<User>;  // optimistic concurrency
  bumpSecurityVersion(id): Promise<number>;
  updateMetadata(id, patch): Promise<User>;
}
interface IdentifierStore {
  add(userId, type, value): Promise<Identifier>;           // stores normalized + display value
  findUserByIdentifier(type|types, normalizedValue): Promise<{user: User}|null>;
  remove(...)
}
interface CredentialStore {
  get(userId, type): Promise<Credential|null>;
  put(userId, type, payload): Promise<void>;               // replace
  touch(credentialId, at): Promise<void>;
}
interface SessionStore {
  create(s: NewSession): Promise<Session>;
  get(id): Promise<Session|null>;
  listByUser(userId, opts): Promise<Session[]>;
  revoke(id, reason): Promise<void>;
  revokeAllForUser(userId, except?): Promise<number>;
  touch(id, at): Promise<void>;                            // throttled by caller
  countActive(userId): Promise<number>;
  evictOldest(userId, keep: number): Promise<Session[]>;   // for max-session limits, atomic
}
interface RefreshTokenStore {
  insert(t: NewRefreshToken): Promise<void>;               // stores HASH only
  /** ATOMIC compare-and-set. */
  consume(hash, now): Promise<
     | { kind:"consumed"; token: RefreshToken }
     | { kind:"reused";   token: RefreshToken }            // was already used
     | { kind:"expired" | "revoked" | "unknown" }>;
  revokeFamily(familyId): Promise<void>;
  deleteExpired(before: Date): Promise<number>;
}
interface RevocationStore { // optional; only for strict access-token revocation
  add(key: string /* sid or jti */, expiresAt): Promise<void>;
  has(key): Promise<boolean>;
}
interface OneTimeTokenStore {
  put(t: {hash, userId, purpose, expiresAt, meta}): Promise<void>;
  consume(hash, purpose, now): Promise<OneTimeToken|null>;  // atomic, single-use
  invalidateForUser(userId, purpose): Promise<void>;
}
interface RoleCatalogStore {                                // mirror of code catalog; or dynamic roles
  sync(catalog: CatalogSnapshot): Promise<void>;
  getCatalogVersion(): Promise<string>;
}
interface AssignmentStore {
  assign(a): Promise<void>; unassign(...): Promise<void>;
  listRoles(subjectId, scope?): Promise<RoleAssignment[]>;   // excludes expired
  listSubjectsByRole(roleId, page): Promise<Page<string>>;
}
interface DirectGrantStore { /* optional */ }
interface AuditSink { write(e: AuditEvent): Promise<void> | void }  // may be non-DB (stdout, SIEM)
```
Plus non-storage ports: `Cache`, `Clock`, `Random`, `IdGenerator`, `PasswordHasher`, `Notifier`, `KeyProvider`, `RateLimiter`, `Logger`.

### 9.3 Backend discussion

| | PostgreSQL | SQLite | MongoDB |
|---|---|---|---|
| Fit for RBAC | Excellent (joins, FK, recursive CTE for hierarchy) | Good (same SQL subset) | Workable (embed roles array; no FK) |
| Atomic refresh `consume` | `UPDATE … WHERE status='active' RETURNING` | Same (single writer) | `findOneAndUpdate` — atomic on single doc ✔ |
| Multi-doc txn (e.g. revoke family + audit) | Native | Native | Needs replica set; avoid by design (single-doc atomic ops) |
| Unique identifiers | Unique index | Unique index | Unique index (collation for case) |
| Scope→filter translation | SQL | SQL | Mongo filter |
| Ops | Production-grade, RLS available for tenancy | Embedded; great for tests, small apps, college projects | Common in MEAN stacks |

**Recommendation: PostgreSQL is the reference production adapter**; **in-memory** is the reference *semantic* adapter (it defines behavior and runs the conformance suite in ms); **SQLite** as the second SQL adapter (shares most SQL, proves portability, perfect for college/dev); **MongoDB** adapter community/phase-3 — the ports are designed so each is implementable with single-document atomic ops, and conformance tests decide "supported" status.

Migrations ship with each SQL adapter (plain SQL files + tiny runner; host may instead copy them into its own migration tool). Tables are prefixed (`auth_`) and schema-configurable to avoid collisions.

---

## 10. Token / session strategy

### 10.1 Modes
| Mode | Carries | Pros | Cons | Pick when |
|---|---|---|---|---|
| **A. Access JWT + rotating opaque refresh + server session** (default for APIs/SPAs/mobile) | JWT in `Authorization`, refresh in httpOnly cookie (web) or secure storage (mobile) | Stateless hot path, revocable via session, multi-device, cross-service verification | Complexity; revocation lag ≤ access TTL unless strict | APIs, mobile, microservices |
| **B. Opaque server session cookie** (default for server-rendered first-party web) | Cookie with random 256-bit id, hash stored | Simplest, instant revocation, no token theft via JS, smaller attack surface | DB/cache hit per request; CSRF must be handled; cross-service harder | Web apps, internal tools, college projects |
| **C. Pure stateless JWT, no session row** | JWT only | No state | Can't revoke, no device list, no reuse detection | **Not offered by default** (explicit `unsafeStatelessMode`) |
| D. Opaque access tokens (introspection) | Random token | Instant revocation | Lookup per request | Offered through the same `AccessTokenProvider` port |

Both A and B use the same `SessionStore`; they differ only in `SessionTransport`. That is how "core doesn't depend on JWT" is satisfied: `authz` sees a `Subject`; `tokens` is one adapter family.

### 10.2 Default parameters (all overridable)
| Item | Default | Rationale |
|---|---|---|
| Access token TTL | **10 min** (max 60 enforced unless override flag) | Bounds revocation lag & theft window |
| Refresh token | 256-bit CSPRNG, stored as SHA-256 hash (high-entropy → no need for slow hash) | DB leak ≠ usable tokens |
| Refresh idle TTL | 14 days | |
| Session absolute TTL | 30–90 days (forces re-login) | Bounds stolen-chain lifetime |
| Rotation | Every use; reuse → family revoke; grace window 0 (opt-in up to 10 s) | |
| Max concurrent sessions | 10 per user; policy `evictOldest` or `reject` | Per-project |
| JWT alg | EdDSA (Ed25519) or ES256; HS256 allowed only when single-service; **`none` and alg-confusion impossible** (alg allow-list is config, not token) | |
| JWT claims | `iss, aud, sub, sid, iat, nbf, exp, jti, sv`(security version), `typ:"at+jwt"`; **no PII, no permissions** | |
| Session cookie | `__Host-` prefix, `HttpOnly; Secure; SameSite=Lax` (Strict optional), path `/` | |
| Refresh cookie (mode A web) | `__Host-`/path-scoped to `/auth/refresh`, `HttpOnly; Secure; SameSite=Strict` | Limits exposure & CSRF |

### 10.3 Strict revocation option
`revocation: "eventual"` (default; ≤ access TTL lag) | `"strict"` (per request check `sid` revoked + `sv` matches via Cache; 1 cache hit). Tradeoff documented in config.

### 10.4 Key management
`KeyProvider` port: returns `{activeKey, verificationKeys[]}` keyed by `kid`. Rotation = add new key as active, keep old verify-only for `max(accessTTL)+leeway`, then retire. JWKS export helper for multi-service verification. Keys come from env/secret manager via the host (library never stores keys on disk).

---

## 11. Security model

### 11.1 Responsibility matrix (library vs host vs infra)

| Concern | Library | Host app | Infra |
|---|---|---|---|
| Password hashing (Argon2id, salt, rehash, pepper support) | ✅ | supplies pepper from secret store | |
| Password policy (length, breach check hook, denylist) | ✅ validators + `BreachChecker` port | picks rules | |
| Token signing/verification, rotation, reuse detection | ✅ | | |
| Session revocation, limits | ✅ | triggers on business events | |
| Account-state gating | ✅ | defines states | |
| Login throttling per identifier/IP (algorithm + port) | ✅ (default in-memory) | supplies **trusted client IP** (proxy config) & shared store (Redis) | WAF, global DDoS, bot management |
| Timing-safe compare, dummy-hash on unknown user | ✅ | | |
| Enumeration-safe responses (login/reset/register) | ✅ default generic errors | keep UI copy generic | |
| Cookie flags & CSRF primitives | ✅ helpers in framework adapters | enables Origin checks, frontend sends header | |
| CORS | ❌ | ✅ | |
| TLS/HSTS | ❌ | | ✅ |
| XSS prevention (CSP, escaping) | ❌ (design reduces blast radius: httpOnly tokens, no localStorage guidance) | ✅ | CDN headers |
| Secret storage | ❌ (accepts via ports; refuses weak/short secrets at boot) | ✅ | Vault/KMS/Secrets Manager |
| Key rotation procedure | ✅ mechanism (`KeyProvider`) | runs it | schedules |
| Audit events | ✅ emit, redact | ships to SIEM/retention | log infra |
| Email delivery, anti-spam | ❌ (`Notifier` port) | ✅ | provider |
| Privilege-escalation guardrails in assignment API | ✅ | uses API not raw DB | DB perms |
| Authorizing *every route* | ❌ (can't know routes) — provides `requirePermission`, deny-by-default mode `auth.protectAll()` | ✅ | |
| DB encryption at rest, backups | ❌ | | ✅ |

### 11.2 Specific controls
- **Passwords**: Argon2id, defaults m=64 MiB, t=3, p=1 (≥ OWASP minimum of 19 MiB/t=2/p=1; documented tuning guide to hit ~100–250 ms). Salt: 16 B CSPRNG per hash, embedded in PHC string. Optional **pepper** (HMAC-SHA256 pre-hash with key from secret store; versioned for rotation). Max length 1024 (avoid DoS) and NUL/NFKC handling. Min 12 chars default; no composition rules (NIST 800-63B); optional `BreachChecker` (HIBP k-anonymity adapter).
- **Replay**: refresh single-use; JWT `jti`+`exp`; OTT single-use via atomic consume; password-reset tokens bound to purpose.
- **Token theft**: short access TTL; rotation + reuse detection; session list & remote revoke; `sv` bump on password change; optional device binding hint (UA/IP-change *signals*, not hard blocks) emitted as audit events.
- **Brute force**: per-identifier + per-IP + global sliding windows, exponential delay; **soft** lockout (delay/CAPTCHA hook) by default rather than hard account lock (hard lock = DoS vector). `ChallengeHook` port for CAPTCHA.
- **Timing**: constant-time comparisons for tokens/hashes; dummy Argon2 verify when user missing; uniform response shape/latency path.
- **Enumeration**: login, register ("check your email" always), reset request, verify all return uniform responses; account-state reveal (suspended) only after valid password.
- **Password reset**: random 256-bit, hash stored, short TTL, single use, invalidates sessions, no login-after-reset, notify on change, rate-limited per account+IP.
- **Email verification**: same token mechanics; changing email requires verifying new address, notifying old.
- **CSRF**: Mode A (bearer header) not CSRF-prone; refresh cookie is SameSite=Strict + path-scoped + requires custom header; Mode B uses SameSite=Lax + Origin/Sec-Fetch-Site check + optional synchronizer token helper.
- **XSS implications**: never persist access tokens in `localStorage`; docs recommend memory-only access token + httpOnly refresh cookie; XSS can still *use* the session (library can't fix) → CSP is host responsibility; step-up for sensitive actions mitigates.
- **Secrets**: boot validation (min 32 bytes, rejects known-default values), no secrets in logs/errors, `Secret` wrapper type with redacting `toString`.
- **Signing key rotation**: §10.4.
- **Audit logs**: events: `login.{succeeded,failed}`, `logout`, `refresh.reuse_detected`, `password.{changed,reset_requested,reset_completed}`, `account.state_changed`, `role.{assigned,revoked}`, `session.revoked`, `authz.denied`, `config.warning`. Fields: actor, subject, ip, ua, requestId, outcome, reason; **never** secrets/tokens/passwords; redaction layer; append-only semantics at sink.
- **Privilege escalation**: §7.5 guardrails; assignment API itself is authorized; role changes bump caches; admin actions optionally require step-up; self-assignment blocked; tenancy checks on assigner scope.
- **RBAC misconfiguration**: linter, role-matrix snapshots, deny-by-default `protectAll`, dev-mode "unprotected route" report, permissions typed so typos don't compile.

### 11.3 Error-handling stance
Typed errors with stable codes (`INVALID_CREDENTIALS`, `RATE_LIMITED`, `ACCOUNT_RESTRICTED`, `TOKEN_EXPIRED`, `TOKEN_INVALID`, `FORBIDDEN`, …). Library throws/returns typed errors; framework adapters map to HTTP (401/403/429). Externally-visible messages are generic; internal `cause` retained for logs only.

---

## 12. Extension points

| Future feature | Where it plugs in | Why current design doesn't block it |
|---|---|---|
| **MFA/TOTP** | New `Credential.type="totp"`; `AuthStrategy` step returns `MfaChallenge`; `Principal.amr` | Login flow step 6 is already a branch; credentials are typed rows |
| **Passkeys/WebAuthn** | New `AuthStrategy` + credential type (public key payload); challenge via `OneTimeTokenStore` | Strategy ≠ transport |
| **OAuth2/OIDC/SSO/social** | `AuthStrategy` adapter producing `VerifiedIdentity{provider, externalId, email}`; `Identifier(type:"external")` linking; account-linking policy hook | Identifiers separate from user |
| **External IdP as source of truth** | `UserStore`/`IdentifierStore` adapter or JIT provisioning hook | Ports, not tables |
| **API keys / service accounts / M2M** | `AuthStrategy`("apikey", "client_credentials") returning `Subject{type:"service"}`; keys stored hashed like refresh tokens; scoped to permissions | `Subject.type`, assignments keyed by subject id (not user table FK) |
| **Orgs/tenants** | `Subject.tenantId`, scoped assignments (`scope` column), policy helper `sameTenant`, per-tenant config resolver, Postgres RLS recipe | Nullable scope in schema & types from v1 |
| **ABAC** | `Subject.attributes`, resource attributes, `PolicyEngine` port | Policies already take (subject, action, resource, ctx) |
| **Custom hashers / key stores / caches / notifiers** | Ports | |
| **Lifecycle hooks** | `hooks: { beforeLogin, afterLogin, onSessionCreated, … }` — async, error-isolated, cannot weaken security checks (they can only *add* denials) | Gives hosts customization without forking |
| **Per-request overrides** | Strategy/config resolver by tenant | Config is data |

Rule for hooks: hooks may **veto**, never **bypass**. That prevents "hidden magic" and weakened security through extension.

---

## 13. Configuration design

Principles: one typed object, validated at boot (schema, fail fast with actionable messages), no globals, no env sniffing inside the library (host passes values), `readonly` after creation, `auth.describe()` prints effective config (secrets redacted).

```ts
const auth = createAuth({
  // ── infrastructure (required: ports → adapters) ──
  storage,                                // bundle of store ports (or per-port overrides)
  hasher,                                 // PasswordHasher
  cache,                                  // optional
  notifier,                               // optional (needed for verify/reset)
  audit,                                  // optional sink(s)
  clock, random,                          // optional (testkit overrides)

  // ── authentication ──
  authentication: {
    identifiers: ["email", "username"],
    strategies: [passwordStrategy({ policy: { minLength: 12, breachCheck } })],
    transport: jwtTransport({ keys, accessTtl: "10m", audience: "orbit-api",
                              refresh: { idleTtl: "14d", absoluteTtl: "60d", reuseGrace: "0s" },
                              revocation: "eventual" }),
    sessions: { max: 10, onLimit: "evict-oldest", idleTtl: "14d" },
    accountStates,                        // state machine (see §4) or preset: presets.basic
    verification: { email: "optional" | "required" | "off" },
    passwordReset: { enabled: true, ttl: "30m" },
    throttle: { identifier: {max:5, window:"15m"}, ip: {max:50, window:"15m"} },
    userMetadata: userMetadataSchema,     // zod/valibot/JSON-schema; typed via generics
  },

  // ── authorization ──
  authorization: {
    permissions,                          // definePermissions({...}) — typed registry
    roles,                                // defineRoles({...})
    features: { hierarchy: false, directGrants: false, deny: false, wildcards: false, dynamicRoles: false },
    cache: { subjectTtl: "30s" },
    policies,                             // [definePolicy(...), ...]
    strictPolicies: false,                // true → resources with no policy are denied
    protectAll: true,                     // routes without explicit requirement are denied (dev warns)
    escalationGuard: { grantCeiling: true, blockSelfAssign: true },
  },

  hooks, plugins,                         // extension points (see §12)
});
```

Definition helpers give compile-time safety:
```ts
const permissions = definePermissions({
  user:    ["read","update","delete","invite"],
  project: ["create","read","update","delete"],
  auction: ["create","read","update","bid","close"],
} as const);                               // → type Permission = "user:read" | ...

const roles = defineRoles(permissions, {   // typo in a permission = compile error
  member:    { permissions: ["project:read","auction:read","auction:bid"] },
  moderator: { inherits: ["member"], permissions: ["auction:close"] },
  admin:     { inherits: ["moderator"], permissions: ["user:*"] },
});
```

Presets (`presets.webApp`, `presets.api`, `presets.internalTool`) bundle safe parameter sets so beginners choose one word and advanced users override pieces.

---

## 14. Public API design

Language-agnostic **conceptual** surface (Section 16 shows TS and Python idioms):

```
createAuth(config) → Auth
Auth.authn        // authentication
  .register({identifier, password, metadata})
  .login({identifier, password, device?})  → {principal, credentials} | MfaChallenge
  .authenticateRequest(requestCredentials) → Principal | null      // transport-agnostic
  .refresh(refreshCredential)              → {credentials}
  .logout(principal) / .logoutAll(userId, {except?})
  .sessions.list(userId) / .sessions.revoke(sessionId)
  .verifyEmail(token) / .requestPasswordReset(identifier) / .resetPassword(token, newPassword)
  .changePassword(principal, old, new)
  .accounts.setStatus(userId, status, {reason})
Auth.authz        // authorization
  .can(subject, action, resource)           → boolean
  .authorize(subject, action, resource)     → Decision
  .assert(subject, action, resource)        → void | throws Forbidden
  .authorizeScope(subject, action, type)    → Scope
  .roles.assign / .revoke / .listFor(subject) / .permissionsFor(subject)
  .explain(subject, action, resource)       → Trace         // debugging misconfig
Auth.doctor()       → ConfigReport
Auth.shutdown()
```
Framework helpers (thin sugar over the above; no logic of their own):
`requireAuth()`, `requireRole("admin")` (documented as coarse; prefers permissions), `requirePermission("user:update")`, `authorizeResource("update", loader)` (loads resource then calls `authorize`), `optionalAuth()`.

**API rules**: every function takes an explicit `Subject/Principal` (no ambient/thread-local magic); one way to do each thing; all async; decisions are values, enforcement (throw) is a separate verb; no function both checks *and* mutates.

---

## 15. Repository structure

Monorepo (pnpm workspaces + Turborepo/Nx), language-neutral spec at the root.

```
Aegis/
├─ spec/                         # LANGUAGE-NEUTRAL SOURCE OF TRUTH (enables Python/Go ports)
│  ├─ ports/                     #  port contracts (JSON-schema/markdown) + semantics (atomicity rules)
│  ├─ flows/                     #  sequence specs: login, refresh/rotation, reset...
│  ├─ vectors/                   #  conformance test vectors (JSON): rbac resolution, policy cases,
│  │                             #   token validation, rotation/reuse state machine, password policy
│  └─ error-codes.md
├─ packages/
│  ├─ core/            src/{domain,ports,errors,result,config-types}  test/
│  ├─ identity/        src/{users,identifiers,credentials,states,password-policy,flows}
│  ├─ authn/           src/{strategies,login,refresh,logout,throttle,hooks}
│  ├─ tokens/          src/{access/{jwt,opaque},refresh,keys}
│  ├─ sessions/        src/{manager,limits,family}
│  ├─ rbac/            src/{catalog,resolver,hierarchy,deny,assignments,cache,linter}
│  ├─ policy/          src/{define,engine,combine,scope,helpers}
│  ├─ authz/           src/{authorizer,decision,explain}
│  ├─ audit/ ratelimit/
│  ├─ auth/            src/{createAuth,config-schema,presets,doctor}     # facade, only public entry for most users
│  ├─ integrations/
│  │   ├─ express/ fastify/ (hono/ next/ later)
│  ├─ adapters/
│  │   ├─ storage-memory/ storage-postgres/{src,migrations} storage-sqlite/ (storage-mongo/ later)
│  │   ├─ cache-memory/ cache-redis/ hasher-argon2/ hasher-scrypt/ mailer-nodemailer/
│  └─ testkit/         src/{fakes,conformance,security,fixtures}
├─ python/                       # PHASE 3: same spec, FastAPI integration (not started)
├─ examples/
│  ├─ campus-auction/            # Project A (small, sessions + SQLite)
│  ├─ orbit-saas/                # Project B (multi-tenant, JWT + Postgres)
│  └─ minimal-express/
├─ docs/
│  ├─ DESIGN.md (this) · adr/NNNN-*.md · concepts/ · guides/{quickstart,custom-adapter,key-rotation,hardening}.md
│  ├─ threat-model.md · security-policy (SECURITY.md) · reference/ (generated API docs)
├─ tools/ (dependency-cruiser rules, license check, release scripts)
└─ .github/workflows/ (ci: lint, typecheck, unit, conformance matrix [memory|sqlite|pg], security, fuzz, release)
```
**Public vs internal**: each package exposes one `index.ts`; everything else is `internal/` (not exported; enforced by `package.json#exports`). Semver applies to exports and to `spec/`. Adapter packages depend on `core` as a **peer** dependency with a narrow version range.

---

## 16. Integration examples

### 16.1 Two very different projects (proving reusability)

**Project A — "CampusAuction": college project, one server, SQLite, server-side sessions**
```ts
const permissions = definePermissions({
  auction: ["create","read","update","bid","close","remove"],
  report:  ["create","review"],
  user:    ["read","suspend"],
} as const);

const roles = defineRoles(permissions, {
  student:   { permissions: ["auction:read","auction:create","auction:update","auction:bid","report:create"] },
  moderator: { inherits: ["student"], permissions: ["report:review","auction:remove"] },
  admin:     { inherits: ["moderator"], permissions: ["user:read","user:suspend"] },
});

const policies = [
  definePolicy<Auction>({ resource: "auction", rules: {
    update: ({subject, resource, ctx}) => resource.sellerId === subject.id && resource.status === "draft",
    bid:    ({subject, resource, ctx}) => resource.sellerId !== subject.id        // can't bid on own
                                          && resource.endsAt > ctx.now,
    remove: ({resource}) => resource.reported === true,                           // moderators: reported only
  }}),
];

const auth = createAuth({
  storage: sqliteStorage({ file: "./auth.db" }),
  hasher: argon2Hasher(),
  ...presets.webApp,                              // opaque session cookie, 7d idle, eviction off
  authentication: {
    identifiers: ["email"],
    emailDomainAllowlist: ["college.edu"],        // via hook: beforeRegister
    accountStates: presets.states.basicWithUnverified,
    verification: { email: "required" },
    sessions: { max: 3 },
  },
  authorization: { permissions, roles, policies, features: { hierarchy: true } },
});
```

**Project B — "Orbit": multi-tenant B2B SaaS API, Postgres + Redis, JWT, MFA-ready**
```ts
const permissions = definePermissions({
  org:     ["read","update","billing"],
  member:  ["read","invite","update","remove"],
  project: ["create","read","update","delete","export"],
  apikey:  ["create","revoke"],
} as const);

const roles = defineRoles(permissions, {
  viewer:   { permissions: ["org:read","member:read","project:read"] },
  editor:   { inherits: ["viewer"], permissions: ["project:create","project:update"] },
  org_admin:{ inherits: ["editor"], permissions: ["member:*","project:delete","project:export","apikey:create","apikey:revoke"] },
  contractor: { inherits: ["editor"], deny: ["project:export","project:delete"] },      // deny feature
});

const policies = [
  definePolicy({ resource: "*", rules: { "*": ({subject, resource}) => resource.orgId === subject.tenantId }}), // tenant wall
  definePolicy<Project>({ resource: "project", rules: {
    export: ({subject, ctx}) => subject.amr?.includes("totp") === true                    // step-up
                                && ctx.now.getUTCHours() >= 6 && ctx.now.getUTCHours() < 22,
  }}),
];

const auth = createAuth({
  storage: postgresStorage({ pool }),
  cache: redisCache({ client: redis }),
  hasher: argon2Hasher({ pepper: secrets.PEPPER }),
  authentication: {
    identifiers: ["email"],
    transport: jwtTransport({ keys: kmsKeyProvider(), accessTtl: "5m", audience: "orbit-api",
                              refresh: { idleTtl: "7d", absoluteTtl: "30d", reuseGrace: "5s" },
                              revocation: "strict" }),
    sessions: { max: 20, onLimit: "evict-oldest" },
    accountStates: orbitStates,                   // adds "pending_approval", "offboarded"
    userMetadata: z.object({ displayName: z.string(), locale: z.string() }),
  },
  authorization: { permissions, roles, policies,
    features: { hierarchy: true, deny: true, dynamicRoles: true },
    strictPolicies: true, escalationGuard: { grantCeiling: true } },
  audit: [jsonStdoutSink(), siemSink],
});
```
Differences exercised: storage, transport, token lifetimes, hierarchy/deny/dynamic roles, policy mode, tenancy, MFA step-up, metadata, account states — **zero changes to any `@aegis/*` package**.

### 16.2 Express
```ts
app.use(aegisExpress.attach(auth, { transport: "bearer" }));       // resolves req.principal (or null)
app.post("/auth/login",   aegisExpress.loginHandler(auth));        // optional batteries
app.post("/auth/refresh", aegisExpress.refreshHandler(auth));

app.get("/projects/:id",
  requireAuth(),
  requirePermission("project:read"),
  authorizeResource("read", req => projects.findById(req.params.id)), // loads then policy-checks
  handler);

app.get("/admin", requireRole("admin"), …);                          // coarse; prefer permission
app.use(errorMapper(auth));                                          // typed error → 401/403/429 JSON
// imperative in service code:
await auth.authz.assert(req.principal, "update", post);
```
**How the adapter works**: (1) extract raw credentials from headers/cookies (`RequestCredentialExtractor`), (2) call `auth.authn.authenticateRequest()`, (3) put `Principal` on the request, (4) provide middleware that call `authz`, (5) map errors to HTTP, (6) set/clear cookies on login/refresh/logout. No business logic in the adapter — which is why a Fastify/Hono/Next adapter is ~150 lines.

### 16.3 FastAPI / Python
Two options, decision recorded in ADR-10:
1. **Native Python port (recommended, Phase 3)** implementing the same `spec/` (ports, flows, vectors) and passing the same conformance vectors; FastAPI integration via `Depends`:
```python
auth = create_auth(storage=SqlAlchemyStorage(engine), hasher=Argon2Hasher(), ...)

@app.get("/projects/{pid}")
async def get_project(pid: int, user = Depends(auth.require_permission("project:read"))):
    project = await repo.get(pid)
    await auth.authz.assert_(user, "read", project)
    return project
```
2. **JWT-verification-only interop** (available day one): Python services verify tokens issued by the Node service using the published JWKS and the `sid`/`sv` rules; for authorization they either call the Node authz endpoint or share the role catalog JSON. Good for microservice estates; not a full port.
A sidecar/HTTP service wrapping the Node facade is possible later, but not the primary route (extra hop and ops burden).

**Single-language decision**: build **TypeScript only first**. Reasoning: (a) two half-implementations double surface for security bugs; (b) the first implementation reveals port design mistakes cheaply — fix before freezing the spec; (c) TS gives literal-type-safe permissions (`as const`) that sell the DX; (d) the `spec/vectors` make the second port mostly mechanical and verifiable. Python starts only after the TS ports are declared stable (v1.0 of spec).

---

## 17. Threat model

Method: STRIDE over assets; attacker classes; trust boundaries.

**Assets**: credentials (password hashes, refresh/session tokens, reset tokens), signing keys, role assignments, audit trail, user PII.
**Trust boundaries**: client↔host app; host↔library (host trusted, supplies IP/headers); library↔storage; library↔key/secret store; host↔mailer.
**Attackers**: anonymous remote; authenticated low-priv user; malicious tenant admin; stolen device/token holder; XSS-capable attacker in browser; DB read-only attacker (backup leak/SQLi); malicious insider/dev; compromised dependency.

| # | Threat | Vector | Mitigation (where) | Residual / host duty |
|---|---|---|---|---|
| T1 | Credential stuffing / brute force | repeated login | Throttle per identifier+IP, delay, `ChallengeHook`, breached-password check (lib); WAF/bot rules (infra) | Correct client-IP config |
| T2 | User enumeration | differing errors/timing | Generic errors, dummy hash, uniform reset/register responses (lib) | Don't leak in UI/other endpoints |
| T3 | DB leak → offline cracking | stolen hashes | Argon2id + per-hash salt + optional pepper (lib) | Pepper in KMS |
| T4 | DB leak → token use | stolen refresh/session rows | Tokens stored only as hashes (lib) | |
| T5 | Refresh token theft | XSS/malware/log leak | Rotation + reuse detection, short access TTL, httpOnly cookie, session list/revoke (lib); CSP (host) | Attacker-first-use window |
| T6 | Access JWT theft | XSS/log leak | 5–15 min TTL, `strict` revocation option, no PII (lib) | |
| T7 | JWT forgery / alg confusion / `none` | crafted token | Server-side alg allow-list, `kid` from own keys, `typ`/`aud`/`iss` checks (lib) | Key secrecy |
| T8 | Key compromise | leaked signing key | `kid` rotation, verify-only retiring, emergency revoke-all by `sv`/key retire (lib mechanism) | Operational runbook |
| T9 | Session fixation | pre-set session id | New session id on every login/privilege change (lib) | |
| T10 | CSRF | cross-site request w/ cookies | SameSite, Origin/Sec-Fetch check helpers, header-based refresh (adapter) | App must use correct CORS |
| T11 | Replay of reset/verify tokens | reuse of link | Single-use atomic consume, short TTL, purpose-bound (lib) | |
| T12 | Account takeover via reset/email change | weak flow | Notify old email, re-verify, session invalidation, rate limits (lib) | Email account security |
| T13 | Vertical privilege escalation | assign self admin, forge role | Authorized assignment API, grant ceiling, self-assign block, last-admin guard, audit (lib) | Host must not bypass service with raw SQL |
| T14 | Horizontal escalation / IDOR | access others' resources | Policies, `strictPolicies`, `authorizeResource` pattern, scope filters (lib+host) | Host must call authorize on every resource access |
| T15 | Cross-tenant data access | missing tenant filter | `sameTenant` global policy, scoped assignments, scope→query constraint; RLS recipe (lib+infra) | |
| T16 | Stale privileges | role removed but cached | Bounded cache TTL + explicit invalidation + `sv` bump; no perms in token (lib) | Choose TTL |
| T17 | RBAC misconfiguration | wildcard/over-broad role | Linter, matrix snapshots, protectAll, typed permissions (lib) | Code review |
| T18 | Policy bug fails open | exception/undefined | Exceptions → deny; `undefined` ≠ allow; explicit return required (lib) | Test policies |
| T19 | Race conditions | double refresh, concurrent assign/revoke | Atomic CAS `consume`, optimistic version on user, idempotent revoke (lib+adapter conformance) | Adapter must pass conformance |
| T20 | DoS via expensive hashing | spam login | Throttle before hash, max password length, concurrency limit on hasher (lib); infra rate limit | |
| T21 | Log/audit tampering or leakage | tokens in logs | Redaction, append-only sink contract (lib); WORM/SIEM (infra) | |
| T22 | Supply chain | malicious dependency | Minimal deps in core (zero), pinned lockfile, provenance/SBOM, 2FA publishing (project) | |
| T23 | Malicious tenant admin | creating roles w/ powers | Dynamic roles composed only from permissions the creator holds (grant ceiling) (lib) | |
| T24 | Insider direct DB edit | SQL update assignment | Audit not guaranteed here; DB perms + integrity checks (`doctor`) (infra) | Out of scope |
| T25 | Clock skew/time attacks | expired-token acceptance | Leeway ≤ 60 s, injected `Clock`, monotonic checks in tests | NTP |

---

## 18. Testing strategy

### 18.1 Pyramid and tooling
- **Unit** (pure, fast, majority): fake `Clock`, deterministic `Random`, in-memory adapters. Vitest/Jest. Mutation testing (Stryker) on `rbac`, `policy`, `tokens`, `sessions` (security-critical — require high mutation score).
- **Property-based** (fast-check): RBAC resolution invariants, policy combination, rotation state machine.
- **Contract/conformance** (`@aegis/testkit`): the *same* suite runs against memory, SQLite, Postgres (Testcontainers), later Mongo; third-party adapters run it to be "certified".
- **Integration**: full flows through the facade + Express adapter via supertest; real Postgres + Redis in CI.
- **Security tests**: dedicated suite (below), plus fuzzing of token parsers and header extraction.
- **Cross-language vectors**: `spec/vectors/*.json` consumed by TS tests now, Python later.

### 18.2 Coverage map

| Area | Key cases |
|---|---|
| **Authentication** | login success/failure; email vs username; case & Unicode normalization; unknown user path executes dummy hash; state gating per state; rehash on login; password policy rejections; throttle thresholds; registration duplicate race |
| **Token rotation** | normal rotation chain; reuse → family revoked; reuse within grace returns same successor; expired/absolute-expired; refresh for suspended account denied; rotation survives crash between steps (idempotency); tokens stored hashed (DB dump contains no raw token) |
| **Session revocation** | revoke one; revoke all except current; password change revokes; state→suspended revokes; max-sessions eviction picks oldest; revoked `sid` rejected with `strict`, accepted ≤ TTL with `eventual` (documented behavior asserted) |
| **Role assignment** | assign/revoke; expiring assignments; scoped assignment; idempotent re-assign; escalation guard cases |
| **Permission inheritance** | transitive closure; diamond inheritance; cycle rejected at boot and at dynamic-role creation; depth limit; deny beats inherited allow; wildcard expansion |
| **Policy checks** | owner rule; tenant wall; state-based; time-based with fake clock around boundaries/DST/UTC; combinator modes; policy throws → deny; policy returns undefined → deny; async policy timeout → deny |
| **Privilege-escalation attempts** | low-role assigns admin; assign role containing permissions assigner lacks; self-assign; modify last admin; cross-tenant assignment; mass-assignment of `roles` in registration payload/metadata; token claim tampering (`sub`, `sid`, adding `roles`); `alg:none`; HS/RS confusion; wrong `aud/iss`; using refresh token as access token and vice versa (`typ`) |
| **Revoked credentials** | revoked session; revoked refresh family; disabled account's valid-signature JWT (via `sv`); deleted user |
| **Concurrency** | N parallel refreshes of same token → exactly one `consumed`, others reused/idempotent; parallel register same email → one wins; concurrent assign+revoke; max-session limit under parallel logins; cache invalidation race; reset token consumed twice in parallel → once |
| **Malformed tokens** | empty, huge (1 MB), wrong segment count, bad base64, invalid JSON header, unknown `kid`, huge `exp`, non-numeric claims, duplicate claims, unicode edge cases — all return `TOKEN_INVALID`, never throw/crash/leak |
| **Expired tokens** | `exp` boundary ±leeway, `nbf` future, clock-skew; refresh after idle/absolute expiry |
| **AuthZ edge cases** | unknown permission string; unknown resource type (strict vs not); null/undefined resource; subject without roles; empty role; permission case-sensitivity; wildcard vs exact; resource with missing owner field; very large role sets perf budget; `authorizeScope` ↔ `rules` consistency property |
| **Timing / enumeration** | statistical test: known vs unknown user latency distribution within tolerance (marked non-flaky via many samples + generous threshold); response bodies byte-identical |
| **Config** | invalid configs fail at boot with clear errors; linter findings; insecure option emits `config.warning` |
| **Adapter conformance** | atomicity of `consume` under contention; uniqueness; transaction rollback; expiry filtering; pagination stability |
| **Framework adapters** | cookie flags exact; 401 vs 403 mapping; no stack traces in responses; CSRF rejection; header injection |

### 18.3 CI gates
Lint + typecheck + dependency-boundary check (authz must not import authn) → unit → conformance matrix → integration → security suite → mutation score threshold on critical packages → `npm audit`/OSV → SBOM+provenance on release. Benchmarks guard: `authorize()` p99 budget with warm cache (e.g. < 0.2 ms in-process).

---

## 19. Implementation roadmap

| Phase | Scope | Exit criteria |
|---|---|---|
| **0 – Spec & ADRs** (now) | This doc reviewed; write `spec/ports`, domain types, error codes, 10 ADRs; decide name/license | Port contracts reviewed; threat model signed off |
| **1 – Core + RBAC + Policy (no I/O)** | `core`, `rbac`, `policy`, `authz`, `testkit` (fakes), `storage-memory`; typed config helpers; linter | Authorization fully usable and tested with memory adapter; property tests; spec vectors v0 |
| **2 – Authentication** | `identity`, `tokens` (JWT+opaque), `sessions`, `authn`, Argon2 hasher, throttle, audit; password/refresh/logout; account states | Rotation & reuse detection pass concurrency tests; full flow via facade |
| **3 – Persistence & reference integration** | `storage-postgres` + migrations, `storage-sqlite`, conformance suite, `cache-redis`; `express` + `fastify` adapters; `examples/` (both projects); email verify/reset flows | CI matrix green; both examples run; security suite green |
| **4 – Hardening & 1.0** | External security review/pen test, fuzzing, docs site, key-rotation runbook, perf benchmarks, API freeze, semver policy | 1.0; spec v1.0 frozen |
| **5 – Ecosystem** | Python port (spec vectors) + FastAPI; Mongo adapter; OIDC strategy; MFA/TOTP | Python passes all vectors |
| **6+** | Passkeys, API keys/service accounts, tenancy helpers (RLS recipes), ABAC engine adapter, admin UI kit | As demanded |

Order rationale: authorization first because it's pure logic (fast to test, no I/O), and it validates the `Subject` seam before authentication complexity arrives; authentication second since its hardest part (rotation) needs conformance tests already in place.

---

## 20. Architectural decisions and tradeoffs (ADR index)

| ADR | Decision | Alternatives rejected | Why chosen is better |
|---|---|---|---|
| 01 | AuthN/AuthZ meet only via `Subject` | One service handling both; passing JWT claims into authz | Swap token strategies or add API keys with zero authz change; authz tests need no tokens |
| 02 | Ports + adapters (hexagonal), zero-dep core | ORM-based core (Prisma/TypeORM); Active Record models | ORMs leak into domain, block Mongo/other DBs, and make unit tests slow |
| 03 | Intent-revealing, small storage ports (`consume`, `evictOldest`) | Generic `Repository<T>` CRUD; single giant interface | Atomicity is a security property (rotation); CRUD forces read-then-write races |
| 04 | Server-side session row always exists, even with JWT | Pure stateless JWT | Revocation, device list, reuse detection, session limits are required features; pure stateless can't deliver them. Cost: one write per login/refresh, not per request |
| 05 | Short JWT access + opaque rotating refresh | Long-lived JWT; refresh as JWT | Opaque refresh stored hashed is simpler to revoke/rotate and carries no info; short access limits revocation lag |
| 06 | No permissions/roles in tokens by default | Embed roles claim | Eliminates stale-privilege and bloat; resolved via cache (bounded staleness) |
| 07 | Permission = `resource:action` strings with typed registry | Bitmasks; arbitrary strings; role-only checks | Readable, greppable, typed, lintable; role-only checks hardcode roles in app code (explicitly avoided) |
| 08 | Roles/permissions declared in code; assignments in DB; dynamic roles opt-in | Everything in DB (admin-editable) | Permissions only mean something where code enforces them; code is reviewable/testable; DB-only config invites runtime misconfig & escalation |
| 09 | RBAC = gate, policy = refinement, AND by default, deny by default | Policy-only (ABAC everywhere); RBAC-only with per-route hacks | Fail-closed, predictable; broad perms cheap to reason about, context rules narrow them. OR mode allowed but flagged |
| 10 | TypeScript reference first; spec + vectors for later ports | Multi-language simultaneous; language-neutral service/sidecar | Quality and learning speed; sidecar adds ops/latency; vectors keep ports behaviorally identical |
| 11 | Postgres reference; memory as semantic oracle; SQLite dev; Mongo later | Mongo-first; SQLite-only | Relational integrity + CAS + RLS suit RBAC; in-memory gives fast deterministic tests |
| 12 | Argon2id (+ pluggable) | bcrypt default; PBKDF2 | Memory-hard, current OWASP recommendation; bcrypt kept as adapter for constrained environments |
| 13 | Soft throttling by default (delay/challenge), not hard lockout | Lock account after N failures | Hard lockout is an easy targeted DoS against a victim account |
| 14 | Policies are pure functions with explicit loaders | Policies free to query DB | Keeps I/O visible, mockable, bounded; avoids N+1 and hidden coupling |
| 15 | `authorizeScope` for lists | Only per-resource `can()` | Per-row checks don't scale and encourage leaky "filter in UI" |
| 16 | Hooks may veto, not bypass | Hooks that can override decisions | Prevents extension code from silently weakening security |
| 17 | Config = typed data validated at boot, `protectAll` option, doctor linter | Convention/env magic | "No hidden magic"; misconfig discovered at start-up, not in prod |
| 18 | Own small implementation of the engine, adapters for others | Depend on Casbin/Passport/Lucia | Controlled guarantees & conformance; still allow wrapping them behind ports |
| 19 | Wildcards, hierarchy, deny, direct grants, dynamic roles each opt-in | All on by default | Each feature is a misconfiguration/escalation surface; users pay complexity only when needed |
| 20 | Nullable `scope`/`tenantId` in schema & types from v1 | Add tenancy later | Retrofitting tenancy into keys, indexes, caches and APIs is the single costliest migration |

### Known tradeoffs / open questions (to settle before Phase 1 ends)
1. **Revocation lag default**: 10 min `eventual` vs `strict` default? (Leaning `eventual` with loud docs; `strict` in SaaS preset.)
2. **Refresh reuse grace** default 0 (strict) vs 10 s (friendlier on flaky mobile). Leaning 0 for core, preset sets 5–10 s for mobile.
3. **Where permission checks for `scope`-ed assignments live** (RBAC resolver vs policy `sameTenant`). Leaning: RBAC resolves *scoped* effective permissions given `subject.tenantId`; policy double-checks resource.tenant.
4. **User metadata storage**: JSON column vs side table — leaning JSON column + optional adapter hook.
5. **Package granularity**: merge `audit`/`ratelimit` into `core`/`authn` if they stay tiny? Revisit after Phase 2.
6. **Library name & license** (Apache-2.0 vs MIT — Apache gives patent grant; leaning Apache-2.0).
7. **Sync vs async policies**: allow both; performance budget for async ones (timeout default 50 ms).

---
*Next step when approved: Phase 0 — write `spec/ports` contracts and the first 10 ADRs, then begin Phase 1.*
