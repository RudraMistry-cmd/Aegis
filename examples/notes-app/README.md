# Aegis Notes — integration example

A small Express app with a one-page UI. Aegis handles sign-in, sessions, tokens and permissions;
the app only stores notes.

```bash
npm install
npm run start-notes-app
```

Open http://localhost:3000. All users share the password `demo-password-123`:

| User | Role | Can |
|---|---|---|
| alice@example.com | member | read, write, delete **her own** notes |
| carol@example.com | member | same; deleting Alice's note → 403 |
| bob@example.com | viewer | read only; adding a note → 403 |

Things to try: sign in as Alice and add a note; sign in as Carol and try to delete it; sign in as
Bob and try to write; press **Refresh token**; sign out, and the old access token stops working at
once (the session is revoked, not just the browser's copy).

## How the integration works

Everything is in [`server.ts`](server.ts), in five steps.

### 1. Describe permissions, roles and policies

```ts
const catalog = defineCatalog({
  permissions: ['note:read', 'note:create', 'note:delete'],   // always "resource:action"
  features: { hierarchy: true },
  roles: {
    viewer: { permissions: ['note:read'] },
    member: { inherits: ['viewer'], permissions: ['note:create', 'note:delete'] },
  },
});

const noteOwnership = definePolicy({
  name: 'note-ownership',
  resource: 'note',
  mode: 'rbacAndPolicy',                    // the role must allow it AND the rule must allow it
  rules: { delete: ({ subject, resource }) => resource['ownerId'] === subject.id },
});
```

Roles answer "may this kind of user ever do this?"; policies answer "…to *this* resource?".

### 2. Create the Aegis instance

```ts
const tokens = await openJwtAccessTokens(
  { tokens: { algorithm: 'RS256', issuer: 'notes-app', audience: 'notes-api', ttl: 5 * 60_000 },
    keys: { rotationEnabled: true, storage: 'memory', generateIfMissing: true, jwks: {} } },
  { keyStore: new InMemoryKeyStore(), clock, ids },
);

const auth = createAuth({
  // The default hash cost (N = 2^17) suits production; this demo uses a lighter one to stay snappy.
  storage, hasher: new ScryptHasher({ N: 1 << 14 }), accessTokens: tokens.accessTokens,
  clock, random: new CryptoRandom(), ids, rateLimiter: new MemoryRateLimiter(),
  catalog, policies: [noteOwnership], identifiers: ['email'],
});
```

`createAuth` validates the whole configuration and throws `CONFIG_INVALID`, listing every problem,
if anything is wrong. Do this once at startup.

### 3. Create users and give them roles

```ts
await auth.authn.register({ identifier: email, password });
const row = await storage.identifiers.findByNormalized('email', email);   // see note below
await auth.authz.roles.assign({ id: SYSTEM_ACTOR, type: 'user' }, row.userId, { roleName: 'member' });
```

`register` deliberately returns no user id, so a sign-up form can't be used to discover which
emails have accounts. Your app looks the id up through the storage it created.

### 4. Mount the auth endpoints

```ts
app.use(express.json({ limit: '16kb' }));
app.use('/auth', createAuthRoutes(auth));          // /auth/login, /auth/refresh, /auth/logout, /auth/me
if (tokens.jwks) app.get(tokens.jwks.path, jwksRoute(tokens.jwks));   // /.well-known/jwks.json
```

| Endpoint | Body | Returns |
|---|---|---|
| `POST /auth/login` | `{ identifier, password }` | `{ tokenType, accessToken, accessTokenExpiresAt, refreshToken, refreshTokenExpiresAt }` |
| `POST /auth/refresh` | `{ refreshToken }` | new tokens; the old refresh token is spent (reusing it fails and revokes the session) |
| `POST /auth/logout` | `{ refreshToken }`, or just the Bearer header | 204; the session is revoked server-side |
| `GET /auth/me` | Bearer header | `{ id, type, authMethod, authenticatedAt, … }` |

### 5. Protect your own routes

```ts
const signedIn = authenticate(auth);

app.get('/api/notes', signedIn, authorize(auth, 'note:read'), handler);

app.delete('/api/notes/:id', signedIn,
  authorize(auth, 'note:delete', {
    // Give the policy the real resource so it can check ownership.
    resource: (req) => {
      const note = notes.get(req.params.id);
      if (!note) throw authError('NOT_FOUND');
      return { id: note.id, ownerId: note.ownerId };
    },
  }),
  handler);
```

- `authenticate` sets `req.principal` (`id`, `sessionId`, …). It checks the token **and** the
  session on every request, so sign-out, a password change or an admin revocation take effect on the
  very next request.
- `authorize` runs after `authenticate`. Denied → 403, not signed in → 401.
- Take identity from `req.principal.id`, never from the request body (`ownerId` in `POST /api/notes`).
- Finish with a 404 handler and an error handler that call `sendError`, so every error is the
  same safe JSON: `{ "error": { "code", "message", "retryable", "details"? } }`.

### Calling the API from a client

```js
const t = await (await fetch('/auth/login', { method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ identifier, password }) })).json();

await fetch('/api/notes', { headers: { authorization: `Bearer ${t.accessToken}` } });
```

When a call returns `401` with `error.code === 'TOKEN_EXPIRED'`, call `/auth/refresh` with the
refresh token and retry once (see `call()` in [`public/index.html`](public/index.html)). Any other
401 means "sign in again".

## From demo to production

| In this demo | In production |
|---|---|
| `createMemoryStorage()` (lost on restart) | `createPostgresStorage({ connectionString })` from `aegis-core/postgres`, then `await storage.migrate()`; use `storage.keys` as the key store with `storage: 'postgres'` |
| Random per-process identifier-digest key | Set `AEGIS_IDENTIFIER_DIGEST_KEY` (32 random bytes); required when `NODE_ENV=production` |
| `InMemoryKeyStore`, new key each start, warning about `AEGIS_MASTER_KEY` | Set `AEGIS_MASTER_KEY` (32 random bytes, from a secret manager) on every instance; `generateIfMissing` only for the very first deploy |
| Users seeded in code | A sign-up route calling `auth.authn.register`, then assigning a default role |
| Tokens kept in page memory | Same for the access token; consider an HttpOnly, `SameSite=Strict` cookie for the refresh token (`authenticate(auth, { cookieName })` reads cookies, and cookie auth needs CSRF protection) |
| `MemoryRateLimiter` | A shared limiter when you run several instances |
| HTTP on localhost | HTTPS only; `app.set('trust proxy', …)` behind a load balancer so `req.ip` is the client's |

See [`docs/JWKS.md`](../../docs/JWKS.md) for key rotation and [`docs/POSTGRES.md`](../../docs/POSTGRES.md)
for the database.
