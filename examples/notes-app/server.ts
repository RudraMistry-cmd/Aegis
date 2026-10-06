// Notes — a small working app with Aegis integrated into an ordinary Express server.
//
//   npm run start-notes-app      then open http://localhost:3000
//
// Seeded users (password for all: demo-password-123):
//   alice@example.com  member  — can read, write and delete her OWN notes
//   carol@example.com  member  — same; cannot delete Alice's notes (ownership policy)
//   bob@example.com    viewer  — can only read notes (RBAC: no note:create / note:delete)
//
// Everything is in memory, so a restart starts clean. See README.md next to this file for how each
// piece maps to a real deployment (PostgreSQL storage, durable keys, a master key).
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import express from 'express';
import {
  authenticate,
  authorize,
  createAuthRoutes,
  jwksRoute,
  sendError,
} from '../../src/adapters/express/index.js';
import {
  authError,
  createAuth,
  createMemoryStorage,
  CryptoIdGenerator,
  CryptoRandom,
  defineCatalog,
  definePolicy,
  InMemoryKeyStore,
  MemoryRateLimiter,
  openJwtAccessTokens,
  ScryptHasher,
  SYSTEM_ACTOR,
  SystemClock,
} from '../../src/index.js';

const PORT = Number(process.env['PORT'] ?? 3000);
const DEMO_PASSWORD = 'demo-password-123';

// ---------------------------------------------------------------- 1. What exists, who may do what
// Permissions are "resource:action". Roles bundle permissions; RBAC answers "may this kind of user
// ever do this?".
const catalog = defineCatalog({
  permissions: ['note:read', 'note:create', 'note:delete'],
  features: { hierarchy: true },
  roles: {
    viewer: { permissions: ['note:read'] },
    member: { inherits: ['viewer'], permissions: ['note:create', 'note:delete'] },
  },
});

// A policy narrows a permission using the actual resource: "…but only your own note".
const noteOwnership = definePolicy({
  name: 'note-ownership',
  resource: 'note',
  mode: 'rbacAndPolicy', // RBAC must allow AND this rule must allow
  rules: { delete: ({ subject, resource }) => resource['ownerId'] === subject.id },
});

// ---------------------------------------------------------------- 2. Wire Aegis
const clock = new SystemClock();
const ids = new CryptoIdGenerator();
const storage = createMemoryStorage(); // production: createPostgresStorage(...) from 'aegis-core/postgres'

// RS256 access tokens with a key store, so the public key can be published as a JWKS.
// Memory store + generateIfMissing: a fresh key on every start (fine for a demo). Without
// AEGIS_MASTER_KEY Aegis prints a warning that keys are unencrypted — expected here.
const tokens = await openJwtAccessTokens(
  {
    tokens: { algorithm: 'RS256', issuer: 'notes-app', audience: 'notes-api', ttl: 5 * 60_000 },
    keys: { rotationEnabled: true, storage: 'memory', generateIfMissing: true, jwks: {} },
  },
  { keyStore: new InMemoryKeyStore(), clock, ids },
);

const auth = createAuth({
  storage,
  hasher: new ScryptHasher(),
  accessTokens: tokens.accessTokens,
  clock,
  random: new CryptoRandom(),
  ids,
  rateLimiter: new MemoryRateLimiter(), // throttles password guessing
  catalog,
  policies: [noteOwnership],
  identifiers: ['email'],
});

// ---------------------------------------------------------------- 3. Seed users (demo only)
const emailById = new Map<string, string>();
for (const [email, role] of [
  ['alice@example.com', 'member'],
  ['carol@example.com', 'member'],
  ['bob@example.com', 'viewer'],
] as const) {
  await auth.authn.register({ identifier: email, password: DEMO_PASSWORD });
  // Registration deliberately returns no user id (it must not reveal whether an email exists), so
  // the app looks the new user up through the storage it owns.
  const row = await storage.identifiers.findByNormalized('email', email);
  if (!row) throw new Error(`seed: ${email} was not created`);
  await auth.authz.roles.assign({ id: SYSTEM_ACTOR, type: 'user' }, row.userId, { roleName: role });
  emailById.set(row.userId, email);
}

// ---------------------------------------------------------------- 4. The application's own data
interface Note {
  readonly id: string;
  readonly ownerId: string;
  readonly text: string;
  readonly createdAt: number;
}
const notes = new Map<string, Note>();

const view = (n: Note) => ({ ...n, owner: emailById.get(n.ownerId) ?? n.ownerId });

// ---------------------------------------------------------------- 5. The Express app
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '16kb' }));
app.use(
  express.static(fileURLToPath(new URL('../../../examples/notes-app/public', import.meta.url))),
);

// Aegis's ready-made endpoints: POST /auth/login, /auth/refresh, /auth/logout, GET /auth/me.
app.use('/auth', createAuthRoutes(auth));
// Public keys for other services that want to verify these tokens.
if (tokens.jwks) app.get(tokens.jwks.path, jwksRoute(tokens.jwks));

// Your API. `authenticate` checks the token AND the session on every request (a logged-out
// token stops working at once); `authorize` asks RBAC + policies.
const signedIn = authenticate(auth);

app.get('/api/notes', signedIn, authorize(auth, 'note:read'), (_req, res) => {
  res.json([...notes.values()].sort((a, b) => b.createdAt - a.createdAt).map(view));
});

app.post('/api/notes', signedIn, authorize(auth, 'note:create'), (req, res) => {
  const text: unknown = (req.body as { text?: unknown } | undefined)?.text;
  if (typeof text !== 'string' || text.trim().length === 0 || text.length > 500) {
    sendError(res, authError('VALIDATION_FAILED', { details: { field: 'text' } }));
    return;
  }
  const note: Note = {
    id: randomUUID(),
    ownerId: req.principal!.id, // always from the verified principal, never from the body
    text: text.trim(),
    createdAt: clock.now(),
  };
  notes.set(note.id, note);
  res.status(201).json(view(note));
});

app.delete(
  '/api/notes/:id',
  signedIn,
  // The resource builder hands the policy the real note, so it can compare ownerId.
  authorize(auth, 'note:delete', {
    resource: (req) => {
      const note = notes.get(String(req.params['id']));
      if (!note) throw authError('NOT_FOUND');
      return { id: note.id, ownerId: note.ownerId };
    },
  }),
  (req, res) => {
    notes.delete(String(req.params['id']));
    res.status(204).end();
  },
);

// Last: unknown routes and any error, as Aegis-style JSON without internals.
app.use((_req: express.Request, res: express.Response) => sendError(res, authError('NOT_FOUND')));
app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) =>
  sendError(res, err),
);

app.listen(PORT, () => {
  console.log(`Notes app on http://localhost:${PORT}`);
  console.log(`Users: alice@example.com, carol@example.com (members), bob@example.com (viewer)`);
  console.log(`Password: ${DEMO_PASSWORD}`);
});
