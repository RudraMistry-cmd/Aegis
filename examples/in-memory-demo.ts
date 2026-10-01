// Runnable demo: wires the in-memory adapter and walks login -> authorize -> refresh -> revoke.
// Implements nothing itself; it exercises the Phase 1 public API (src/index.ts).
//
// Run with: npm run start-demo
import {
  createAuth,
  createMemoryStorage,
  CryptoRandom,
  defineCatalog,
  definePolicy,
  isAuthError,
  ManualClock,
  MemoryAuditSink,
  MemoryRateLimiter,
  ScryptHasher,
  SequentialIdGenerator,
  StubAccessTokenProvider,
  SYSTEM_ACTOR,
} from '../src/index.js';

const line = (label: string, value: unknown): void => {
  console.log(`  ${label.padEnd(26)} ${typeof value === 'string' ? value : JSON.stringify(value)}`);
};
const heading = (text: string): void => console.log(`\n${text}\n${'-'.repeat(text.length)}`);

async function main(): Promise<void> {
  // ---------------------------------------------------------------- configuration
  const catalog = defineCatalog({
    permissions: [
      'post:read',
      'post:update',
      'post:delete',
      'role:assign',
      'role:revoke',
      'role:read',
    ],
    features: { hierarchy: true, deny: true },
    roles: {
      reader: { permissions: ['post:read'] },
      author: { inherits: ['reader'], permissions: ['post:update'] },
      moderator: { inherits: ['author'], permissions: ['post:delete', 'role:read'] },
    },
  });

  // RBAC grants post:update broadly; the policy narrows it to the author of the post.
  const postPolicy = definePolicy({
    name: 'post-ownership',
    resource: 'post',
    mode: 'rbacAndPolicy',
    rules: { update: ({ subject, resource }) => resource['authorId'] === subject.id },
    scope: { update: ({ subject }) => ({ op: 'eq', field: 'authorId', value: subject.id }) },
  });

  const clock = new ManualClock(Date.UTC(2030, 0, 1));
  const ids = new SequentialIdGenerator('demo');
  const audit = new MemoryAuditSink();
  const storage = createMemoryStorage(new SequentialIdGenerator('row'));
  const auth = createAuth({
    storage,
    hasher: new ScryptHasher({ N: 1 << 12 }),
    accessTokens: new StubAccessTokenProvider({
      secret: 'demo-secret-of-at-least-thirty-two-bytes',
      issuer: 'aegis-demo',
      audience: 'aegis-demo-api',
      ids,
    }),
    clock,
    random: new CryptoRandom(),
    ids,
    rateLimiter: new MemoryRateLimiter(),
    audit,
    catalog,
    policies: [postPolicy],
    identifiers: ['email'],
    sessions: { max: 2, onLimit: 'evict-oldest' },
    tokens: { accessTtlMs: 10 * 60_000, refreshIdleTtlMs: 7 * 24 * 60 * 60_000 },
  });

  heading('1. Configuration');
  line('catalog version', catalog.version);
  line(
    'doctor findings',
    auth.doctor().map((f) => `${f.severity}:${f.finding}`),
  );

  // ---------------------------------------------------------------- registration
  heading('2. Registration');
  await auth.authn.register({ identifier: 'ada@example.com', password: 'a-long-enough-password' });
  // The uniform response carries no user id (spec/flows/login.md §6.1.7), so the demo reads it
  // back through the storage adapter it owns.
  const identifier = await storage.identifiers.findByNormalized('email', 'ada@example.com');
  if (!identifier) throw new Error('demo: registration did not create an identifier');
  const userId = identifier.userId;
  line('registered', 'ada@example.com');
  line('user id', userId);

  // A default role, assigned by the reserved system actor.
  await auth.authz.roles.assign({ id: SYSTEM_ACTOR, type: 'user' }, userId, { roleName: 'author' });
  line('roles', await auth.authz.rolesFor({ id: userId }));
  line('permissions', await auth.authz.permissionsFor({ id: userId }));

  // ---------------------------------------------------------------- login
  heading('3. Login');
  const session = await auth.authn.login({
    identifier: 'ADA@example.com', // normalization makes this the same identifier
    password: 'a-long-enough-password',
    device: { label: 'demo-cli' },
  });
  line('principal', {
    id: session.principal.id,
    authMethod: session.principal.authMethod,
    amr: session.principal.amr,
  });
  line('access token (truncated)', `${session.credentials.accessToken.slice(0, 32)}...`);
  line('session id', session.principal.sessionId);

  // ---------------------------------------------------------------- authorization
  heading('4. Authorization');
  const ownPost = { type: 'post', id: 'p1', authorId: userId };
  const otherPost = { type: 'post', id: 'p2', authorId: 'someone-else' };
  line('update own post', await auth.authz.authorize(session.principal, 'update', ownPost));
  line('update other post', await auth.authz.authorize(session.principal, 'update', otherPost));
  line('delete own post', await auth.authz.authorize(session.principal, 'delete', ownPost));
  line('scope for listing', await auth.authz.authorizeScope(session.principal, 'update', 'post'));

  // ---------------------------------------------------------------- refresh
  heading('5. Refresh (rotation)');
  clock.advance(5 * 60_000);
  const rotated = await auth.authn.refresh({ refreshToken: session.credentials.refreshToken });
  line('new refresh token', `${rotated.credentials.refreshToken.slice(0, 16)}... (rotated)`);
  line('session unchanged', rotated.principal.sessionId === session.principal.sessionId);
  line(
    'old token replayed',
    await expectFailure(() =>
      auth.authn.refresh({ refreshToken: session.credentials.refreshToken }),
    ),
  );
  line(
    'reuse alert',
    audit.ofType('refresh.reuse_detected').map((e) => e.severity),
  );

  // ---------------------------------------------------------------- revocation
  heading('6. Revocation');
  // The replay above already revoked the family; log in again to show an explicit logout.
  const second = await auth.authn.login({
    identifier: 'ada@example.com',
    password: 'a-long-enough-password',
  });
  line(
    'resolved before logout',
    (await auth.authn.resolve(second.credentials.accessToken)) !== null,
  );
  await auth.authn.logout({ principal: second.principal });
  line(
    'resolved after logout',
    (await auth.authn.resolve(second.credentials.accessToken)) !== null,
  );
  line(
    'refresh after logout',
    await expectFailure(() =>
      auth.authn.refresh({ refreshToken: second.credentials.refreshToken }),
    ),
  );

  heading('7. Audit trail');
  for (const event of audit.events()) {
    line(event.type, {
      outcome: event.outcome,
      severity: event.severity,
      reason: event.reason ?? null,
    });
  }
}

/** Returns the error code of a call that is expected to fail. */
async function expectFailure(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
    return 'UNEXPECTED SUCCESS';
  } catch (e) {
    return isAuthError(e) ? e.code : `UNEXPECTED ${String(e)}`;
  }
}

await main();
