// Express adapter (src/adapters/express): a transport over the Aegis facade. Every request goes
// through a real HTTP server, so headers, status codes and bodies are tested as clients see them.
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';
import express, { type Express } from 'express';
import {
  authenticate,
  authorize,
  createExpressApp,
  errorResponse,
  HTTP_STATUS,
} from '../../src/adapters/express/index.js';
import {
  AuthError,
  ERROR_CODES,
  InMemoryKeyStore,
  isAuthError,
  ManualClock,
  openJwtAccessTokens,
  SequentialIdGenerator,
} from '../../src/index.js';
import {
  createTestSystem,
  postPolicy,
  START,
  TEST_PASSWORD,
  type TestSystem,
} from '../support/fixtures.js';

interface Served {
  readonly url: string;
  close(): Promise<void>;
}

async function serve(app: Express): Promise<Served> {
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });
const json = (body: unknown) => ({
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(body),
});

async function errorOf(r: Response): Promise<{ code: string; message: string; details?: unknown }> {
  return ((await r.json()) as { error: { code: string; message: string; details?: unknown } })
    .error;
}

/** An app with probe routes: one behind authenticate(), some behind authorize(). */
function probeApp(sys: TestSystem, cookieName?: string): Express {
  const app = express();
  app.use(express.json());
  const authn = authenticate(sys.auth, cookieName !== undefined ? { cookieName } : {});
  app.get('/probe', authn, (req, res) => {
    res.json({ id: req.principal?.id, sessionId: req.principal?.sessionId });
  });
  app.get('/posts', authn, authorize(sys.auth, 'post:read'), (_req, res) => {
    res.json({ ok: true });
  });
  app.delete('/projects/:id', authn, authorize(sys.auth, 'project:delete'), (_req, res) => {
    res.json({ ok: true });
  });
  app.put(
    '/posts/:id',
    authn,
    authorize(sys.auth, 'post:update', {
      resource: (req) => ({ id: req.params['id'], authorId: req.get('x-author-id') }),
    }),
    (_req, res) => {
      res.json({ ok: true });
    },
  );
  app.get('/unguarded-authorize', authorize(sys.auth, 'post:read'), (_req, res) => {
    res.json({ ok: true });
  });
  return app;
}

describe('Express adapter — authenticate()', () => {
  let sys: TestSystem;
  let srv: Served;

  before(async () => {
    sys = createTestSystem();
    srv = await serve(probeApp(sys, 'aegis_at'));
    await sys.createUser('alice@example.com', ['viewer']);
  });
  after(() => srv.close());

  it('a valid token → req.principal is the authenticated subject', async () => {
    const { principal, accessToken } = await sys.login('alice@example.com');
    const r = await fetch(`${srv.url}/probe`, { headers: bearer(accessToken) });
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), { id: principal.id, sessionId: principal.sessionId });
  });

  it('no credential → 401 UNAUTHENTICATED with a Bearer challenge', async () => {
    const r = await fetch(`${srv.url}/probe`);
    assert.equal(r.status, 401);
    assert.equal(r.headers.get('www-authenticate'), 'Bearer');
    assert.equal(r.headers.get('cache-control'), 'no-store');
    assert.equal((await errorOf(r)).code, 'UNAUTHENTICATED');
  });

  it('an invalid token → 401 TOKEN_INVALID (garbage, tampered, wrong scheme, malformed header)', async () => {
    const { accessToken } = await sys.login('alice@example.com');
    const [h, p, s] = accessToken.split('.') as [string, string, string];
    const tampered = `${h}.${p}.${s.slice(0, -2)}${s.endsWith('AA') ? 'BB' : 'AA'}`;
    for (const authorization of [
      'Bearer not-a-jwt',
      `Bearer ${tampered}`,
      `Basic ${Buffer.from('alice:pw').toString('base64')}`,
      'Bearer',
      `Bearer ${accessToken} extra`,
    ]) {
      const r = await fetch(`${srv.url}/probe`, { headers: { authorization } });
      assert.equal(r.status, 401, authorization);
      assert.equal(r.headers.get('www-authenticate'), 'Bearer error="invalid_token"');
      const e = await errorOf(r);
      assert.equal(e.code, 'TOKEN_INVALID', authorization);
      assert.equal(e.message, 'The credential is invalid.');
    }
  });

  it('an expired token → 401 TOKEN_EXPIRED', async () => {
    const { accessToken } = await sys.login('alice@example.com');
    sys.clock.advance((sys.accessTokens.ttlMs ?? 0) + 1_000);
    const r = await fetch(`${srv.url}/probe`, { headers: bearer(accessToken) });
    assert.equal(r.status, 401);
    assert.equal((await errorOf(r)).code, 'TOKEN_EXPIRED');
  });

  it('a revoked session is rejected although its JWT is still cryptographically valid', async () => {
    const { principal, accessToken } = await sys.login('alice@example.com');
    const ok = await fetch(`${srv.url}/probe`, { headers: bearer(accessToken) });
    assert.equal(ok.status, 200, 'accepted before revocation');

    await sys.auth.authn.logout({ principal });
    assert.equal(sys.accessTokens.verify(accessToken, sys.clock.now()).ok, true, 'JWT still valid');

    const r = await fetch(`${srv.url}/probe`, { headers: bearer(accessToken) });
    assert.equal(r.status, 401, 'nothing was cached: the next request sees the revocation');
    assert.equal((await errorOf(r)).code, 'TOKEN_INVALID');
  });

  it('a securityVersion bump (credential invalidation) is rejected at once', async () => {
    const id = await sys.createUser('bob@example.com', ['viewer']);
    const { accessToken } = await sys.login('bob@example.com');
    await sys.storage.users.bumpSecurityVersion(id, sys.clock.now());
    const r = await fetch(`${srv.url}/probe`, { headers: bearer(accessToken) });
    assert.equal(r.status, 401);
  });

  it('cookie: used only when configured and only without an Authorization header', async () => {
    const { principal, accessToken } = await sys.login('alice@example.com');
    const viaCookie = await fetch(`${srv.url}/probe`, {
      headers: { cookie: `other=1; aegis_at=${accessToken}` },
    });
    assert.equal(viaCookie.status, 200);
    assert.equal(((await viaCookie.json()) as { id: string }).id, principal.id);

    const headerWins = await fetch(`${srv.url}/probe`, {
      headers: { cookie: `aegis_at=${accessToken}`, authorization: 'Bearer junk' },
    });
    assert.equal(headerWins.status, 401, 'a bad header is never rescued by the cookie');

    const sys2 = createTestSystem();
    await sys2.createUser('carol@example.com');
    const srv2 = await serve(probeApp(sys2));
    try {
      const { accessToken: t } = await sys2.login('carol@example.com');
      const r = await fetch(`${srv2.url}/probe`, { headers: { cookie: `aegis_at=${t}` } });
      assert.equal(r.status, 401, 'cookies are ignored unless configured');
    } finally {
      await srv2.close();
    }
  });

  it('rejects an invalid cookie name at construction', () => {
    assert.throws(
      () => authenticate(sys.auth, { cookieName: 'bad name;' }),
      (e: unknown) => isAuthError(e) && e.code === 'CONFIG_INVALID',
    );
  });
});

describe('Express adapter — authorize()', () => {
  let sys: TestSystem;
  let srv: Served;
  let viewer: { id: string; token: string };
  let admin: { id: string; token: string };
  let editor: { id: string; token: string };

  before(async () => {
    sys = createTestSystem({ policies: [postPolicy()] });
    srv = await serve(probeApp(sys));
    const v = await sys.createUser('viewer@example.com', ['viewer']);
    const a = await sys.createUser('admin@example.com', ['admin']);
    const e = await sys.createUser('editor@example.com', ['editor']);
    viewer = { id: v, token: (await sys.login('viewer@example.com')).accessToken };
    admin = { id: a, token: (await sys.login('admin@example.com')).accessToken };
    editor = { id: e, token: (await sys.login('editor@example.com')).accessToken };
  });
  after(() => srv.close());

  it('allows a granted permission', async () => {
    const r = await fetch(`${srv.url}/posts`, { headers: bearer(viewer.token) });
    assert.equal(r.status, 200);
  });

  it('denies a missing permission with 403 FORBIDDEN', async () => {
    const r = await fetch(`${srv.url}/projects/p1`, {
      method: 'DELETE',
      headers: bearer(viewer.token),
    });
    assert.equal(r.status, 403);
    const e = await errorOf(r);
    assert.equal(e.code, 'FORBIDDEN');
    assert.equal(e.message, 'You do not have permission to perform this action.');
    const ok = await fetch(`${srv.url}/projects/p1`, {
      method: 'DELETE',
      headers: bearer(admin.token),
    });
    assert.equal(ok.status, 200);
  });

  it('passes the resource to policies (ownership)', async () => {
    const own = await fetch(`${srv.url}/posts/p1`, {
      method: 'PUT',
      headers: { ...bearer(editor.token), 'x-author-id': editor.id },
    });
    assert.equal(own.status, 200);
    const other = await fetch(`${srv.url}/posts/p1`, {
      method: 'PUT',
      headers: { ...bearer(editor.token), 'x-author-id': admin.id },
    });
    assert.equal(other.status, 403);
  });

  it('without authenticate() there is no principal: 401, never an allow', async () => {
    const r = await fetch(`${srv.url}/unguarded-authorize`, { headers: bearer(viewer.token) });
    assert.equal(r.status, 401);
    assert.equal((await errorOf(r)).code, 'UNAUTHENTICATED');
  });

  it('rejects a permission that is not "resource:action" at construction', () => {
    for (const p of ['post', ':read', 'post:', '']) {
      assert.throws(
        () => authorize(sys.auth, p),
        (e: unknown) => isAuthError(e) && e.code === 'CONFIG_INVALID',
        p,
      );
    }
  });
});

describe('Express adapter — demo routes', () => {
  let sys: TestSystem;
  let srv: Served;

  before(async () => {
    sys = createTestSystem();
    srv = await serve(createExpressApp({ auth: sys.auth }));
    await sys.createUser('dave@example.com', ['viewer']);
  });
  after(() => srv.close());

  it('login → me → refresh → logout, then the old credentials are dead', async () => {
    const login = await fetch(
      `${srv.url}/login`,
      json({ identifier: 'dave@example.com', password: TEST_PASSWORD }),
    );
    assert.equal(login.status, 200);
    assert.equal(login.headers.get('cache-control'), 'no-store');
    const t1 = (await login.json()) as {
      accessToken: string;
      refreshToken: string;
      tokenType: string;
    };
    assert.equal(t1.tokenType, 'Bearer');

    const me = await fetch(`${srv.url}/me`, { headers: bearer(t1.accessToken) });
    assert.equal(me.status, 200);
    const body = (await me.json()) as Record<string, unknown>;
    assert.equal(body['type'], 'user');
    assert.ok(!('attributes' in body) && !('claims' in body));

    const refreshed = await fetch(`${srv.url}/refresh`, json({ refreshToken: t1.refreshToken }));
    assert.equal(refreshed.status, 200);
    const t2 = (await refreshed.json()) as { accessToken: string; refreshToken: string };
    assert.notEqual(t2.refreshToken, t1.refreshToken);

    const out = await fetch(`${srv.url}/logout`, {
      method: 'POST',
      headers: bearer(t2.accessToken),
    });
    assert.equal(out.status, 204);
    const after = await fetch(`${srv.url}/me`, { headers: bearer(t2.accessToken) });
    assert.equal(after.status, 401);
    const reuse = await fetch(`${srv.url}/refresh`, json({ refreshToken: t2.refreshToken }));
    assert.equal(reuse.status, 401);
  });

  it('logout by refresh token works without an access token', async () => {
    const { accessToken, refreshToken } = await sys.login('dave@example.com');
    const out = await fetch(`${srv.url}/logout`, json({ refreshToken }));
    assert.equal(out.status, 204);
    assert.equal((await fetch(`${srv.url}/me`, { headers: bearer(accessToken) })).status, 401);
  });

  it('wrong password → 401 INVALID_CREDENTIALS; missing field or bad JSON → 400', async () => {
    const wrong = await fetch(
      `${srv.url}/login`,
      json({ identifier: 'dave@example.com', password: 'nope-nope-nope' }),
    );
    assert.equal(wrong.status, 401);
    assert.equal((await errorOf(wrong)).code, 'INVALID_CREDENTIALS');

    const missing = await fetch(`${srv.url}/login`, json({ identifier: 'dave@example.com' }));
    assert.equal(missing.status, 400);
    assert.deepEqual((await errorOf(missing)).details, {
      field: 'password',
      rule: 'required_string',
    });

    const bad = await fetch(`${srv.url}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"identifier": ',
    });
    assert.equal(bad.status, 400);
    assert.equal((await errorOf(bad)).code, 'VALIDATION_FAILED');
  });

  it('unknown route → 404 NOT_FOUND as JSON, and no x-powered-by', async () => {
    const r = await fetch(`${srv.url}/nope`);
    assert.equal(r.status, 404);
    assert.equal((await errorOf(r)).code, 'NOT_FOUND');
    assert.equal(r.headers.get('x-powered-by'), null);
  });
});

describe('Express adapter — JWKS route', () => {
  it('serves the JWKS with the configured Cache-Control and no private members', async () => {
    const sys = createTestSystem();
    const opened = await openJwtAccessTokens(
      {
        tokens: { algorithm: 'RS256', issuer: 'i', audience: 'a', ttl: 600_000 },
        keys: {
          rotationEnabled: true,
          storage: 'memory',
          generateIfMissing: true,
          refreshIntervalMs: 0,
          jwks: { cacheTtlSec: 120 },
        },
      },
      {
        keyStore: new InMemoryKeyStore(),
        clock: new ManualClock(START),
        ids: new SequentialIdGenerator('x'),
        env: {
          AEGIS_MASTER_KEY: '8f1c2a7d4e9b0365aa17c3d2f8e46b9c0d1e2f3a4b5c6d7e8f90a1b2c3d4e5f6',
        },
        logger: { warn: () => undefined },
      },
    );
    const srv = await serve(createExpressApp({ auth: sys.auth, jwks: opened.jwks }));
    try {
      const r = await fetch(`${srv.url}/.well-known/jwks.json`);
      assert.equal(r.status, 200);
      assert.equal(r.headers.get('cache-control'), 'public, max-age=120');
      assert.equal(r.headers.get('content-type'), 'application/jwk-set+json; charset=utf-8');
      const doc = (await r.json()) as { keys: Record<string, unknown>[] };
      assert.equal(doc.keys.length, 1);
      assert.equal(doc.keys[0]?.['kid'], opened.keys.getActiveKey().kid);
      for (const m of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'])
        assert.ok(!(m in (doc.keys[0] ?? {})));
    } finally {
      opened.keys.close();
      await srv.close();
    }
  });

  it('no JWKS handler (HS256) → no route', async () => {
    const sys = createTestSystem();
    const srv = await serve(createExpressApp({ auth: sys.auth, jwks: null }));
    try {
      assert.equal((await fetch(`${srv.url}/.well-known/jwks.json`)).status, 404);
    } finally {
      await srv.close();
    }
  });
});

describe('Express adapter — error mapping', () => {
  it('maps every error code, including the table of the adapter brief', () => {
    const expected: Record<string, number> = {
      UNAUTHENTICATED: 401,
      TOKEN_EXPIRED: 401,
      TOKEN_INVALID: 401,
      FORBIDDEN: 403,
      NOT_FOUND: 404,
      CONFLICT: 409,
      VALIDATION_FAILED: 400,
      PRECONDITION_FAILED: 400,
      CONFIG_INVALID: 500,
      STORAGE_UNAVAILABLE: 503,
    };
    for (const [code, status] of Object.entries(expected)) {
      assert.equal(HTTP_STATUS[code as keyof typeof HTTP_STATUS], status, code);
    }
    for (const code of ERROR_CODES) {
      const s = errorResponse(new AuthError(code)).status;
      assert.ok(s >= 400 && s < 600, code);
    }
  });

  it('never exposes internal causes, stacks or configuration details', () => {
    const secret = 'postgres://admin:hunter2@db/aegis';
    const internal = errorResponse(new Error(`connect failed ${secret}`));
    assert.equal(internal.status, 500);
    assert.deepEqual(internal.body, {
      error: { code: 'INTERNAL', message: 'An unexpected error occurred.', retryable: false },
    });

    const storage = errorResponse(
      new AuthError('STORAGE_UNAVAILABLE', { cause: new Error(secret), retryAfterMs: 1500 }),
    );
    assert.equal(storage.status, 503);
    assert.equal(storage.headers['retry-after'], '2');
    assert.ok(!JSON.stringify(storage.body).includes('hunter2'));
    assert.ok(!('details' in storage.body.error), 'no details on a 5xx');

    const config = errorResponse(
      new AuthError('CONFIG_INVALID', {
        details: { violations: [{ path: 'keys.secret', rule: 'x', message: secret }] },
      }),
    );
    assert.equal(config.status, 500);
    assert.ok(!JSON.stringify(config.body).includes('keys.secret'));

    const limited = errorResponse(new AuthError('RATE_LIMITED', { retryAfterMs: 30_000 }));
    assert.equal(limited.status, 429);
    assert.equal(limited.headers['retry-after'], '30');
  });
});
