// Observability (src/observability/metrics.ts): exposition format, the Auth wrapper passes results
// and errors through unchanged, and labels stay bounded.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  Counter,
  createAegisMetrics,
  instrumentAuth,
  isAuthError,
  METRICS_CONTENT_TYPE,
  metricsHandler,
  watchKeyRotations,
} from '../../src/index.js';
import { createTestSystem } from '../support/fixtures.js';

describe('metrics', () => {
  it('renders the three counters in Prometheus text format', () => {
    const m = createAegisMetrics();
    m.authRequests.inc('success');
    m.authRequests.inc('success');
    m.authRequests.inc('TOKEN_INVALID');
    m.refreshSuccess.inc();
    const text = m.render();
    assert.match(text, /^# TYPE auth_requests_total counter$/m);
    assert.match(text, /^auth_requests_total\{result="success"\} 2$/m);
    assert.match(text, /^auth_requests_total\{result="TOKEN_INVALID"\} 1$/m);
    assert.match(text, /^refresh_success_total 1$/m);
    assert.match(text, /^key_rotations_total 0$/m);
    assert.ok(text.endsWith('\n'));
  });

  it('escapes label values and rejects bad names and negative increments', () => {
    const c = new Counter('x_total', 'help', 'l');
    c.inc('a"b\\c\nd');
    assert.match(c.render(), /x_total\{l="a\\"b\\\\c\\nd"\} 1/);
    assert.throws(() => new Counter('bad name', 'h'));
    assert.throws(() => c.inc('a', -1));
  });

  it('instrumentAuth counts but changes nothing: same principal, same error', async () => {
    const sys = createTestSystem();
    await sys.createUser('m@example.com');
    const m = createAegisMetrics();
    const auth = instrumentAuth(sys.auth, m);
    const { accessToken, refreshToken, principal } = await sys.login('m@example.com');

    assert.deepEqual(await auth.authn.authenticate(accessToken), principal);
    await assert.rejects(
      auth.authn.authenticate('junk'),
      (e) => isAuthError(e) && e.code === 'TOKEN_INVALID',
    );
    await assert.rejects(
      auth.authn.authenticate(null),
      (e) => isAuthError(e) && e.code === 'UNAUTHENTICATED',
    );
    await auth.authn.refresh({ refreshToken });
    await assert.rejects(auth.authn.refresh({ refreshToken }));

    assert.equal(m.authRequests.get('success'), 1);
    assert.equal(m.authRequests.get('TOKEN_INVALID'), 1);
    assert.equal(m.authRequests.get('UNAUTHENTICATED'), 1);
    assert.equal(m.refreshSuccess.get(), 1, 'only successful refreshes count');
    // Strict revocation still applies through the wrapper.
    await sys.auth.authn.logout({ principal });
    await assert.rejects(auth.authn.authenticate(accessToken));
  });

  it('watchKeyRotations counts changes of the active kid only', async () => {
    const m = createAegisMetrics();
    let kid = 'k1';
    const stop = watchKeyRotations(() => kid, m, 5);
    await new Promise((r) => setTimeout(r, 20));
    kid = 'k2';
    await new Promise((r) => setTimeout(r, 20));
    stop();
    assert.equal(m.keyRotations.get(), 1);
  });

  it('the handler serves GET with the Prometheus content type and refuses other methods', () => {
    const m = createAegisMetrics();
    const h = metricsHandler(m);
    const fake = (method: string) => {
      const out: { status?: number; headers?: Record<string, string>; body?: string } = {};
      const res = {
        writeHead(s: number, hd?: Record<string, string>) {
          out.status = s;
          out.headers = hd ?? {};
          return res;
        },
        end(b?: string) {
          out.body = b;
        },
      };
      h({ method } as never, res as never);
      return out;
    };
    const ok = fake('GET');
    assert.equal(ok.status, 200);
    assert.equal(ok.headers?.['content-type'], METRICS_CONTENT_TYPE);
    assert.match(ok.body ?? '', /auth_requests_total/);
    assert.equal(fake('POST').status, 405);
  });
});
