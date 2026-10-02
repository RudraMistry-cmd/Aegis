// Prometheus metrics for an Aegis deployment. Observability only: counters are fed by wrapping the
// public `Auth` facade from the outside and by watching the active signing key, so no auth, token
// or key code changes. The text exposition format is written directly (no client library):
// https://prometheus.io/docs/instrumenting/exposition_formats/
//
// Labels are bounded on purpose (an error code is one of a fixed catalog; never a user, session
// or kid), so the series count cannot grow with traffic.
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Auth } from '../auth/index.js';
import { isAuthError, type ErrorCode } from '../errors/index.js';

export const METRICS_CONTENT_TYPE = 'text/plain; version=0.0.4; charset=utf-8';

const NAME_RE = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;

function escapeLabel(v: string): string {
  return v.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
}

/** A monotonically increasing counter, optionally with one label dimension. */
export class Counter {
  private readonly values = new Map<string, number>();

  constructor(
    readonly name: string,
    readonly help: string,
    readonly labelName?: string,
  ) {
    if (!NAME_RE.test(name) || (labelName !== undefined && !NAME_RE.test(labelName))) {
      throw new Error(`invalid metric or label name: ${name}`);
    }
  }

  inc(labelValue?: string, by = 1): void {
    if (!(by >= 0)) throw new Error('a counter only increases');
    const key = this.labelName === undefined ? '' : (labelValue ?? '');
    this.values.set(key, (this.values.get(key) ?? 0) + by);
  }

  /** Current value, for tests and dashboards. */
  get(labelValue?: string): number {
    return this.values.get(this.labelName === undefined ? '' : (labelValue ?? '')) ?? 0;
  }

  render(): string {
    const lines = [`# HELP ${this.name} ${this.help}`, `# TYPE ${this.name} counter`];
    if (this.labelName === undefined) {
      lines.push(`${this.name} ${this.values.get('') ?? 0}`);
    } else {
      for (const [v, n] of [...this.values].sort(([a], [b]) => a.localeCompare(b))) {
        lines.push(`${this.name}{${this.labelName}="${escapeLabel(v)}"} ${n}`);
      }
    }
    return lines.join('\n');
  }
}

/** The Aegis counters. */
export interface AegisMetrics {
  /** `result` = "success" or the Aegis error code (a fixed catalog). */
  readonly authRequests: Counter;
  readonly refreshSuccess: Counter;
  /** Changes of the active signing key observed by this instance. */
  readonly keyRotations: Counter;
  render(): string;
}

export function createAegisMetrics(): AegisMetrics {
  const authRequests = new Counter(
    'auth_requests_total',
    'Access-token authentications by result (success or Aegis error code).',
    'result',
  );
  const refreshSuccess = new Counter(
    'refresh_success_total',
    'Successful refresh-token rotations.',
  );
  const keyRotations = new Counter(
    'key_rotations_total',
    'Changes of the active signing key observed by this instance.',
  );
  const all = [authRequests, refreshSuccess, keyRotations];
  return {
    authRequests,
    refreshSuccess,
    keyRotations,
    render: () => `${all.map((c) => c.render()).join('\n')}\n`,
  };
}

/** `GET /metrics` for Express or plain `node:http`. Anything else is 405. */
export function metricsHandler(metrics: AegisMetrics) {
  return (req: IncomingMessage, res: ServerResponse): void => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD' }).end();
      return;
    }
    const body = metrics.render();
    res.writeHead(200, { 'content-type': METRICS_CONTENT_TYPE, 'cache-control': 'no-store' });
    res.end(req.method === 'HEAD' ? undefined : body);
  };
}

/**
 * Returns the same `Auth`, with `authn.authenticate` and `authn.refresh` counted. Results and
 * errors pass through unchanged; only the counters are touched.
 */
export function instrumentAuth(auth: Auth, metrics: AegisMetrics): Auth {
  const result = (e: unknown): ErrorCode | 'error' => (isAuthError(e) ? e.code : 'error');
  return {
    ...auth,
    authn: {
      ...auth.authn,
      authenticate: async (token) => {
        try {
          const p = await auth.authn.authenticate(token);
          metrics.authRequests.inc('success');
          return p;
        } catch (e) {
          metrics.authRequests.inc(result(e));
          throw e;
        }
      },
      refresh: async (input) => {
        const r = await auth.authn.refresh(input);
        metrics.refreshSuccess.inc();
        return r;
      },
    },
  };
}

/**
 * Counts changes of the active key id as seen by this instance (it reloads the keyring from the
 * shared store, so rotations made by another instance or by the key CLI are seen too). Returns a
 * stop function; the timer never keeps the process alive.
 */
export function watchKeyRotations(
  activeKid: () => string | null,
  metrics: AegisMetrics,
  intervalMs = 5_000,
): () => void {
  let last = activeKid();
  const timer = setInterval(() => {
    const now = activeKid();
    if (now !== null && last !== null && now !== last) metrics.keyRotations.inc();
    if (now !== null) last = now;
  }, intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}
