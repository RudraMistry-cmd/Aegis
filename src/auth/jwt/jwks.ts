// A JSON Web Key Set (RFC 7517) of this server's token-verification keys, served at
// `/.well-known/jwks.json` so other services can verify Aegis access tokens on their own.
//
// WHAT IS PUBLISHED: exactly the public keys this server itself would accept a signature from at this
// instant (`KeyProvider.verificationKeys`) — the active key, pending keys (so verifiers can cache a
// new key before it signs anything), and retired keys still inside their ttl + leeway window. A key
// stops appearing the moment this server would stop accepting it.
//
// WHAT IS NEVER PUBLISHED: private material. Each entry is built from a PUBLIC KeyObject and then
// reduced to an explicit whitelist {kty, kid, alg, use, n, e}; private members (d, p, q, dp, dq, qi)
// cannot appear even if a caller passed something unexpected. HS256 keys are shared secrets, so an
// HS256 deployment has nothing to publish: building a JWKS for it is refused (CONFIG_INVALID).
//
// Server-agnostic: `handle()` returns status, headers and body for any HTTP framework to send.
import type { Timestamp } from '../../domain/index.js';
import { configInvalid } from '../../errors/index.js';
import type { Clock } from '../../ports/index.js';
import type { KeyProvider } from './keyProvider.js';

export interface PublicJwk {
  readonly kty: 'RSA';
  readonly kid: string;
  readonly alg: 'RS256';
  readonly use: 'sig';
  readonly n: string;
  readonly e: string;
}

export interface JwksDocument {
  readonly keys: readonly PublicJwk[];
}

export interface JwksResponse {
  readonly status: 200;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

export interface JwksHandler {
  /** The path to mount, e.g. `/.well-known/jwks.json`. */
  readonly path: string;
  /** Builds the response for the current instant. Never throws for a correctly built handler. */
  handle(): JwksResponse;
}

export interface JwksOptions {
  readonly path?: string;
  /** `Cache-Control: max-age`. Default 300 s; 0 .. 86 400. See docs/JWKS.md for choosing it. */
  readonly cacheTtlSec?: number;
  readonly clock: Clock;
}

function refuseHmac(): never {
  throw configInvalid([
    {
      path: 'keys.jwks',
      rule: 'jwks.hmac',
      message:
        'HS256 keys are shared secrets and cannot be published; use RS256 for external verifiers',
    },
  ]);
}

/** The JWKS document for `now`. Refuses HS256 providers. */
export function buildJwks(provider: KeyProvider, now: Timestamp): JwksDocument {
  if (provider.algorithm !== 'RS256') refuseHmac();
  const keys: PublicJwk[] = [];
  for (const k of provider.verificationKeys(now)) {
    // Defence in depth: only ever export a public key, and only the whitelisted members.
    if (k.key.type !== 'public' || k.key.asymmetricKeyType !== 'rsa') continue;
    const jwk = k.key.export({ format: 'jwk' });
    if (typeof jwk.n !== 'string' || typeof jwk.e !== 'string') continue;
    keys.push({ kty: 'RSA', kid: k.kid, alg: 'RS256', use: 'sig', n: jwk.n, e: jwk.e });
  }
  keys.sort((a, b) => (a.kid < b.kid ? -1 : a.kid > b.kid ? 1 : 0));
  return { keys };
}

/**
 * A server-agnostic JWKS endpoint. Configuration problems are reported here, at construction, never
 * per request.
 *
 * @throws CONFIG_INVALID for an HS256 provider, an invalid path or an invalid cache TTL.
 */
export function createJwksHandler(provider: KeyProvider, options: JwksOptions): JwksHandler {
  if (provider.algorithm !== 'RS256') refuseHmac();
  const path = options.path ?? '/.well-known/jwks.json';
  const ttl = options.cacheTtlSec ?? 300;
  const violations = [];
  if (typeof path !== 'string' || !/^\/[A-Za-z0-9._~/-]*$/.test(path)) {
    violations.push({
      path: 'keys.jwks.path',
      rule: 'jwks.path',
      message: 'must be an absolute URL path',
    });
  }
  if (!Number.isInteger(ttl) || ttl < 0 || ttl > 86_400) {
    violations.push({
      path: 'keys.jwks.cacheTtlSec',
      rule: 'jwks.cache_ttl',
      message: 'must be an integer in 0..86400',
    });
  }
  if (violations.length > 0) throw configInvalid(violations);
  return {
    path,
    handle: () => ({
      status: 200,
      headers: {
        'content-type': 'application/jwk-set+json; charset=utf-8',
        'cache-control': `public, max-age=${ttl}`,
        'x-content-type-options': 'nosniff',
      },
      body: JSON.stringify(buildJwks(provider, options.clock.now())),
    }),
  };
}
