// Implements spec/auth/tokens.md §2 (access tokens) with the JWT profile of §2.6 (RFC 7519 JWT,
// RFC 7515 JWS compact serialization), signed by the keys of §6. Uses node:crypto only.
//
// THE JWT IS A TRANSPORT, NOT AN AUTHORITY
// A token that passes `verify` has only proven that *this server* issued it for a given session,
// and that it is unexpired. Whether that session may still act is decided by request resolution
// (`ResolutionService`), which on every request reads the session and the user's securityVersion
// from the store (tokens.md §2.5, strict revocation). Nothing in here can make a revoked session
// usable again.
//
// VERIFICATION ORDER (never throws; every problem is a VerifyFailure)
//   1. shape:    3 segments, strict canonical base64url, bounded length
//   2. header:   JSON object; typ = "at+jwt"; alg = the server-configured algorithm (the header never
//                chooses it; "none" is impossible); no crit/jwk/jku/x5u/x5c/zip; kid present
//   3. key:      looked up by kid among this server's keys only — never fetched from anywhere
//   4. signature verified over the exact received bytes, BEFORE any claim is read
//   5. claims:   iss, aud, typ, sub/sid/jti grammar, sv, iat/exp/nbf with bounded leeway, lifetime
//                no longer than the configured TTL, retired keys only vouch for older tokens
import { createHmac, sign as rsaSign, timingSafeEqual, verify as rsaVerify } from 'node:crypto';
import { isValidId, type Timestamp } from '../../domain/index.js';
import { authError, configInvalid, type ConfigViolation } from '../../errors/index.js';
import type {
  AccessTokenInput,
  AccessTokenProvider,
  Clock,
  IdGenerator,
  IssuedAccessToken,
  VerifiedAccessToken,
  VerifyFailure,
} from '../../ports/index.js';
import {
  InMemoryKeyProvider,
  type JwtAlgorithm,
  type KeyInput,
  type KeyProvider,
} from './keyProvider.js';

/** The JWT `typ` of an Aegis access token (RFC 9068). Distinct from every other token class. */
export const ACCESS_TOKEN_TYP = 'at+jwt';

const MAX_TOKEN_BYTES = 8 * 1024;
const MAX_LEEWAY_MS = 60_000;
const MAX_TTL_MS = 60 * 60_000;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
/** Header parameters that would let a token pick its own key or processing rules (spec §2.6.4). */
const FORBIDDEN_HEADERS = ['crit', 'jwk', 'jku', 'x5u', 'x5c', 'x5t', 'x5t#S256', 'zip'] as const;
const SECURITY_HEADER_PARAMS = ['alg', 'typ', 'kid'] as const;
const SECURITY_CLAIMS = [
  'iss',
  'aud',
  'sub',
  'sid',
  'iat',
  'exp',
  'nbf',
  'jti',
  'sv',
  'typ',
] as const;

// ---------------------------------------------------------------- configuration

export interface JwtConfigInput {
  readonly tokens: {
    readonly algorithm: JwtAlgorithm;
    readonly issuer: string;
    readonly audience: string;
    /** Access-token lifetime in ms; whole seconds, 1 s .. 60 min. Default 10 min. */
    readonly ttl?: number;
    /** Clock-skew leeway in ms, 0 .. 60 000. Default 0. */
    readonly leewayMs?: number;
  };
  readonly keys: {
    readonly rotationEnabled: boolean;
  };
}

export interface JwtConfig {
  readonly tokens: {
    readonly algorithm: JwtAlgorithm;
    readonly issuer: string;
    readonly audience: string;
    readonly ttl: number;
    readonly leewayMs: number;
  };
  readonly keys: { readonly rotationEnabled: boolean };
}

/** Validates the JWT configuration. Throws CONFIG_INVALID listing every violation. */
export function resolveJwtConfig(input: JwtConfigInput): JwtConfig {
  const v: ConfigViolation[] = [];
  const t = input?.tokens ?? ({} as Partial<JwtConfigInput['tokens']>);
  const algorithm = t.algorithm;
  if (algorithm !== 'HS256' && algorithm !== 'RS256') {
    v.push({ path: 'tokens.algorithm', rule: 'jwt.algorithm', message: 'must be HS256 or RS256' });
  }
  for (const field of ['issuer', 'audience'] as const) {
    const value = t[field];
    if (typeof value !== 'string' || value.length === 0 || value.length > 256) {
      v.push({
        path: `tokens.${field}`,
        rule: `jwt.${field}`,
        message: 'must be a non-empty string of at most 256 characters',
      });
    }
  }
  const ttl = t.ttl ?? 10 * 60_000;
  if (!Number.isInteger(ttl) || ttl < 1000 || ttl > MAX_TTL_MS || ttl % 1000 !== 0) {
    // JWT times are whole seconds (NumericDate), and tokens.md §2.3.1 caps the lifetime at 60 min.
    v.push({
      path: 'tokens.ttl',
      rule: 'jwt.ttl',
      message: 'must be whole seconds between 1 s and 60 min (in ms)',
    });
  }
  const leewayMs = t.leewayMs ?? 0;
  if (!Number.isInteger(leewayMs) || leewayMs < 0 || leewayMs > MAX_LEEWAY_MS) {
    v.push({
      path: 'tokens.leewayMs',
      rule: 'jwt.leeway',
      message: 'must be an integer in 0..60000',
    });
  }
  if (typeof input?.keys?.rotationEnabled !== 'boolean') {
    v.push({ path: 'keys.rotationEnabled', rule: 'keys.rotation', message: 'must be a boolean' });
  }
  if (v.length > 0) throw configInvalid(v);
  return Object.freeze({
    tokens: Object.freeze({
      algorithm: algorithm as JwtAlgorithm,
      issuer: t.issuer as string,
      audience: t.audience as string,
      ttl,
      leewayMs,
    }),
    keys: Object.freeze({ rotationEnabled: input.keys.rotationEnabled }),
  });
}

// ---------------------------------------------------------------- encoding helpers

function b64url(data: string | Buffer): string {
  return Buffer.from(data).toString('base64url');
}

/**
 * Strict base64url decoding: only the URL-safe alphabet, no padding, and canonical (re-encoding the
 * bytes must reproduce the input). Node's decoder silently skips invalid characters and ignores
 * non-canonical trailing bits, which would let two different strings verify as the same token.
 */
function decodeSegment(segment: string): Buffer | null {
  if (!B64URL_RE.test(segment)) return null;
  const bytes = Buffer.from(segment, 'base64url');
  return bytes.toString('base64url') === segment ? bytes : null;
}

/** Parses a JSON object; rejects arrays, scalars and duplicated security-relevant members. */
function parseObject(bytes: Buffer, guarded: readonly string[]): Record<string, unknown> | null {
  const text = bytes.toString('utf8');
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  // JSON.parse keeps the last of duplicated members; spec §2.3.5 requires rejecting duplicates of
  // security-relevant members instead of guessing which one was meant.
  for (const name of guarded) {
    const occurrences = text.match(new RegExp(`"${name.replace(/[#]/g, '\\$&')}"\\s*:`, 'g'));
    if (occurrences && occurrences.length > 1) return null;
  }
  return value as Record<string, unknown>;
}

function isNumericDate(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
}

// ---------------------------------------------------------------- provider

/** A real JWT access-token provider (spec §2.2) over a KeyProvider (spec §6). */
export class JwtAccessTokenProvider implements AccessTokenProvider {
  /** The lifetime this provider issues; createAuth requires the core's access TTL to equal it. */
  readonly ttlMs: number;
  private readonly ttlSeconds: number;

  /** @throws CONFIG_INVALID when the key provider does not fit the configuration. */
  constructor(
    readonly config: JwtConfig,
    private readonly keys: KeyProvider,
    private readonly ids: IdGenerator,
  ) {
    const v: ConfigViolation[] = [];
    if (keys.algorithm !== config.tokens.algorithm) {
      v.push({
        path: 'keys.algorithm',
        rule: 'jwt.algorithm_mismatch',
        message: 'key provider algorithm differs from tokens.algorithm',
      });
    }
    // Spec §6.2.3: a retired key must keep verifying until every token it signed has expired.
    if (keys.retiredKeyGraceMs < config.tokens.ttl + config.tokens.leewayMs) {
      v.push({
        path: 'keys.retiredKeyGraceMs',
        rule: 'jwt.retired_grace',
        message: 'must be >= tokens.ttl + tokens.leewayMs',
      });
    }
    if (v.length > 0) throw configInvalid(v);
    this.ttlMs = config.tokens.ttl;
    this.ttlSeconds = config.tokens.ttl / 1000;
  }

  /**
   * Signs a token with the active key. Claims are exactly those of spec §2.3: no roles, no
   * permissions, no PII. `iat`/`exp` are JWT NumericDates (seconds).
   */
  issue(input: AccessTokenInput, now: Timestamp): IssuedAccessToken {
    if (input.ttlMs !== this.ttlMs) {
      // createAuth enforces equality at construction; reaching this is a wiring defect.
      throw authError('INTERNAL');
    }
    const key = this.keys.getActiveKey();
    const iat = Math.floor(now / 1000);
    const exp = iat + this.ttlSeconds;
    const jti = this.ids.newId();
    const header = { alg: key.algorithm, typ: ACCESS_TOKEN_TYP, kid: key.kid };
    const payload = {
      iss: this.config.tokens.issuer,
      aud: this.config.tokens.audience,
      sub: input.subjectId,
      sid: input.sessionId,
      iat,
      exp,
      jti,
      sv: input.securityVersion,
      typ: ACCESS_TOKEN_TYP,
    };
    const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
    const signature =
      key.algorithm === 'HS256'
        ? createHmac('sha256', key.key).update(signingInput, 'utf8').digest()
        : rsaSign('sha256', Buffer.from(signingInput, 'utf8'), key.key);
    return {
      token: `${signingInput}.${b64url(signature)}`,
      jti,
      issuedAt: iat * 1000,
      expiresAt: exp * 1000,
    };
  }

  /** Spec §2.2: never throws, for any input. See the module note for the order of checks. */
  verify(
    token: string,
    now: Timestamp,
  ): { ok: true; token: VerifiedAccessToken } | { ok: false; failure: VerifyFailure } {
    const fail = (failure: VerifyFailure): { ok: false; failure: VerifyFailure } => ({
      ok: false,
      failure,
    });
    try {
      // ---- 1. shape
      if (typeof token !== 'string' || token.length === 0) return fail('malformed');
      if (Buffer.byteLength(token, 'utf8') > MAX_TOKEN_BYTES) return fail('malformed');
      const parts = token.split('.');
      if (parts.length !== 3) return fail('malformed');
      const [h, p, s] = parts as [string, string, string];
      const headerBytes = decodeSegment(h);
      const payloadBytes = decodeSegment(p);
      const signature = decodeSegment(s);
      if (!headerBytes || !payloadBytes || !signature) return fail('malformed');

      // ---- 2. header
      const header = parseObject(headerBytes, SECURITY_HEADER_PARAMS);
      if (!header) return fail('malformed');
      if (header['typ'] !== ACCESS_TOKEN_TYP) return fail('wrong_type');
      // The server's configuration decides the algorithm; the token can only agree with it.
      if (header['alg'] !== this.keys.algorithm) return fail('unsupported_algorithm');
      for (const forbidden of FORBIDDEN_HEADERS) {
        if (Object.hasOwn(header, forbidden)) return fail('malformed');
      }
      const kid = header['kid'];
      if (typeof kid !== 'string' || kid.length === 0) return fail('malformed');

      // ---- 3. key: only this server's keys, by kid; nothing is fetched (spec §2.6.3)
      const key = this.keys.getKeyById(kid, now);
      if (!key) return fail('unknown_key');

      // ---- 4. signature, before any claim is trusted (spec §2.3.6)
      const signingInput = Buffer.from(`${h}.${p}`, 'utf8');
      const valid =
        key.algorithm === 'HS256'
          ? (() => {
              const expected = createHmac('sha256', key.key).update(signingInput).digest();
              return expected.length === signature.length && timingSafeEqual(expected, signature);
            })()
          : rsaVerify('sha256', signingInput, key.key, signature);
      if (!valid) return fail('bad_signature');

      // ---- 5. claims
      const claims = parseObject(payloadBytes, SECURITY_CLAIMS);
      if (!claims) return fail('malformed');
      if (claims['typ'] !== ACCESS_TOKEN_TYP) return fail('wrong_type');
      if (claims['iss'] !== this.config.tokens.issuer) return fail('wrong_issuer');
      const aud = claims['aud'];
      const audienceOk =
        aud === this.config.tokens.audience ||
        (Array.isArray(aud) && aud.length <= 16 && aud.includes(this.config.tokens.audience));
      if (!audienceOk) return fail('wrong_audience');

      const { sub, sid, jti, sv, iat, exp, nbf } = claims;
      if (!isValidId(sub) || !isValidId(sid) || !isValidId(jti)) return fail('malformed');
      if (!Number.isSafeInteger(sv) || (sv as number) < 0) return fail('malformed');
      if (!isNumericDate(iat) || !isNumericDate(exp) || exp <= iat) return fail('malformed');
      // A lifetime longer than this server ever issues cannot be one of our tokens.
      if (exp - iat > this.ttlSeconds) return fail('malformed');

      const leeway = this.config.tokens.leewayMs;
      if (iat * 1000 > now + leeway) return fail('not_yet_valid');
      if (nbf !== undefined) {
        if (!isNumericDate(nbf)) return fail('malformed');
        if (nbf * 1000 > now + leeway) return fail('not_yet_valid');
      }
      // A retired key only vouches for tokens issued before its retirement: a leaked old key cannot
      // mint new tokens even inside its verification window.
      if (
        key.status === 'retired' &&
        key.retiredAt !== undefined &&
        iat * 1000 > key.retiredAt + leeway
      ) {
        return fail('unknown_key');
      }
      // Expiry last: TOKEN_EXPIRED is only ever reported for a genuine, otherwise valid token.
      if (now - leeway >= exp * 1000) return fail('expired');

      return {
        ok: true,
        token: {
          subjectId: sub,
          sessionId: sid,
          securityVersion: sv as number,
          jti,
          issuedAt: iat * 1000,
          expiresAt: exp * 1000,
        },
      };
    } catch {
      // Defensive: verification never throws (spec §2.2).
      return fail('malformed');
    }
  }
}

/**
 * Convenience wiring: validates the configuration, builds the key provider with the retirement
 * grace the configuration implies (ttl + leeway, so it can never be set too short), and returns
 * both. Keep the key provider to rotate keys at runtime.
 *
 * @throws CONFIG_INVALID listing every violation in the configuration or the keys.
 */
export function createJwtAccessTokens(
  input: JwtConfigInput,
  deps: { readonly keys: readonly KeyInput[]; readonly clock: Clock; readonly ids: IdGenerator },
): { readonly accessTokens: JwtAccessTokenProvider; readonly keys: InMemoryKeyProvider } {
  const config = resolveJwtConfig(input);
  const keys = new InMemoryKeyProvider({
    algorithm: config.tokens.algorithm,
    keys: deps.keys,
    rotationEnabled: config.keys.rotationEnabled,
    retiredKeyGraceMs: config.tokens.ttl + config.tokens.leewayMs,
    clock: deps.clock,
  });
  return { accessTokens: new JwtAccessTokenProvider(config, keys, deps.ids), keys };
}
