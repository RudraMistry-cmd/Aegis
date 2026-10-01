// Implements spec/auth/tokens.md §2: a format-neutral access token provider.
//
// This is the Phase 1 STUB provider required by the brief ("token generator (stub, not real JWT)").
// It is a compact MAC-protected format, not a JWT: `at1.<base64url(payload)>.<base64url(mac)>`.
// It implements the normative parts of tokens.md §2.2-§2.5 (claim set, type/issuer/audience
// discrimination, leeway bounds, never throwing on malformed input, verifying the MAC before any
// claim is trusted). The JWT profile of tokens.md §2.6 and key rotation of §6 are NOT implemented.
// TODO(spec/auth/tokens.md §2.6, §6): JWT provider and KeyProvider/kid rotation.
import { createHmac, timingSafeEqual } from 'node:crypto';
import type { Timestamp } from '../domain/index.js';
import { configInvalid, type ConfigViolation } from '../errors/index.js';
import type {
  AccessTokenInput,
  AccessTokenProvider,
  IdGenerator,
  IssuedAccessToken,
  VerifiedAccessToken,
  VerifyFailure,
} from '../ports/index.js';

/** The token type discriminator; distinct from every other token class (tokens.md §2.3.3). */
const TOKEN_TYPE = 'at1';
/** Rejects oversized input before any work (tokens.md §2.2). */
const MAX_TOKEN_BYTES = 8 * 1024;
/** tokens.md §2.3.4: leeway must not exceed 60 s. */
const MAX_LEEWAY_MS = 60_000;

export interface StubAccessTokenOptions {
  /** MAC secret; at least 32 bytes (tokens.md §6.4). */
  readonly secret: string;
  readonly issuer: string;
  readonly audience: string;
  readonly ids: IdGenerator;
  /** Clock-skew leeway in ms, 0..60000. Default 0. */
  readonly leewayMs?: number;
}

interface Payload {
  readonly iss: string;
  readonly aud: string;
  readonly sub: string;
  readonly sid: string;
  readonly iat: number;
  readonly exp: number;
  readonly nbf?: number;
  readonly jti: string;
  readonly sv: number;
  readonly typ: string;
}

export class StubAccessTokenProvider implements AccessTokenProvider {
  private readonly secret: Buffer;
  private readonly issuer: string;
  private readonly audience: string;
  private readonly ids: IdGenerator;
  private readonly leewayMs: number;

  constructor(opts: StubAccessTokenOptions) {
    const v: ConfigViolation[] = [];
    if (typeof opts.secret !== 'string' || Buffer.byteLength(opts.secret, 'utf8') < 32) {
      v.push({
        path: 'accessTokens.secret',
        rule: 'key.min_length',
        message: 'secret must be at least 32 bytes',
      });
    }
    if (/^(changeme|secret|test|password)$/i.test(opts.secret ?? '')) {
      v.push({
        path: 'accessTokens.secret',
        rule: 'key.placeholder',
        message: 'placeholder secret rejected',
      });
    }
    if (!opts.issuer) {
      v.push({ path: 'accessTokens.issuer', rule: 'token.issuer', message: 'issuer is required' });
    }
    // tokens.md §2.3.3 / conformance TOK-ACC-09: a verifier without an audience is invalid.
    if (!opts.audience) {
      v.push({
        path: 'accessTokens.audience',
        rule: 'token.audience',
        message: 'audience is required',
      });
    }
    const leeway = opts.leewayMs ?? 0;
    if (!Number.isInteger(leeway) || leeway < 0 || leeway > MAX_LEEWAY_MS) {
      v.push({
        path: 'accessTokens.leewayMs',
        rule: 'token.leeway',
        message: 'leeway must be 0..60000 ms',
      });
    }
    if (v.length > 0) throw configInvalid(v);
    this.secret = Buffer.from(opts.secret, 'utf8');
    this.issuer = opts.issuer;
    this.audience = opts.audience;
    this.ids = opts.ids;
    this.leewayMs = leeway;
  }

  /** Issues a token carrying only the claims of tokens.md §2.3 (no roles, no PII). */
  issue(input: AccessTokenInput, now: Timestamp): IssuedAccessToken {
    const payload: Payload = {
      iss: this.issuer,
      aud: this.audience,
      sub: input.subjectId,
      sid: input.sessionId,
      iat: now,
      exp: now + input.ttlMs,
      jti: this.ids.newId(),
      sv: input.securityVersion,
      typ: TOKEN_TYPE,
    };
    const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const token = `${TOKEN_TYPE}.${body}.${this.mac(body)}`;
    return { token, jti: payload.jti, issuedAt: payload.iat, expiresAt: payload.exp };
  }

  /**
   * Verifies a token. MUST NOT throw for any input (tokens.md §2.2); every problem is a
   * `VerifyFailure`. The MAC is checked before any claim is parsed.
   */
  verify(
    token: string,
    now: Timestamp,
  ): { ok: true; token: VerifiedAccessToken } | { ok: false; failure: VerifyFailure } {
    const fail = (failure: VerifyFailure): { ok: false; failure: VerifyFailure } => ({
      ok: false,
      failure,
    });
    try {
      if (typeof token !== 'string' || token.length === 0) return fail('malformed');
      if (Buffer.byteLength(token, 'utf8') > MAX_TOKEN_BYTES) return fail('malformed');
      const parts = token.split('.');
      if (parts.length !== 3) return fail('malformed');
      const [typ, body, mac] = parts as [string, string, string];
      // Type discrimination before anything else: a refresh/session token can never verify here.
      if (typ !== TOKEN_TYPE) return fail('wrong_type');
      if (body.length === 0 || mac.length === 0) return fail('malformed');
      if (!this.macEquals(body, mac)) return fail('bad_signature');

      // Only now may the claims be trusted.
      let parsed: unknown;
      try {
        parsed = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
      } catch {
        return fail('malformed');
      }
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed))
        return fail('malformed');
      const p = parsed as Record<string, unknown>;
      if (p['typ'] !== TOKEN_TYPE) return fail('wrong_type');
      if (
        typeof p['sub'] !== 'string' ||
        typeof p['sid'] !== 'string' ||
        typeof p['jti'] !== 'string'
      ) {
        return fail('malformed');
      }
      if (!Number.isFinite(p['iat']) || !Number.isFinite(p['exp']) || !Number.isInteger(p['sv'])) {
        return fail('malformed');
      }
      if (p['iss'] !== this.issuer) return fail('wrong_issuer');
      if (p['aud'] !== this.audience) return fail('wrong_audience');
      const nbf = p['nbf'];
      if (nbf !== undefined) {
        if (!Number.isFinite(nbf)) return fail('malformed');
        if (now + this.leewayMs < (nbf as number)) return fail('not_yet_valid');
      }
      if (now - this.leewayMs >= (p['exp'] as number)) return fail('expired');
      return {
        ok: true,
        token: {
          subjectId: p['sub'],
          sessionId: p['sid'],
          securityVersion: p['sv'] as number,
          jti: p['jti'],
          issuedAt: p['iat'] as number,
          expiresAt: p['exp'] as number,
        },
      };
    } catch {
      // Defensive: verification never throws.
      return fail('malformed');
    }
  }

  private mac(body: string): string {
    return createHmac('sha256', this.secret).update(body, 'utf8').digest('base64url');
  }

  private macEquals(body: string, provided: string): boolean {
    const expected = Buffer.from(this.mac(body), 'utf8');
    const got = Buffer.from(provided, 'utf8');
    return expected.length === got.length && timingSafeEqual(expected, got);
  }
}
