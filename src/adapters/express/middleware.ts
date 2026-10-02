// Express middleware over the Aegis facade. Transport only: it finds the credential in the request,
// hands it to `auth.authn.authenticate` (signature, then the session store: strict revocation) and
// `auth.authz.authorize`, and encodes the outcome. It never decodes a token and caches nothing.
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { Auth } from '../../auth/index.js';
import type { Principal } from '../../domain/index.js';
import { authError, configInvalid } from '../../errors/index.js';
import type { Resource } from '../../policy/index.js';
import { sendError } from './errors.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /** Set by `authenticate()` for the lifetime of this request only. */
      principal?: Principal;
    }
  }
}

export interface AuthenticateOptions {
  /**
   * Also accept the access token from this cookie when there is no Authorization header. Off by
   * default. A cookie is sent by the browser automatically, so cookie authentication needs CSRF
   * protection (SameSite=Strict or Lax cookies, or an anti-CSRF token) in the application.
   */
  readonly cookieName?: string;
}

const COOKIE_NAME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/;
// RFC 6750 §2.1: "Bearer" 1*SP b64token. The scheme is case-insensitive.
const BEARER_RE = /^Bearer +([A-Za-z0-9\-._~+/]+=*) *$/i;

/** The raw value of one cookie, or undefined. No other cookie is read or decoded. */
function readCookie(header: string | undefined, name: string): string | undefined {
  if (header === undefined) return undefined;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1 || part.slice(0, eq).trim() !== name) continue;
    const raw = part.slice(eq + 1).trim();
    try {
      return decodeURIComponent(raw.startsWith('"') && raw.endsWith('"') ? raw.slice(1, -1) : raw);
    } catch {
      return raw;
    }
  }
  return undefined;
}

/**
 * The credential presented with the request: the Bearer token of the Authorization header or,
 * only when there is no such header and a cookie name is configured, that cookie. Null when none.
 * A present but malformed Authorization header is TOKEN_INVALID (never a silent fallback).
 */
export function extractAccessToken(req: Request, options: AuthenticateOptions = {}): string | null {
  const header = req.get('authorization');
  if (header !== undefined) {
    const m = BEARER_RE.exec(header);
    if (!m) throw authError('TOKEN_INVALID');
    return m[1] as string;
  }
  if (options.cookieName !== undefined) {
    const value = readCookie(req.get('cookie'), options.cookieName);
    if (value !== undefined && value.length > 0) return value;
  }
  return null;
}

function validateOptions(options: AuthenticateOptions): void {
  if (options.cookieName !== undefined && !COOKIE_NAME_RE.test(options.cookieName)) {
    throw configInvalid([
      { path: 'cookieName', rule: 'express.cookie_name', message: 'must be a valid cookie name' },
    ]);
  }
}

/**
 * Requires a valid credential. On success `req.principal` is set and the next handler runs; on
 * failure the response is 401 (or 503 when storage is unavailable) and the chain stops.
 */
export function authenticate(auth: Auth, options: AuthenticateOptions = {}): RequestHandler {
  validateOptions(options);
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    let principal: Principal;
    try {
      principal = await auth.authn.authenticate(extractAccessToken(req, options));
    } catch (e) {
      sendError(res, e);
      return;
    }
    req.principal = principal;
    next();
  };
}

export interface AuthorizeOptions {
  /**
   * Builds the resource the decision is about (id, owner, tenant, …) so policies can apply. Its
   * `type` is always the permission's resource type. Default: the bare resource type.
   */
  readonly resource?: (req: Request) => Omit<Resource, 'type'> | Promise<Omit<Resource, 'type'>>;
}

/**
 * Requires `permission` ("resource:action") for `req.principal`, decided by `auth.authz.authorize`.
 * Must run after `authenticate()`. No principal → 401; deny → 403.
 *
 * @throws CONFIG_INVALID at construction when `permission` is not "resource:action".
 */
export function authorize(
  auth: Auth,
  permission: string,
  options: AuthorizeOptions = {},
): RequestHandler {
  const colon = typeof permission === 'string' ? permission.indexOf(':') : -1;
  if (colon <= 0 || colon === permission.length - 1) {
    throw configInvalid([
      { path: 'permission', rule: 'express.permission', message: 'must be "resource:action"' },
    ]);
  }
  const resourceType = permission.slice(0, colon);
  const action = permission.slice(colon + 1);
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (req.principal === undefined) throw authError('UNAUTHENTICATED');
      const resource: Resource | string =
        options.resource === undefined
          ? resourceType
          : { ...(await options.resource(req)), type: resourceType };
      const decision = await auth.authz.authorize(req.principal, action, resource);
      if (decision.effect !== 'allow') {
        throw authError('FORBIDDEN', {
          ...(decision.permission !== undefined
            ? { details: { permission: decision.permission } }
            : {}),
        });
      }
    } catch (e) {
      sendError(res, e);
      return;
    }
    next();
  };
}
