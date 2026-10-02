// Demo routes: each one reads its input from the request, calls exactly one Aegis function and
// returns its result as JSON. No authentication, session or token logic lives here.
import { Router, type Request, type Response } from 'express';
import type { Auth } from '../../auth/index.js';
import type { IssuedCredentials } from '../../auth/issue.js';
import { authError } from '../../errors/index.js';
import { authenticate, extractAccessToken, type AuthenticateOptions } from './middleware.js';
import { sendError } from './errors.js';

/** A string field of the JSON body, or VALIDATION_FAILED naming the field. */
function field(req: Request, name: string): string {
  const body: unknown = req.body;
  const value =
    typeof body === 'object' && body !== null ? (body as Record<string, unknown>)[name] : undefined;
  if (typeof value !== 'string') {
    throw authError('VALIDATION_FAILED', { details: { field: name, rule: 'required_string' } });
  }
  return value;
}

function hasField(req: Request, name: string): boolean {
  const body: unknown = req.body;
  return typeof body === 'object' && body !== null && name in body;
}

function tokens(c: IssuedCredentials): Record<string, unknown> {
  return {
    tokenType: 'Bearer',
    accessToken: c.accessToken,
    accessTokenExpiresAt: c.accessTokenExpiresAt,
    refreshToken: c.refreshToken,
    refreshTokenExpiresAt: c.refreshTokenExpiresAt,
  };
}

/** Wraps an async handler so every failure becomes a mapped error response. */
function handle(fn: (req: Request, res: Response) => Promise<void>) {
  return async (req: Request, res: Response): Promise<void> => {
    try {
      await fn(req, res);
    } catch (e) {
      sendError(res, e);
    }
  };
}

/**
 * POST /login    { identifier, password }  → 200 tokens
 * POST /refresh  { refreshToken }          → 200 tokens (the presented token is rotated)
 * POST /logout   { refreshToken } or Bearer → 204 (ends that session)
 * GET  /me       Bearer                    → 200 the authenticated principal
 */
export function createAuthRoutes(auth: Auth, options: AuthenticateOptions = {}): Router {
  const router = Router();
  const requireAuth = authenticate(auth, options);

  router.post(
    '/login',
    handle(async (req, res) => {
      const userAgent = req.get('user-agent');
      const result = await auth.authn.login({
        identifier: field(req, 'identifier'),
        password: field(req, 'password'),
        ...(req.ip !== undefined ? { clientIp: req.ip } : {}),
        ...(userAgent !== undefined ? { device: { userAgent } } : {}),
      });
      res.status(200).set('cache-control', 'no-store').json(tokens(result.credentials));
    }),
  );

  router.post(
    '/refresh',
    handle(async (req, res) => {
      const result = await auth.authn.refresh({
        refreshToken: field(req, 'refreshToken'),
        ...(req.ip !== undefined ? { clientIp: req.ip } : {}),
      });
      res.status(200).set('cache-control', 'no-store').json(tokens(result.credentials));
    }),
  );

  // Logout by refresh token works even after the access token expired; otherwise the Bearer
  // token's own session is ended. A session id is never taken from the client.
  router.post(
    '/logout',
    handle(async (req, res) => {
      if (hasField(req, 'refreshToken')) {
        await auth.authn.logout({ refreshToken: field(req, 'refreshToken') });
      } else {
        const principal = await auth.authn.authenticate(extractAccessToken(req, options));
        await auth.authn.logout({ principal });
      }
      res.status(204).set('cache-control', 'no-store').end();
    }),
  );

  router.get(
    '/me',
    requireAuth,
    handle(async (req, res) => {
      const p = req.principal as NonNullable<Request['principal']>;
      res
        .status(200)
        .set('cache-control', 'no-store')
        .json({
          id: p.id,
          type: p.type,
          ...(p.tenantId !== undefined ? { tenantId: p.tenantId } : {}),
          authMethod: p.authMethod,
          authenticatedAt: p.authenticatedAt,
          ...(p.amr !== undefined ? { amr: p.amr } : {}),
        });
    }),
  );

  return router;
}
