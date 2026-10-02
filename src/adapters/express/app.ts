// A ready-to-run Express app over an Aegis instance: JSON body parsing, the demo auth routes, the
// JWKS document, and error encoding. Applications usually mount the pieces into their own app.
import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import type { Auth } from '../../auth/index.js';
import type { JwksHandler } from '../../auth/jwt/jwks.js';
import { authError } from '../../errors/index.js';
import { sendError } from './errors.js';
import type { AuthenticateOptions } from './middleware.js';
import { createAuthRoutes } from './routes.js';

export interface AegisExpressInput {
  readonly auth: Auth;
  /** From `openJwtAccessTokens` (RS256 only); null or absent → no JWKS route. */
  readonly jwks?: JwksHandler | null;
  readonly authentication?: AuthenticateOptions;
  /** Maximum JSON body size. Default '16kb'. */
  readonly bodyLimit?: string;
}

/** Serves `jwks.handle()` as is: its body, status and headers (including Cache-Control). */
export function jwksRoute(jwks: JwksHandler) {
  return (_req: Request, res: Response): void => {
    try {
      const r = jwks.handle();
      res.status(r.status).set(r.headers).send(r.body);
    } catch (e) {
      sendError(res, e);
    }
  };
}

export function createExpressApp(aegis: AegisExpressInput): Express {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: aegis.bodyLimit ?? '16kb' }));

  if (aegis.jwks) app.get(aegis.jwks.path, jwksRoute(aegis.jwks));
  app.use(createAuthRoutes(aegis.auth, aegis.authentication));

  app.use((_req: Request, res: Response) => sendError(res, authError('NOT_FOUND')));
  // Four parameters: Express's error-handler signature (malformed JSON, oversize bodies, …).
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => sendError(res, err));
  return app;
}
