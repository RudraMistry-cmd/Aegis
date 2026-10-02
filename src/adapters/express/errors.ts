// HTTP encoding of Aegis errors (spec/errors.md §1 and the transport note in §2). Pure mapping:
// every response carries the code and its fixed message; internal causes, stacks and
// configuration details never leave the process.
import type { Response } from 'express';
import { AuthError, isAuthError, type ErrorCode } from '../../errors/index.js';

/** One HTTP status per error code. Codes not named in the adapter brief follow the spec's category rule. */
export const HTTP_STATUS: Readonly<Record<ErrorCode, number>> = {
  UNAUTHENTICATED: 401,
  TOKEN_EXPIRED: 401,
  TOKEN_INVALID: 401,
  INVALID_CREDENTIALS: 401,
  ACCOUNT_RESTRICTED: 401,
  SESSION_LIMIT_REACHED: 401,
  FORBIDDEN: 403,
  ESCALATION_DENIED: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  VALIDATION_FAILED: 400,
  STATE_TRANSITION_INVALID: 400,
  PRECONDITION_FAILED: 400,
  RATE_LIMITED: 429,
  CONFIG_INVALID: 500,
  INTERNAL: 500,
  STORAGE_UNAVAILABLE: 503,
};

/** The JSON body of an error response. */
export interface ErrorBody {
  readonly error: {
    readonly code: ErrorCode;
    readonly message: string;
    readonly retryable: boolean;
    /** Whitelisted details (errors.md §2), client errors only. */
    readonly details?: Readonly<Record<string, unknown>>;
  };
}

/**
 * Normalises anything thrown into an AuthError. Malformed request bodies rejected by the Express
 * body parser (http-errors with a 4xx `status` and `expose: true`) become VALIDATION_FAILED;
 * everything else that is not an AuthError becomes INTERNAL.
 */
export function toHttpAuthError(e: unknown): AuthError {
  if (isAuthError(e)) return e;
  if (typeof e === 'object' && e !== null) {
    const { status, expose } = e as { status?: unknown; expose?: unknown };
    if (typeof status === 'number' && status >= 400 && status < 500 && expose === true) {
      return new AuthError('VALIDATION_FAILED', { details: { rule: 'request.body' }, cause: e });
    }
  }
  return new AuthError('INTERNAL', { cause: e });
}

/** Status, headers and body for an error. Details are never sent with a 5xx. */
export function errorResponse(e: unknown): {
  status: number;
  headers: Record<string, string>;
  body: ErrorBody;
} {
  const err = toHttpAuthError(e);
  const status = HTTP_STATUS[err.code];
  const headers: Record<string, string> = { 'cache-control': 'no-store' };
  if (status === 401) {
    // RFC 6750 §3: a presented token that failed gets error="invalid_token"; none presented gets none.
    headers['www-authenticate'] =
      err.code === 'TOKEN_INVALID' || err.code === 'TOKEN_EXPIRED'
        ? 'Bearer error="invalid_token"'
        : 'Bearer';
  }
  if ((status === 429 || status === 503) && err.retryAfterMs !== undefined) {
    headers['retry-after'] = String(Math.max(1, Math.ceil(err.retryAfterMs / 1000)));
  }
  const body: ErrorBody = {
    error: {
      code: err.code,
      message: err.message,
      retryable: err.retryable,
      ...(status < 500 && err.details !== undefined ? { details: err.details } : {}),
    },
  };
  return { status, headers, body };
}

/** Writes an error response. */
export function sendError(res: Response, e: unknown): void {
  const { status, headers, body } = errorResponse(e);
  res.status(status).set(headers).json(body);
}
