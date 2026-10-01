// Implements spec/errors.md: error model, fixed messages, and internal->external code mapping.

/** All error codes defined by spec/errors.md §2. No other codes may be used. */
export const ERROR_CODES = [
  'VALIDATION_FAILED',
  'INVALID_CREDENTIALS',
  'ACCOUNT_RESTRICTED',
  'RATE_LIMITED',
  'UNAUTHENTICATED',
  'TOKEN_INVALID',
  'TOKEN_EXPIRED',
  'FORBIDDEN',
  'ESCALATION_DENIED',
  'SESSION_LIMIT_REACHED',
  'NOT_FOUND',
  'CONFLICT',
  'PRECONDITION_FAILED',
  'STATE_TRANSITION_INVALID',
  'CONFIG_INVALID',
  'STORAGE_UNAVAILABLE',
  'INTERNAL',
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

export type ErrorCategory =
  | 'validation'
  | 'authentication'
  | 'authorization'
  | 'conflict'
  | 'throttling'
  | 'configuration'
  | 'infrastructure'
  | 'internal';

interface CodeMeta {
  readonly category: ErrorCategory;
  readonly retryable: boolean;
  /** Fixed message per spec/errors.md §5. */
  readonly message: string;
  /** Whitelisted `details` keys per spec/errors.md §2. */
  readonly details: readonly string[];
}

const META: Readonly<Record<ErrorCode, CodeMeta>> = {
  VALIDATION_FAILED: {
    category: 'validation',
    retryable: false,
    message: 'The request is invalid.',
    details: ['field', 'rule'],
  },
  INVALID_CREDENTIALS: {
    category: 'authentication',
    retryable: false,
    message: 'Invalid credentials.',
    details: [],
  },
  ACCOUNT_RESTRICTED: {
    category: 'authentication',
    retryable: false,
    message: 'This account cannot perform that action.',
    details: ['state'],
  },
  RATE_LIMITED: {
    category: 'throttling',
    retryable: true,
    message: 'Too many attempts. Try again later.',
    details: ['retryAfter'],
  },
  UNAUTHENTICATED: {
    category: 'authentication',
    retryable: false,
    message: 'Authentication required.',
    details: [],
  },
  TOKEN_INVALID: {
    category: 'authentication',
    retryable: false,
    message: 'The credential is invalid.',
    details: [],
  },
  TOKEN_EXPIRED: {
    category: 'authentication',
    retryable: false,
    message: 'The credential has expired.',
    details: [],
  },
  FORBIDDEN: {
    category: 'authorization',
    retryable: false,
    message: 'You do not have permission to perform this action.',
    details: ['permission'],
  },
  ESCALATION_DENIED: {
    category: 'authorization',
    retryable: false,
    message: 'This change is not permitted.',
    details: ['rule'],
  },
  SESSION_LIMIT_REACHED: {
    category: 'authentication',
    retryable: false,
    message: 'Too many active sessions.',
    details: [],
  },
  NOT_FOUND: { category: 'validation', retryable: false, message: 'Not found.', details: [] },
  CONFLICT: {
    category: 'conflict',
    retryable: false,
    message: 'The request conflicts with existing data.',
    details: ['field'],
  },
  PRECONDITION_FAILED: {
    category: 'conflict',
    retryable: true,
    message: 'The resource was modified; reload and retry.',
    details: [],
  },
  STATE_TRANSITION_INVALID: {
    category: 'validation',
    retryable: false,
    message: 'That state change is not allowed.',
    details: ['from', 'to'],
  },
  CONFIG_INVALID: {
    category: 'configuration',
    retryable: false,
    message: 'The configuration is invalid.',
    details: ['violations'],
  },
  STORAGE_UNAVAILABLE: {
    category: 'infrastructure',
    retryable: true,
    message: 'Service temporarily unavailable.',
    details: ['retryAfter'],
  },
  INTERNAL: {
    category: 'internal',
    retryable: false,
    message: 'An unexpected error occurred.',
    details: [],
  },
};

/** One violation entry of a CONFIG_INVALID error (spec/errors.md §2). */
export interface ConfigViolation {
  readonly path: string;
  readonly rule: string;
  readonly message: string;
}

export interface AuthErrorOptions {
  readonly details?: Readonly<Record<string, unknown>>;
  /** Milliseconds; surfaced as `retryAfter` detail. */
  readonly retryAfterMs?: number;
  /** Retryable override (e.g. in-flight refresh); defaults to the code's meta. */
  readonly retryable?: boolean;
  /** Internal diagnostic chain. NEVER serialized (spec/errors.md §1.4). */
  readonly cause?: unknown;
  readonly requestId?: string;
}

/**
 * The single error type crossing the public API boundary (spec/errors.md §1).
 * `message` is always the fixed text of the code; `cause` is never serialized.
 */
export class AuthError extends Error {
  readonly code: ErrorCode;
  readonly category: ErrorCategory;
  readonly retryable: boolean;
  readonly retryAfterMs?: number;
  readonly details?: Readonly<Record<string, unknown>>;
  readonly requestId?: string;
  /** Internal only. */
  readonly internalCause?: unknown;

  constructor(code: ErrorCode, options: AuthErrorOptions = {}) {
    const meta = META[code];
    super(meta.message);
    this.name = 'AuthError';
    this.code = code;
    this.category = meta.category;
    this.retryable = options.retryable ?? meta.retryable;
    if (options.retryAfterMs !== undefined) this.retryAfterMs = options.retryAfterMs;
    if (options.requestId !== undefined) this.requestId = options.requestId;
    this.internalCause = options.cause;
    const allowed = new Set(meta.details);
    const details: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(options.details ?? {})) {
      if (allowed.has(k)) details[k] = v;
    }
    if (options.retryAfterMs !== undefined && allowed.has('retryAfter')) {
      details['retryAfter'] = options.retryAfterMs;
    }
    if (Object.keys(details).length > 0) this.details = Object.freeze(details);
  }

  /** Safe serialization: omits `cause` and the stack. */
  toJSON(): Record<string, unknown> {
    return {
      code: this.code,
      category: this.category,
      message: this.message,
      retryable: this.retryable,
      ...(this.details ? { details: this.details } : {}),
      ...(this.requestId ? { requestId: this.requestId } : {}),
    };
  }
}

/** Error factory. */
export function authError(code: ErrorCode, options?: AuthErrorOptions): AuthError {
  return new AuthError(code, options);
}

export function configInvalid(violations: readonly ConfigViolation[]): AuthError {
  return new AuthError('CONFIG_INVALID', { details: { violations: [...violations] } });
}

export function isAuthError(e: unknown): e is AuthError {
  return e instanceof AuthError;
}

/**
 * Wraps any unexpected throwable as INTERNAL (spec/errors.md §4.3) while
 * passing AuthErrors through unchanged. The original is kept as internal cause.
 */
export function toAuthError(e: unknown): AuthError {
  return isAuthError(e) ? e : new AuthError('INTERNAL', { cause: e });
}

/** Wraps non-AuthError failures from infrastructure ports as STORAGE_UNAVAILABLE. */
export function toInfraError(e: unknown): AuthError {
  return isAuthError(e) ? e : new AuthError('STORAGE_UNAVAILABLE', { cause: e });
}

/**
 * Internal reasons mapped to external codes (spec/errors.md §3).
 * `null` means "not an error": `resolve` yields an absent Principal instead.
 */
export const INTERNAL_REASON_TO_CODE = {
  'refresh.unknown': 'TOKEN_INVALID',
  'refresh.revoked': 'TOKEN_INVALID',
  'refresh.reused': 'TOKEN_INVALID',
  'refresh.superseded': 'TOKEN_INVALID',
  'refresh.session_missing': 'TOKEN_INVALID',
  'refresh.user_deleted': 'TOKEN_INVALID',
  'refresh.sv_mismatch': 'TOKEN_INVALID',
  'refresh.integrity_failure': 'TOKEN_INVALID',
  'refresh.expired': 'TOKEN_EXPIRED',
  'refresh.can_refresh_false': 'ACCOUNT_RESTRICTED',
  'access.malformed': 'TOKEN_INVALID',
  'access.bad_signature': 'TOKEN_INVALID',
  'access.unknown_key': 'TOKEN_INVALID',
  'access.wrong_issuer': 'TOKEN_INVALID',
  'access.wrong_audience': 'TOKEN_INVALID',
  'access.wrong_type': 'TOKEN_INVALID',
  'access.unsupported_algorithm': 'TOKEN_INVALID',
  'access.not_yet_valid': 'TOKEN_INVALID',
  'access.expired': 'TOKEN_EXPIRED',
  'resolve.rejected': null,
  'login.unknown_identifier': 'INVALID_CREDENTIALS',
  'login.malformed_identifier': 'INVALID_CREDENTIALS',
  'login.wrong_password': 'INVALID_CREDENTIALS',
  'login.no_credential': 'INVALID_CREDENTIALS',
  'login.oversize_password': 'INVALID_CREDENTIALS',
  'onetime.invalid': 'TOKEN_INVALID',
  'authz.deny': 'FORBIDDEN',
  'authz.policy_error': 'FORBIDDEN',
  'adapter.conflict': 'CONFLICT',
  'adapter.precondition_failed': 'PRECONDITION_FAILED',
  'adapter.unavailable': 'STORAGE_UNAVAILABLE',
  'adapter.invalid': 'VALIDATION_FAILED',
} as const satisfies Record<string, ErrorCode | null>;

export type InternalReason = keyof typeof INTERNAL_REASON_TO_CODE;

/** Maps an internal reason to its external error code (or null when no error is raised). */
export function externalCodeFor(reason: InternalReason): ErrorCode | null {
  return INTERNAL_REASON_TO_CODE[reason];
}

/** The fixed message for a code (spec/errors.md §5). */
export function messageFor(code: ErrorCode): string {
  return META[code].message;
}
