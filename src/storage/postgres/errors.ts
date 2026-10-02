// Implements spec/storage/interfaces.md §1.1 for PostgreSQL: driver errors never cross the port
// boundary; each is mapped to one of the five adapter failures, which spec/errors.md §3 maps to an
// external code. The original error is kept only as the internal cause (errors.md §1.4).
import { AuthError, authError, isAuthError } from '../../errors/index.js';

/** SQLSTATEs on which a whole transaction may safely be re-run: the server aborted it. */
export const RETRYABLE_SQLSTATES: ReadonlySet<string> = new Set([
  '40001', // serialization_failure
  '40P01', // deadlock_detected
]);

/** Shape of an error thrown by node-postgres (`DatabaseError`) or by the socket layer. */
interface DriverError {
  readonly code?: unknown;
  readonly constraint?: unknown;
}

function sqlState(e: unknown): string | undefined {
  const code = (e as DriverError | null)?.code;
  return typeof code === 'string' ? code : undefined;
}

/** The SQLSTATE behind an error, whether raw or already wrapped by `mapPgError`. */
export function underlyingSqlState(e: unknown): string | undefined {
  if (isAuthError(e)) return sqlState(e.internalCause);
  return sqlState(e);
}

/** True when the transaction was aborted by the server and can be retried from the start. */
export function isRetryable(e: unknown): boolean {
  const state = underlyingSqlState(e);
  return state !== undefined && RETRYABLE_SQLSTATES.has(state);
}

/** Maps a constraint name to the `field` detail allowed by errors.md §2 for CONFLICT. */
function conflictField(constraint: string | undefined): string {
  switch (constraint) {
    case 'identifiers_type_normalized_key':
      return 'identifier';
    case 'refresh_tokens_hash_key':
      return 'hash';
    case 'credentials_user_type_key':
      return 'credential';
    default:
      return 'id';
  }
}

/**
 * Maps any error raised while talking to PostgreSQL.
 *
 * | SQLSTATE            | Meaning                         | Adapter failure    | Code                |
 * |---------------------|---------------------------------|--------------------|---------------------|
 * | 23505               | unique_violation                | Conflict           | CONFLICT            |
 * | 23503               | foreign_key_violation           | NotFound           | NOT_FOUND           |
 * | 23502 23514 22xxx   | not null / check / data         | Invalid            | VALIDATION_FAILED   |
 * | AE0xx               | Aegis integrity trigger         | (defect)           | INTERNAL            |
 * | 40001 40P01         | serialization / deadlock        | Unavailable*       | STORAGE_UNAVAILABLE |
 * | 55P03 57014         | lock / statement timeout        | Unavailable        | STORAGE_UNAVAILABLE |
 * | 08xxx 53xxx 57Pxx   | connection / resources / shutdown | Unavailable      | STORAGE_UNAVAILABLE |
 * | 25P02               | statement in an aborted txn     | Unavailable        | STORAGE_UNAVAILABLE |
 * | anything else       | unknown — state unknown         | Unavailable        | STORAGE_UNAVAILABLE |
 *
 * (*) 40001/40P01 are retried by the transaction runner first; they surface only once retries
 * are exhausted. Unknown errors map to "unavailable", never to success, so the core fails closed
 * (spec §1.1.2: after Unavailable the outcome must be treated as unknown).
 */
export function mapPgError(e: unknown): AuthError {
  if (isAuthError(e)) return e;
  const state = sqlState(e);
  const constraint = (e as DriverError | null)?.constraint;

  if (state === '23505') {
    return authError('CONFLICT', {
      details: { field: conflictField(typeof constraint === 'string' ? constraint : undefined) },
      cause: e,
    });
  }
  if (state === '23503') return authError('NOT_FOUND', { cause: e });
  if (state === '23502' || state === '23514' || state?.startsWith('22')) {
    return authError('VALIDATION_FAILED', { details: { rule: 'storage.constraint' }, cause: e });
  }
  if (state?.startsWith('AE')) {
    // An integrity trigger fired: application code attempted to break an invariant.
    return authError('INTERNAL', { cause: e });
  }
  return authError('STORAGE_UNAVAILABLE', { cause: e });
}
