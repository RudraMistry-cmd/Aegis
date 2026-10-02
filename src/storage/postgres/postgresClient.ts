// Implements spec/storage/interfaces.md §1 and §11 for PostgreSQL: the connection pool, query
// routing to the ambient transaction, row decoding, and the per-statement safety settings.
//
// AMBIENT TRANSACTION ROUTING
// While a unit of work runs, every store call made in its async context — including calls made
// through the *non-transactional* store handles — executes on that unit's connection, inside its
// transaction. This is what the in-memory reference adapter does implicitly (one database), and it
// matters on a real server for two reasons:
//   1. Correctness. A guard that reads through a non-transactional handle (for example the grant
//      ceiling, which resolves the actor's roles) must see the same snapshot and the same locks as
//      the write it protects, or the check-then-write becomes a time-of-check/time-of-use race.
//   2. Liveness. A second connection opened from inside a transaction can block forever on a row
//      lock that its own transaction holds, while also pinning a pool slot.
import { AsyncLocalStorage } from 'node:async_hooks';
import pg from 'pg';
import { authError } from '../../errors/index.js';
import { mapPgError } from './errors.js';

/** Connection and safety settings. */
export interface PostgresConfig {
  /** A libpq connection string, e.g. `postgres://user:pass@host:5432/db`. */
  readonly connectionString: string;
  /** Pool size. Each unit of work holds exactly one connection. Default 10. */
  readonly maxConnections?: number;
  /**
   * Transaction isolation for every unit of work and every multi-statement store operation.
   * Default `read committed`; see docs/POSTGRES.md "Isolation level choice" for why.
   */
  readonly isolation?: 'read committed' | 'serializable';
  /** spec §1.1.3: no operation may block indefinitely. Default 10 000 ms. */
  readonly statementTimeoutMs?: number;
  /** Maximum wait for a row lock before failing with STORAGE_UNAVAILABLE. Default 5 000 ms. */
  readonly lockTimeoutMs?: number;
  /** Attempts for a transaction aborted by a serialization failure or deadlock. Default 10. */
  readonly maxTransactionAttempts?: number;
}

/** A transaction in progress, bound to one pooled connection. */
export interface TxContext {
  readonly client: pg.PoolClient;
  /** Set once the transaction has committed or rolled back; later queries are a defect. */
  finished: boolean;
  /**
   * The first statement failure in the transaction (raw driver error). PostgreSQL then aborts the
   * transaction and silently turns a later COMMIT into a ROLLBACK, so the runner must refuse to
   * report success.
   */
  failed: unknown;
}

export interface QueryResult<R> {
  readonly rows: R[];
  readonly rowCount: number;
}

/** BIGINT (oid 20) as a JS number, refusing values that would lose precision. */
function parseBigint(value: string): number {
  const n = Number(value);
  if (!Number.isSafeInteger(n)) throw new RangeError(`aegis: bigint ${value} exceeds 2^53`);
  return n;
}

const BIGINT_OID = 20;

export class PostgresClient {
  readonly pool: pg.Pool;
  readonly isolation: 'read committed' | 'serializable';
  readonly maxTransactionAttempts: number;
  private readonly ambientTx = new AsyncLocalStorage<TxContext>();

  constructor(config: PostgresConfig) {
    this.isolation = config.isolation ?? 'read committed';
    this.maxTransactionAttempts = config.maxTransactionAttempts ?? 10;
    this.pool = new pg.Pool({
      connectionString: config.connectionString,
      max: config.maxConnections ?? 10,
      application_name: 'aegis',
      statement_timeout: config.statementTimeoutMs ?? 10_000,
      lock_timeout: config.lockTimeoutMs ?? 5_000,
      idle_in_transaction_session_timeout: 30_000,
      // Per-pool type parsing; never mutate the process-global pg.types registry.
      types: {
        getTypeParser: ((oid: number, format?: string) =>
          oid === BIGINT_OID && format !== 'binary'
            ? parseBigint
            : pg.types.getTypeParser(oid, format as 'text')) as typeof pg.types.getTypeParser,
      },
    });
    // An idle client erroring (e.g. server restart) must not crash the process; the next query
    // on a fresh client reports STORAGE_UNAVAILABLE instead.
    this.pool.on('error', () => undefined);
  }

  /** The transaction of the current async context, if any. */
  ambient(): TxContext | undefined {
    return this.ambientTx.getStore();
  }

  /** Runs `fn` with `ctx` as the ambient transaction. */
  withTransaction<T>(ctx: TxContext, fn: () => Promise<T>): Promise<T> {
    return this.ambientTx.run(ctx, fn);
  }

  /**
   * Executes one statement: on the ambient transaction's connection when there is one, otherwise
   * as a single auto-committed statement. Values are always bound parameters, never interpolated.
   */
  async query<R extends object = Record<string, unknown>>(
    text: string,
    values: readonly unknown[] = [],
  ): Promise<QueryResult<R>> {
    const ctx = this.ambient();
    if (ctx) {
      if (ctx.finished) {
        // A promise started inside a unit outlived it. Using the released connection would run the
        // statement in some other caller's transaction.
        throw authError('INTERNAL');
      }
      try {
        const r = await ctx.client.query<R>(text, values as unknown[]);
        return { rows: r.rows, rowCount: r.rowCount ?? 0 };
      } catch (e) {
        // Keep the FIRST failure: after it, PostgreSQL rejects every further statement in the
        // transaction with 25P02 ("transaction is aborted"), which would hide the real cause.
        if (ctx.failed === undefined) ctx.failed = e;
        throw mapPgError(e);
      }
    }
    try {
      const r = await this.pool.query<R>(text, values as unknown[]);
      return { rows: r.rows, rowCount: r.rowCount ?? 0 };
    } catch (e) {
      throw mapPgError(e);
    }
  }

  /** Acquires a dedicated connection (used by the transaction runner). */
  async connect(): Promise<pg.PoolClient> {
    try {
      return await this.pool.connect();
    } catch (e) {
      throw mapPgError(e);
    }
  }

  async end(): Promise<void> {
    await this.pool.end();
  }
}

// ---------------------------------------------------------------- row decoding helpers

/** Omits a property whose value is null, matching the optional fields of the domain types. */
export function optional<K extends string, V>(
  key: K,
  value: V | null | undefined,
): { [P in K]?: V } {
  return (value === null || value === undefined ? {} : { [key]: value }) as { [P in K]?: V };
}
