// Implements spec/storage/interfaces.md §11 for PostgreSQL: UnitOfWork backed by a real
// transaction, with nested-join semantics, abort detection and bounded retry.
//
// ISOLATION
//   Default READ COMMITTED + explicit row locks taken in one global order (see locks.ts), or
//   SERIALIZABLE when configured. docs/POSTGRES.md explains the choice.
// RETRY
//   A transaction is re-run from the start only when the server reports that it aborted it:
//   serialization_failure (40001) or deadlock_detected (40P01). Those guarantee nothing committed,
//   so re-running `fn` cannot apply anything twice. Connection errors are never retried: a lost
//   connection during COMMIT leaves the outcome unknown, and spec §1.1.2 requires the caller to
//   treat it as failed (STORAGE_UNAVAILABLE) rather than guess.
//   Backoff is exponential with full jitter (5 ms base, 250 ms cap), up to `maxTransactionAttempts`.
// SIDE EFFECTS
//   §11.4: `fn` may be executed more than once, so it must contain storage work only. The core
//   emits audit events, notifications and hashes outside units.
import type pg from 'pg';
import { authError, isAuthError } from '../../errors/index.js';
import type { StoreSet, UnitOfWork } from '../../ports/index.js';
import { isRetryable, mapPgError } from './errors.js';
import type { PostgresClient, TxContext } from './postgresClient.js';

const BACKOFF_BASE_MS = 5;
const BACKOFF_CAP_MS = 250;

function backoff(attempt: number): Promise<void> {
  const ceiling = Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2 ** attempt);
  const delay = Math.random() * ceiling; // full jitter; not security-relevant randomness
  return new Promise((resolve) => setTimeout(resolve, delay));
}

/** True when the failure suggests the socket itself is unusable and must not return to the pool. */
function isConnectionFailure(e: unknown): boolean {
  const code = (e as { code?: unknown } | null)?.code;
  return typeof code !== 'string' || code.startsWith('08') || code.startsWith('57P');
}

/** Executes functions inside PostgreSQL transactions. */
export class TransactionRunner {
  /** Number of re-executions caused by retryable aborts (observable for tests and metrics). */
  retries = 0;

  constructor(private readonly pg: PostgresClient) {}

  /**
   * Runs `fn` atomically. If a transaction is already active in this async context, `fn` joins it
   * (§11.5) and the outermost transaction decides commit, rollback and retry.
   */
  async atomic<T>(fn: () => Promise<T>): Promise<T> {
    if (this.pg.ambient()) return fn();
    for (let attempt = 1; ; attempt++) {
      try {
        return await this.attempt(fn);
      } catch (e) {
        if (isRetryable(e) && attempt < this.pg.maxTransactionAttempts) {
          this.retries += 1;
          await backoff(attempt);
          continue;
        }
        // Database errors were mapped where they arose; anything else was thrown by `fn` itself
        // and propagates unchanged — a domain error must never be disguised as an outage.
        throw e;
      }
    }
  }

  /**
   * One transaction attempt on one connection.
   *
   * Errors thrown by `fn` are rethrown unchanged after ROLLBACK (database errors inside `fn` were
   * already mapped by the client, keeping the driver error as internal cause). Errors from
   * BEGIN/COMMIT, and a failure `fn` swallowed, are mapped here. `isRetryable` sees the underlying
   * SQLSTATE either way.
   */
  private async attempt<T>(fn: () => Promise<T>): Promise<T> {
    const client = await this.pg.connect();
    const ctx: TxContext = { client, finished: false, failed: undefined };
    let discard = false;
    try {
      await this.raw(
        client,
        this.pg.isolation === 'serializable'
          ? 'BEGIN ISOLATION LEVEL SERIALIZABLE'
          : 'BEGIN ISOLATION LEVEL READ COMMITTED',
      );
      let result: T;
      try {
        result = await this.pg.withTransaction(ctx, fn);
      } catch (e) {
        discard = !(await this.rollback(client));
        throw e;
      }
      if (ctx.failed !== undefined) {
        // `fn` caught a database error and carried on. PostgreSQL has already aborted the
        // transaction and would silently turn COMMIT into ROLLBACK; refuse to report success.
        discard = !(await this.rollback(client));
        throw mapPgError(ctx.failed);
      }
      const commit = await this.raw(client, 'COMMIT');
      if (commit.command !== 'COMMIT') {
        throw authError('STORAGE_UNAVAILABLE', {
          cause: new Error(`COMMIT returned ${commit.command}`),
        });
      }
      return result;
    } catch (e) {
      // If the socket itself failed (during BEGIN or COMMIT), the connection must not go back to
      // the pool; a failed COMMIT's outcome is unknown and is never retried.
      if (isAuthError(e) && isConnectionFailure(e.internalCause)) discard = true;
      throw e;
    } finally {
      ctx.finished = true;
      client.release(discard ? true : undefined);
    }
  }

  /** Runs a transaction-control statement, mapping a failure to an AuthError at the source. */
  private async raw(client: pg.PoolClient, sql: string): Promise<pg.QueryResult> {
    try {
      return await client.query(sql);
    } catch (e) {
      throw mapPgError(e);
    }
  }

  /** Rolls back; returns false when the connection is unusable. */
  private async rollback(client: pg.PoolClient): Promise<boolean> {
    try {
      await client.query('ROLLBACK');
      return true;
    } catch {
      return false;
    }
  }
}

/** The UnitOfWork port: `fn` receives the store set; ambient routing makes it transactional. */
export class PostgresUnitOfWork implements UnitOfWork {
  constructor(
    private readonly runner: TransactionRunner,
    private readonly stores: StoreSet,
  ) {}

  run<T>(fn: (tx: StoreSet) => Promise<T>): Promise<T> {
    return this.runner.atomic(() => fn(this.stores));
  }
}
