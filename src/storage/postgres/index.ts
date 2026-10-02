// The PostgreSQL storage adapter (spec/storage/interfaces.md §12 profile A-FULL).
//
// Published as the `aegis-core/postgres` subpath so the core package stays free of runtime
// dependencies: only applications that use this adapter need the `pg` driver installed.
import type { Timestamp } from '../../domain/index.js';
import { CryptoIdGenerator } from '../../ports/defaults.js';
import type { IdGenerator, Storage, StoreSet } from '../../ports/index.js';
import { PostgresAssignmentStore } from './assignmentStore.js';
import {
  PostgresCredentialStore,
  PostgresIdentifierStore,
  PostgresUserStore,
} from './identityStores.js';
import { migrate } from './migrate.js';
import { PostgresClient, type PostgresConfig } from './postgresClient.js';
import { PostgresRefreshTokenStore } from './refreshTokenStore.js';
import { PostgresRoleCatalogStore } from './roleStore.js';
import { PostgresSessionStore } from './sessionStore.js';
import { PostgresUnitOfWork, TransactionRunner } from './unitOfWork.js';

export interface PostgresStorage extends Storage {
  readonly client: PostgresClient;
  readonly runner: TransactionRunner;
  /** Applies pending migrations from `migrations/`. Safe to call on every start. */
  migrate(dir?: string): Promise<string[]>;
  /**
   * Deletes sessions (and, by cascade, their refresh tokens) that became terminal before `cutoff`.
   *
   * Never required for correctness: every query evaluates expiry against the caller's `now`, so an
   * expired row is already unusable. Choose `cutoff` no later than `now - retention`, where
   * retention is at least `max(accessTtl, reuseGrace) + 24h` (session.md §8.1), so reuse detection
   * and audit stay possible for recently ended sessions.
   */
  housekeep(cutoff: Timestamp): Promise<number>;
  /** Closes the pool. */
  close(): Promise<void>;
}

export interface CreatePostgresStorageOptions extends PostgresConfig {
  /** Generator for store-assigned ids (identifiers, credentials). Defaults to UUIDv4. */
  readonly ids?: IdGenerator;
}

/** Creates the PostgreSQL storage adapter. Call `migrate()` before first use. */
export function createPostgresStorage(options: CreatePostgresStorageOptions): PostgresStorage {
  const client = new PostgresClient(options);
  const runner = new TransactionRunner(client);
  const ids = options.ids ?? new CryptoIdGenerator();
  const stores: StoreSet = {
    users: new PostgresUserStore(client, runner),
    identifiers: new PostgresIdentifierStore(client, ids),
    credentials: new PostgresCredentialStore(client, ids),
    sessions: new PostgresSessionStore(client, runner),
    refreshTokens: new PostgresRefreshTokenStore(client, runner),
    assignments: new PostgresAssignmentStore(client, runner),
    roles: new PostgresRoleCatalogStore(client, runner),
  };
  return {
    ...stores,
    uow: new PostgresUnitOfWork(runner, stores),
    client,
    runner,
    migrate: (dir?: string) => migrate(client, dir),
    housekeep: async (cutoff: Timestamp) => {
      const r = await client.query(
        `DELETE FROM aegis.sessions
          WHERE (revoked_at_ms IS NOT NULL AND revoked_at_ms < $1)
             OR (revoked_at_ms IS NULL AND least(idle_expires_at_ms, absolute_expires_at_ms) < $1)`,
        [cutoff],
      );
      return r.rowCount;
    },
    close: () => client.end(),
  };
}

export { PostgresAuditSink, type PostgresAuditSinkOptions } from './auditSink.js';
export { isRetryable, mapPgError } from './errors.js';
export { defaultMigrationsDir, migrate } from './migrate.js';
export { PostgresClient, type PostgresConfig } from './postgresClient.js';
export { PostgresUnitOfWork, TransactionRunner } from './unitOfWork.js';
