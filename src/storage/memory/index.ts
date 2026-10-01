// Implements spec/storage/interfaces.md §11-§12: the in-memory reference adapter and its UnitOfWork.
import { AsyncLocalStorage } from 'node:async_hooks';
import { CryptoIdGenerator } from '../../ports/defaults.js';
import type { IdGenerator, Storage, StoreSet, UnitOfWork } from '../../ports/index.js';
import { MemoryDatabase, Mutex } from './database.js';
import { MemoryAssignmentStore, MemoryRoleCatalogStore } from './assignmentStore.js';
import { MemoryCredentialStore, MemoryIdentifierStore, MemoryUserStore } from './identityStores.js';
import { MemoryRefreshTokenStore } from './refreshTokenStore.js';
import { MemorySessionStore } from './sessionStore.js';

/**
 * §11 UnitOfWork for the in-memory adapter.
 *
 * LIMITATIONS (documented per the Phase 1 brief and docs/CONFORMANCE.md):
 * - Isolation is achieved by *serializing* transactions with a mutex, which is stricter than
 *   serializable isolation and therefore satisfies §11.3, but it is single-process only.
 * - Rollback restores a deep snapshot of the tables taken before `fn` ran. Because transactions are
 *   serialized, no concurrent writer can be lost by that restore.
 * - `fn` must contain no external side effects (§11.4); the core performs notifications, hashing
 *   and audit emission outside the unit.
 * - Nesting is detected per async context (§11.5). A transaction started from *within* another
 *   joins it; an unrelated concurrent transaction must not, or a rollback in one would discard the
 *   other's writes.
 */
export class MemoryUnitOfWork implements UnitOfWork {
  private readonly active = new AsyncLocalStorage<true>();

  constructor(
    private readonly db: MemoryDatabase,
    private readonly stores: StoreSet,
    private readonly mutex: Mutex,
  ) {}

  async run<T>(fn: (tx: StoreSet) => Promise<T>): Promise<T> {
    // §11.5: a nested run joins the outer transaction instead of starting a new one.
    if (this.active.getStore() === true) return fn(this.stores);
    return this.mutex.run(async () => {
      const snapshot = this.db.snapshot();
      try {
        return await this.active.run(true, () => fn(this.stores));
      } catch (e) {
        this.db.restore(snapshot);
        throw e;
      }
    });
  }
}

/** The in-memory storage bundle, plus test helpers. */
export interface MemoryStorage extends Storage {
  readonly db: MemoryDatabase;
  /** Clears every table. Test helper only. */
  reset(): void;
}

/**
 * Creates the in-memory reference storage adapter (profile A-FULL for a single process).
 * @param ids Identifier generator for store-assigned ids; defaults to UUIDv4.
 */
export function createMemoryStorage(ids: IdGenerator = new CryptoIdGenerator()): MemoryStorage {
  const db = new MemoryDatabase();
  const mutex = new Mutex();
  const stores: StoreSet = {
    users: new MemoryUserStore(db, ids),
    identifiers: new MemoryIdentifierStore(db, ids),
    credentials: new MemoryCredentialStore(db, ids),
    sessions: new MemorySessionStore(db),
    refreshTokens: new MemoryRefreshTokenStore(db),
    assignments: new MemoryAssignmentStore(db),
    roles: new MemoryRoleCatalogStore(db),
  };
  const uow = new MemoryUnitOfWork(db, stores, mutex);
  return {
    ...stores,
    uow,
    db,
    reset: () => db.reset(),
  };
}

export { MemoryDatabase, Mutex } from './database.js';
export { MemoryAssignmentStore, MemoryRoleCatalogStore } from './assignmentStore.js';
export { MemoryCredentialStore, MemoryIdentifierStore, MemoryUserStore } from './identityStores.js';
export { MemoryRefreshTokenStore } from './refreshTokenStore.js';
export { MemorySessionStore } from './sessionStore.js';
