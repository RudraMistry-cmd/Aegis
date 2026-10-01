// Implements spec/storage/interfaces.md §1 and §11 for the in-memory reference adapter:
// tables, atomicity simulation, and snapshot/rollback for UnitOfWork.
//
// ATOMICITY MODEL (limitation, see docs/CONFORMANCE.md):
// Node runs this adapter on a single thread. Every store method below performs its whole
// read-modify-write synchronously (it never awaits mid-operation), which gives the A1
// (linearizable single-record) guarantee of §1.2 for free: two concurrent callers can never
// interleave inside one operation. A2 (atomic group) is provided by `MemoryUnitOfWork`, which
// serializes transactions with a mutex and restores a deep snapshot on failure. This is a faithful
// simulation for a single process only; it cannot model multi-process contention.
import type {
  Credential,
  Identifier,
  Id,
  RefreshTokenRecord,
  RoleAssignment,
  Session,
  User,
} from '../../domain/index.js';

/** Key for the assignment table: identity is (subjectId, roleName, scope) (assignments.md §1.1). */
export function assignmentKey(
  subjectId: Id,
  roleName: string,
  scope: RoleAssignment['scope'],
): string {
  const s = scope === undefined || scope === null ? '-' : `${scope.type}:${scope.id}`;
  return `${subjectId}\u0000${roleName}\u0000${s}`;
}

/** All tables of the in-memory adapter. */
export interface Tables {
  users: Map<Id, User>;
  identifiers: Map<Id, Identifier>;
  /** Keyed by `${type}\0${normalized}` for the unique index of identifiers.md §3.1. */
  identifierIndex: Map<string, Id>;
  credentials: Map<Id, Credential>;
  sessions: Map<Id, Session>;
  refreshTokens: Map<Id, RefreshTokenRecord>;
  /** Unique index on the token digest (tokens.md §3.2). */
  refreshTokenIndex: Map<string, Id>;
  assignments: Map<string, RoleAssignment>;
  catalogVersion: string | null;
}

function emptyTables(): Tables {
  return {
    users: new Map(),
    identifiers: new Map(),
    identifierIndex: new Map(),
    credentials: new Map(),
    sessions: new Map(),
    refreshTokens: new Map(),
    refreshTokenIndex: new Map(),
    assignments: new Map(),
    catalogVersion: null,
  };
}

/** The mutable store state. Stores hold a reference to this object, never to the maps. */
export class MemoryDatabase {
  tables: Tables = emptyTables();

  /** Deep snapshot for transaction rollback (§11.2). */
  snapshot(): Tables {
    const t = this.tables;
    return {
      users: new Map(t.users),
      identifiers: new Map(t.identifiers),
      identifierIndex: new Map(t.identifierIndex),
      credentials: new Map(t.credentials),
      sessions: new Map(t.sessions),
      refreshTokens: new Map(t.refreshTokens),
      refreshTokenIndex: new Map(t.refreshTokenIndex),
      assignments: new Map(t.assignments),
      catalogVersion: t.catalogVersion,
    };
  }

  restore(snapshot: Tables): void {
    this.tables = snapshot;
  }

  reset(): void {
    this.tables = emptyTables();
  }
}

/**
 * Promise-chain mutex. Used to serialize units of work so a transaction observes no interleaving
 * (the serializable isolation of §11.3).
 */
export class Mutex {
  private tail: Promise<void> = Promise.resolve();

  async run<T>(fn: () => Promise<T>): Promise<T> {
    const previous = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await fn();
    } finally {
      release();
    }
  }
}
