// Implements spec/storage/interfaces.md §2-§4 in memory: UserStore, IdentifierStore, CredentialStore.
import { authError } from '../../errors/index.js';
import type {
  Credential,
  Identifier,
  Id,
  Json,
  NewUser,
  Timestamp,
  User,
} from '../../domain/index.js';
import type {
  CredentialStore,
  IdGenerator,
  IdentifierStore,
  UserStore,
} from '../../ports/index.js';
import type { MemoryDatabase } from './database.js';

function indexKey(type: string, normalized: string): string {
  return `${type}\u0000${normalized}`;
}

/** §2 UserStore. */
export class MemoryUserStore implements UserStore {
  constructor(
    private readonly db: MemoryDatabase,
    private readonly ids: IdGenerator,
  ) {}

  async create(user: NewUser): Promise<User> {
    const t = this.db.tables;
    if (t.users.has(user.id)) {
      throw authError('CONFLICT', { details: { field: 'id' } });
    }
    // §2.1: the adapter ignores caller-supplied version/securityVersion; both start at 0.
    const row: User = {
      id: user.id,
      status: user.status,
      version: 0,
      securityVersion: 0,
      createdAt: user.createdAt,
      updatedAt: user.createdAt,
      metadata: Object.freeze(structuredClone(user.metadata)),
    };
    t.users.set(row.id, row);
    return row;
  }

  async getById(id: Id): Promise<User | null> {
    return this.db.tables.users.get(id) ?? null;
  }

  async setStatus(id: Id, to: string, expectedVersion: number, now: Timestamp): Promise<User> {
    const t = this.db.tables;
    const current = t.users.get(id);
    if (!current) throw authError('NOT_FOUND');
    // §2.2: the store enforces only the version check; transition validity is the core's job.
    if (current.version !== expectedVersion) throw authError('PRECONDITION_FAILED');
    const next: User = { ...current, status: to, version: current.version + 1, updatedAt: now };
    t.users.set(id, next);
    return next;
  }

  async bumpSecurityVersion(id: Id, now: Timestamp): Promise<number> {
    const t = this.db.tables;
    const current = t.users.get(id);
    if (!current) throw authError('NOT_FOUND');
    const next: User = {
      ...current,
      securityVersion: current.securityVersion + 1,
      version: current.version + 1,
      updatedAt: now,
    };
    t.users.set(id, next);
    return next.securityVersion;
  }

  async updateMetadata(
    id: Id,
    patch: Record<string, Json>,
    expectedVersion: number | undefined,
    now: Timestamp,
  ): Promise<User> {
    const t = this.db.tables;
    const current = t.users.get(id);
    if (!current) throw authError('NOT_FOUND');
    if (expectedVersion !== undefined && current.version !== expectedVersion) {
      throw authError('PRECONDITION_FAILED');
    }
    const next: User = {
      ...current,
      metadata: Object.freeze({ ...current.metadata, ...structuredClone(patch) }),
      version: current.version + 1,
      updatedAt: now,
    };
    t.users.set(id, next);
    return next;
  }

  /**
   * §2.6: cascade delete of identifiers, credentials, sessions, refresh tokens and assignments.
   * Non-reuse of the id (INV-ID-01) rests on the IdGenerator never repeating a value; this adapter
   * keeps no tombstones, so a caller that supplies a previously used id explicitly would succeed.
   */
  async delete(id: Id): Promise<void> {
    const t = this.db.tables;
    t.users.delete(id);
    for (const [k, row] of [...t.identifiers]) {
      if (row.userId === id) {
        t.identifiers.delete(k);
        t.identifierIndex.delete(indexKey(row.type, row.normalized));
      }
    }
    for (const [k, row] of [...t.credentials]) if (row.userId === id) t.credentials.delete(k);
    for (const [k, row] of [...t.sessions]) if (row.userId === id) t.sessions.delete(k);
    for (const [k, row] of [...t.refreshTokens]) {
      if (row.userId === id) {
        t.refreshTokens.delete(k);
        t.refreshTokenIndex.delete(row.hash);
      }
    }
    for (const [k, row] of [...t.assignments]) if (row.subjectId === id) t.assignments.delete(k);
    void this.ids;
  }
}

/** §3 IdentifierStore. */
export class MemoryIdentifierStore implements IdentifierStore {
  constructor(
    private readonly db: MemoryDatabase,
    private readonly ids: IdGenerator,
  ) {}

  async add(
    userId: Id,
    type: string,
    value: string,
    normalized: string,
    verified: boolean,
    now: Timestamp,
  ): Promise<Identifier> {
    const t = this.db.tables;
    if (!t.users.has(userId)) throw authError('NOT_FOUND');
    const key = indexKey(type, normalized);
    // §3.1: uniqueness enforced by the store, not by a check-then-insert in the core.
    if (t.identifierIndex.has(key))
      throw authError('CONFLICT', { details: { field: 'identifier' } });
    const row: Identifier = {
      id: this.ids.newId(),
      userId,
      type,
      value,
      normalized,
      verified,
      createdAt: now,
    };
    t.identifiers.set(row.id, row);
    t.identifierIndex.set(key, row.id);
    return row;
  }

  async findByNormalized(type: string, normalized: string): Promise<Identifier | null> {
    const t = this.db.tables;
    const id = t.identifierIndex.get(indexKey(type, normalized));
    return id ? (t.identifiers.get(id) ?? null) : null;
  }

  async listByUser(userId: Id): Promise<readonly Identifier[]> {
    return [...this.db.tables.identifiers.values()].filter((i) => i.userId === userId);
  }

  async markVerified(identifierId: Id, now: Timestamp): Promise<void> {
    const t = this.db.tables;
    const row = t.identifiers.get(identifierId);
    if (!row) throw authError('NOT_FOUND');
    if (row.verified) return; // idempotent
    t.identifiers.set(identifierId, { ...row, verified: true, createdAt: row.createdAt });
    void now;
  }

  async remove(identifierId: Id): Promise<void> {
    const t = this.db.tables;
    const row = t.identifiers.get(identifierId);
    if (!row) return; // idempotent
    t.identifiers.delete(identifierId);
    t.identifierIndex.delete(indexKey(row.type, row.normalized));
  }
}

/** §4 CredentialStore. The only port that returns credential payloads. */
export class MemoryCredentialStore implements CredentialStore {
  constructor(
    private readonly db: MemoryDatabase,
    private readonly ids: IdGenerator,
  ) {}

  private find(userId: Id, type: string): Credential | undefined {
    for (const row of this.db.tables.credentials.values()) {
      if (row.userId === userId && row.type === type) return row;
    }
    return undefined;
  }

  async get(userId: Id, type: string): Promise<Credential | null> {
    return this.find(userId, type) ?? null;
  }

  /** §4.1: replacement is atomic — readers never see zero or two credentials of a type. */
  async put(userId: Id, type: string, payload: string, now: Timestamp): Promise<Credential> {
    const t = this.db.tables;
    const existing = this.find(userId, type);
    const row: Credential = {
      id: existing?.id ?? this.ids.newId(),
      userId,
      type,
      payload,
      createdAt: existing?.createdAt ?? now,
    };
    t.credentials.set(row.id, row);
    return row;
  }

  async touch(credentialId: Id, at: Timestamp): Promise<void> {
    const t = this.db.tables;
    const row = t.credentials.get(credentialId);
    if (!row) return;
    t.credentials.set(credentialId, { ...row, lastUsedAt: at });
  }

  async delete(userId: Id, type: string): Promise<void> {
    const existing = this.find(userId, type);
    if (existing) this.db.tables.credentials.delete(existing.id);
  }
}
