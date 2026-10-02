// Implements spec/storage/interfaces.md §2-§4 for PostgreSQL: UserStore, IdentifierStore,
// CredentialStore.
import type {
  Credential,
  Identifier,
  Id,
  Json,
  NewUser,
  Timestamp,
  User,
} from '../../domain/index.js';
import { authError } from '../../errors/index.js';
import type {
  CredentialStore,
  IdGenerator,
  IdentifierStore,
  UserStore,
} from '../../ports/index.js';
import { lockUserForDelete } from './locks.js';
import { optional, type PostgresClient } from './postgresClient.js';
import type { TransactionRunner } from './unitOfWork.js';

// ---------------------------------------------------------------- users

interface UserRow {
  id: string;
  status: string;
  version: number;
  security_version: number;
  created_at_ms: number;
  updated_at_ms: number;
  metadata: Record<string, Json>;
}

const USER_COLUMNS =
  'id, status, version, security_version, created_at_ms, updated_at_ms, metadata';

function toUser(r: UserRow): User {
  return {
    id: r.id,
    status: r.status,
    version: r.version,
    securityVersion: r.security_version,
    createdAt: r.created_at_ms,
    updatedAt: r.updated_at_ms,
    metadata: Object.freeze(r.metadata),
  };
}

export class PostgresUserStore implements UserStore {
  constructor(
    private readonly pg: PostgresClient,
    private readonly tx: TransactionRunner,
  ) {}

  /**
   * §2.1: version and securityVersion always start at 0. The id is first recorded in a registry
   * that is never deleted from, so a deleted user's id can never be issued again (INV-ID-01).
   */
  async create(user: NewUser): Promise<User> {
    return this.tx.atomic(async () => {
      await this.pg.query(
        'INSERT INTO aegis.user_id_registry (id, registered_at_ms) VALUES ($1, $2)',
        [user.id, user.createdAt],
      );
      const r = await this.pg.query<UserRow>(
        `INSERT INTO aegis.users (id, status, version, security_version, created_at_ms, updated_at_ms, metadata)
         VALUES ($1, $2, 0, 0, $3, $3, $4)
         RETURNING ${USER_COLUMNS}`,
        [user.id, user.status, user.createdAt, JSON.stringify(user.metadata)],
      );
      return toUser(r.rows[0] as UserRow);
    });
  }

  async getById(id: Id): Promise<User | null> {
    const r = await this.pg.query<UserRow>(
      `SELECT ${USER_COLUMNS} FROM aegis.users WHERE id = $1`,
      [id],
    );
    return r.rows[0] ? toUser(r.rows[0]) : null;
  }

  /**
   * §2.2: compare-and-set on `version` in a single UPDATE. Of two concurrent calls with the same
   * expected version, the second waits for the first's row lock, then re-evaluates its WHERE
   * clause against the committed row (READ COMMITTED) — the version no longer matches, so it
   * changes nothing and reports PRECONDITION_FAILED.
   */
  async setStatus(id: Id, to: string, expectedVersion: number, now: Timestamp): Promise<User> {
    return this.tx.atomic(async () => {
      const r = await this.pg.query<UserRow>(
        `UPDATE aegis.users SET status = $2, version = version + 1, updated_at_ms = $4
          WHERE id = $1 AND version = $3
          RETURNING ${USER_COLUMNS}`,
        [id, to, expectedVersion, now],
      );
      if (r.rows[0]) return toUser(r.rows[0]);
      return this.throwMissingOrStale(id);
    });
  }

  /** §2.3: an atomic in-place increment; concurrent bumps can never be lost. */
  async bumpSecurityVersion(id: Id, now: Timestamp): Promise<number> {
    const r = await this.pg.query<{ security_version: number }>(
      `UPDATE aegis.users
          SET security_version = security_version + 1, version = version + 1, updated_at_ms = $2
        WHERE id = $1
        RETURNING security_version`,
      [id, now],
    );
    const v = r.rows[0]?.security_version;
    if (v === undefined) throw authError('NOT_FOUND');
    return v;
  }

  async updateMetadata(
    id: Id,
    patch: Record<string, Json>,
    expectedVersion: number | undefined,
    now: Timestamp,
  ): Promise<User> {
    return this.tx.atomic(async () => {
      const r = await this.pg.query<UserRow>(
        `UPDATE aegis.users
            SET metadata = metadata || $2::jsonb, version = version + 1, updated_at_ms = $4
          WHERE id = $1 AND ($3::integer IS NULL OR version = $3)
          RETURNING ${USER_COLUMNS}`,
        [id, JSON.stringify(patch), expectedVersion ?? null, now],
      );
      if (r.rows[0]) return toUser(r.rows[0]);
      return this.throwMissingOrStale(id);
    });
  }

  /**
   * §2.6: cascade delete inside one transaction. Identifiers, credentials, sessions and refresh
   * tokens go by foreign-key cascade; assignments are keyed by subject id (not a foreign key, so
   * service subjects can hold roles too) and are deleted explicitly. The registry row stays.
   */
  async delete(id: Id): Promise<void> {
    await this.tx.atomic(async () => {
      if (!(await lockUserForDelete(this.pg, id))) return; // idempotent
      await this.pg.query('DELETE FROM aegis.role_assignments WHERE subject_id = $1', [id]);
      await this.pg.query('DELETE FROM aegis.users WHERE id = $1', [id]);
    });
  }

  private async throwMissingOrStale(id: Id): Promise<never> {
    const exists = await this.pg.query('SELECT 1 FROM aegis.users WHERE id = $1', [id]);
    throw authError(exists.rowCount === 0 ? 'NOT_FOUND' : 'PRECONDITION_FAILED');
  }
}

// ---------------------------------------------------------------- identifiers

interface IdentifierRow {
  id: string;
  user_id: string;
  type: string;
  value: string;
  normalized: string;
  verified: boolean;
  created_at_ms: number;
}

const IDENTIFIER_COLUMNS = 'id, user_id, type, value, normalized, verified, created_at_ms';

function toIdentifier(r: IdentifierRow): Identifier {
  return {
    id: r.id,
    userId: r.user_id,
    type: r.type,
    value: r.value,
    normalized: r.normalized,
    verified: r.verified,
    createdAt: r.created_at_ms,
  };
}

export class PostgresIdentifierStore implements IdentifierStore {
  constructor(
    private readonly pg: PostgresClient,
    private readonly ids: IdGenerator,
  ) {}

  /**
   * §3.1: uniqueness is enforced by the unique constraint, not by a prior lookup. Of two concurrent
   * inserts with the same (type, normalized), PostgreSQL makes the second wait for the first and
   * then fail with unique_violation, which maps to CONFLICT (INV-ID-02). A missing user fails the
   * foreign key and maps to NOT_FOUND.
   */
  async add(
    userId: Id,
    type: string,
    value: string,
    normalized: string,
    verified: boolean,
    now: Timestamp,
  ): Promise<Identifier> {
    const r = await this.pg.query<IdentifierRow>(
      `INSERT INTO aegis.identifiers (${IDENTIFIER_COLUMNS})
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING ${IDENTIFIER_COLUMNS}`,
      [this.ids.newId(), userId, type, value, normalized, verified, now],
    );
    return toIdentifier(r.rows[0] as IdentifierRow);
  }

  async findByNormalized(type: string, normalized: string): Promise<Identifier | null> {
    const r = await this.pg.query<IdentifierRow>(
      `SELECT ${IDENTIFIER_COLUMNS} FROM aegis.identifiers WHERE type = $1 AND normalized = $2`,
      [type, normalized],
    );
    return r.rows[0] ? toIdentifier(r.rows[0]) : null;
  }

  async listByUser(userId: Id): Promise<readonly Identifier[]> {
    const r = await this.pg.query<IdentifierRow>(
      `SELECT ${IDENTIFIER_COLUMNS} FROM aegis.identifiers
        WHERE user_id = $1 ORDER BY created_at_ms, id COLLATE "C"`,
      [userId],
    );
    return r.rows.map(toIdentifier);
  }

  async markVerified(identifierId: Id, _now: Timestamp): Promise<void> {
    const r = await this.pg.query('UPDATE aegis.identifiers SET verified = true WHERE id = $1', [
      identifierId,
    ]);
    if (r.rowCount === 0) throw authError('NOT_FOUND');
  }

  async remove(identifierId: Id): Promise<void> {
    await this.pg.query('DELETE FROM aegis.identifiers WHERE id = $1', [identifierId]);
  }
}

// ---------------------------------------------------------------- credentials

interface CredentialRow {
  id: string;
  user_id: string;
  type: string;
  payload: string;
  created_at_ms: number;
  last_used_at_ms: number | null;
}

const CREDENTIAL_COLUMNS = 'id, user_id, type, payload, created_at_ms, last_used_at_ms';

function toCredential(r: CredentialRow): Credential {
  return {
    id: r.id,
    userId: r.user_id,
    type: r.type,
    payload: r.payload,
    createdAt: r.created_at_ms,
    ...optional('lastUsedAt', r.last_used_at_ms),
  };
}

export class PostgresCredentialStore implements CredentialStore {
  constructor(
    private readonly pg: PostgresClient,
    private readonly ids: IdGenerator,
  ) {}

  async get(userId: Id, type: string): Promise<Credential | null> {
    const r = await this.pg.query<CredentialRow>(
      `SELECT ${CREDENTIAL_COLUMNS} FROM aegis.credentials WHERE user_id = $1 AND type = $2`,
      [userId, type],
    );
    return r.rows[0] ? toCredential(r.rows[0]) : null;
  }

  /**
   * §4.1: one upsert statement. A reader sees either the old row or the new one, never zero or
   * two (INV-CRED-03); the id and creation time of an existing credential are preserved.
   */
  async put(userId: Id, type: string, payload: string, now: Timestamp): Promise<Credential> {
    const r = await this.pg.query<CredentialRow>(
      `INSERT INTO aegis.credentials (id, user_id, type, payload, created_at_ms)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id, type)
         DO UPDATE SET payload = EXCLUDED.payload, last_used_at_ms = NULL
       RETURNING ${CREDENTIAL_COLUMNS}`,
      [this.ids.newId(), userId, type, payload, now],
    );
    return toCredential(r.rows[0] as CredentialRow);
  }

  async touch(credentialId: Id, at: Timestamp): Promise<void> {
    await this.pg.query('UPDATE aegis.credentials SET last_used_at_ms = $2 WHERE id = $1', [
      credentialId,
      at,
    ]);
  }

  async delete(userId: Id, type: string): Promise<void> {
    await this.pg.query('DELETE FROM aegis.credentials WHERE user_id = $1 AND type = $2', [
      userId,
      type,
    ]);
  }
}
