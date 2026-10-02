// Implements the KeyStore port (src/ports/index.ts; spec/auth/tokens.md §6) on PostgreSQL, over
// migrations/003_create_keys_table.sql.
//
// ATOMICITY AND CONCURRENCY
// Every mutation runs in a transaction that first takes the KEYRING LOCK — a transaction-scoped
// advisory lock on one fixed key. Mutations of the keyring from any number of instances therefore
// run one at a time, and each sees everything committed before it (READ COMMITTED, every deciding
// read issued after the lock is granted: spec/storage/interfaces.md §11.1). Consequences:
//   - two instances rotating at once both succeed, one after the other: exactly one key ends active,
//     the other new key and the previous one are retired — never two active, never none;
//   - two instances starting on an empty store with generateIfMissing create exactly one key
//     (`atomically` holds the lock across "is there an active key? if not, create + activate").
// Independently, the schema admits at most one active key (partial unique index) and enforces the
// lifecycle with a trigger, so even a defect here cannot produce two signers or revive a key.
//
// LOCK DOMAINS: the keyring lock is a third domain. Key operations never take user, session, token
// or role locks, and no other flow takes the keyring lock, so it cannot join a deadlock cycle.
import type { Json, Timestamp } from '../../domain/index.js';
import { authError } from '../../errors/index.js';
import type {
  KeyStore,
  KeyStoreMaterial,
  PublicJwkMaterial,
  StoredKey,
  StoredKeyStatus,
  StoredKeyType,
} from '../../ports/index.js';
import { validatePublicMaterial } from '../memory/keyStore.js';
import type { PostgresClient } from './postgresClient.js';
import type { TransactionRunner } from './unitOfWork.js';

interface KeyRow {
  kid: string;
  type: StoredKeyType;
  status: StoredKeyStatus;
  created_at_ms: number;
  activated_at_ms: number | null;
  retired_at_ms: number | null;
  public_material: PublicJwkMaterial | null;
  private_material: Buffer;
  metadata: Record<string, Json>;
}

const COLUMNS = `kid, type, status, created_at_ms, activated_at_ms, retired_at_ms, public_material,
  private_material, metadata`;

const KID_RE = /^[A-Za-z0-9_.-]{1,64}$/;

function toStored(r: KeyRow): StoredKey {
  return Object.freeze({
    kid: r.kid,
    type: r.type,
    status: r.status,
    createdAt: r.created_at_ms,
    activatedAt: r.activated_at_ms,
    retiredAt: r.retired_at_ms,
    publicMaterial: r.public_material ? Object.freeze({ ...r.public_material }) : null,
    privateMaterial: new Uint8Array(r.private_material),
    metadata: Object.freeze(r.metadata),
  });
}

export class PostgresKeyStore implements KeyStore {
  readonly kind = 'postgres' as const;

  constructor(
    private readonly pg: PostgresClient,
    private readonly tx: TransactionRunner,
  ) {}

  /** Runs `fn` in a transaction holding the keyring lock (joins an ambient transaction). */
  atomically<T>(fn: () => Promise<T>): Promise<T> {
    return this.tx.atomic(async () => {
      await this.pg.query("SELECT pg_advisory_xact_lock(hashtextextended('aegis.keyring', 0))");
      return fn();
    });
  }

  async createKey(
    material: KeyStoreMaterial,
    meta: { readonly createdAt: Timestamp; readonly metadata?: Record<string, Json> },
  ): Promise<StoredKey> {
    if (typeof material.kid !== 'string' || !KID_RE.test(material.kid)) {
      throw authError('VALIDATION_FAILED', { details: { field: 'kid', rule: 'key.kid' } });
    }
    const pubError = validatePublicMaterial(material.type, material.publicMaterial);
    if (pubError) {
      throw authError('VALIDATION_FAILED', {
        details: { field: 'publicMaterial', rule: pubError },
      });
    }
    return this.atomically(async () => {
      // The registry's primary key rejects any kid ever used, including removed ones (CONFLICT).
      await this.pg.query(
        'INSERT INTO aegis.signing_key_registry (kid, registered_at_ms) VALUES ($1, $2)',
        [material.kid, meta.createdAt],
      );
      const r = await this.pg.query<KeyRow>(
        `INSERT INTO aegis.signing_keys
           (kid, type, status, created_at_ms, public_material, private_material, metadata)
         VALUES ($1, $2, 'pending', $3, $4, $5, $6)
         RETURNING ${COLUMNS}`,
        [
          material.kid,
          material.type,
          meta.createdAt,
          material.publicMaterial === null ? null : JSON.stringify(material.publicMaterial),
          Buffer.from(material.privateMaterial),
          JSON.stringify(meta.metadata ?? {}),
        ],
      );
      return toStored(r.rows[0] as KeyRow);
    });
  }

  async getActiveKey(): Promise<StoredKey | null> {
    const r = await this.pg.query<KeyRow>(
      `SELECT ${COLUMNS} FROM aegis.signing_keys WHERE status = 'active'`,
    );
    return r.rows[0] ? toStored(r.rows[0]) : null;
  }

  async getKeyById(kid: string): Promise<StoredKey | null> {
    const r = await this.pg.query<KeyRow>(
      `SELECT ${COLUMNS} FROM aegis.signing_keys WHERE kid = $1`,
      [kid],
    );
    return r.rows[0] ? toStored(r.rows[0]) : null;
  }

  async listKeys(): Promise<readonly StoredKey[]> {
    const r = await this.pg.query<KeyRow>(
      `SELECT ${COLUMNS} FROM aegis.signing_keys ORDER BY created_at_ms, kid COLLATE "C"`,
    );
    return r.rows.map(toStored);
  }

  async markPending(kid: string): Promise<void> {
    const r = await this.pg.query<{ status: StoredKeyStatus }>(
      'SELECT status FROM aegis.signing_keys WHERE kid = $1',
      [kid],
    );
    const status = r.rows[0]?.status;
    if (status === undefined) throw authError('NOT_FOUND');
    if (status !== 'pending') throw authError('PRECONDITION_FAILED');
  }

  /**
   * The kid becomes the single active key; the previous active key is retired at `now`, in the same
   * transaction. The old key is retired first so the one-active index is never violated mid-way.
   */
  activate(kid: string, now: Timestamp): Promise<{ activated: string; retired: string | null }> {
    return this.atomically(async () => {
      const target = await this.pg.query<{ status: StoredKeyStatus; created_at_ms: number }>(
        'SELECT status, created_at_ms FROM aegis.signing_keys WHERE kid = $1 FOR UPDATE',
        [kid],
      );
      const row = target.rows[0];
      if (row === undefined) throw authError('NOT_FOUND');
      if (row.status === 'active') return { activated: kid, retired: null };
      if (row.status === 'retired') throw authError('PRECONDITION_FAILED');
      const current = await this.pg.query<{ activated_at_ms: number }>(
        "SELECT activated_at_ms FROM aegis.signing_keys WHERE status = 'active' FOR UPDATE",
      );
      const currentSince = current.rows[0]?.activated_at_ms;
      if (now < row.created_at_ms || (currentSince !== undefined && now < currentSince)) {
        throw authError('VALIDATION_FAILED', {
          details: { field: 'now', rule: 'key.activated_at' },
        });
      }
      const previous = await this.pg.query<{ kid: string }>(
        `UPDATE aegis.signing_keys SET status = 'retired', retired_at_ms = $1
          WHERE status = 'active' RETURNING kid`,
        [now],
      );
      await this.pg.query(
        `UPDATE aegis.signing_keys SET status = 'active', activated_at_ms = $2 WHERE kid = $1`,
        [kid, now],
      );
      return { activated: kid, retired: previous.rows[0]?.kid ?? null };
    });
  }

  retire(kid: string, retiredAt: Timestamp): Promise<boolean> {
    return this.atomically(async () => {
      const r = await this.pg.query<{
        status: StoredKeyStatus;
        created_at_ms: number;
        activated_at_ms: number | null;
      }>(
        'SELECT status, created_at_ms, activated_at_ms FROM aegis.signing_keys WHERE kid = $1 FOR UPDATE',
        [kid],
      );
      const row = r.rows[0];
      if (!row) throw authError('NOT_FOUND');
      if (row.status === 'retired') return false;
      if (
        retiredAt < row.created_at_ms ||
        (row.activated_at_ms !== null && retiredAt < row.activated_at_ms)
      ) {
        throw authError('VALIDATION_FAILED', {
          details: { field: 'retiredAt', rule: 'key.retired_at' },
        });
      }
      await this.pg.query(
        `UPDATE aegis.signing_keys SET status = 'retired', retired_at_ms = $2 WHERE kid = $1`,
        [kid, retiredAt],
      );
      return true;
    });
  }

  remove(kid: string): Promise<void> {
    return this.atomically(async () => {
      const r = await this.pg.query<{ status: StoredKeyStatus }>(
        'SELECT status FROM aegis.signing_keys WHERE kid = $1 FOR UPDATE',
        [kid],
      );
      const status = r.rows[0]?.status;
      if (status === undefined) return; // idempotent
      if (status === 'active') throw authError('PRECONDITION_FAILED');
      // The registry row stays: the kid can never be reused.
      await this.pg.query('DELETE FROM aegis.signing_keys WHERE kid = $1', [kid]);
    });
  }

  prune(olderThan: Timestamp): Promise<number> {
    return this.atomically(async () => {
      const r = await this.pg.query(
        `DELETE FROM aegis.signing_keys WHERE status = 'retired' AND retired_at_ms < $1`,
        [olderThan],
      );
      return r.rowCount;
    });
  }
}
