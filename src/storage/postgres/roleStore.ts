// Implements spec/storage/interfaces.md §8.1 for PostgreSQL: the RoleCatalogStore mirror.
//
// The mirror exists for referential integrity and administration. The authorization engine never
// reads it: it evaluates the immutable in-code catalog (roles.md §3.3), so nothing written here can
// change a decision.
import type { Timestamp } from '../../domain/index.js';
import type { RoleCatalogStore } from '../../ports/index.js';
import type { PostgresClient } from './postgresClient.js';
import type { TransactionRunner } from './unitOfWork.js';

export class PostgresRoleCatalogStore implements RoleCatalogStore {
  constructor(
    private readonly pg: PostgresClient,
    private readonly tx: TransactionRunner,
  ) {}

  /**
   * §8.1.1-§8.1.2: idempotent, and safe when several processes start at once.
   *
   * The singleton `catalog_state` row is created if absent and then locked FOR UPDATE, so
   * concurrent syncs run one at a time. If the stored version already equals the snapshot's (the
   * version is a digest of the catalog, roles.md §3.2), nothing is written: syncing the same catalog
   * twice is a no-op. Otherwise the role and permission sets are replaced to match exactly.
   */
  async sync(
    snapshot: { version: string; roles: readonly string[]; permissions: readonly string[] },
    now: Timestamp,
  ): Promise<void> {
    await this.tx.atomic(async () => {
      await this.pg.query(
        `INSERT INTO aegis.catalog_state (singleton, version, synced_at_ms)
         VALUES (true, '', $1) ON CONFLICT (singleton) DO NOTHING`,
        [now],
      );
      const current = await this.pg.query<{ version: string }>(
        'SELECT version FROM aegis.catalog_state WHERE singleton FOR UPDATE',
      );
      if (current.rows[0]?.version === snapshot.version) return;

      const roles = [...snapshot.roles];
      const permissions = [...snapshot.permissions];
      await this.pg.query('DELETE FROM aegis.roles WHERE NOT (name = ANY($1::text[]))', [roles]);
      await this.pg.query(
        'INSERT INTO aegis.roles (name) SELECT unnest($1::text[]) ON CONFLICT DO NOTHING',
        [roles],
      );
      await this.pg.query('DELETE FROM aegis.permissions WHERE NOT (name = ANY($1::text[]))', [
        permissions,
      ]);
      await this.pg.query(
        'INSERT INTO aegis.permissions (name) SELECT unnest($1::text[]) ON CONFLICT DO NOTHING',
        [permissions],
      );
      await this.pg.query(
        'UPDATE aegis.catalog_state SET version = $1, synced_at_ms = $2 WHERE singleton',
        [snapshot.version, now],
      );
    });
  }

  async getCatalogVersion(): Promise<string | null> {
    const r = await this.pg.query<{ version: string }>(
      'SELECT version FROM aegis.catalog_state WHERE singleton',
    );
    const v = r.rows[0]?.version;
    return v === undefined || v === '' ? null : v;
  }
}
