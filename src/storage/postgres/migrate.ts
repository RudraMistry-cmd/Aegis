// Applies the SQL files in migrations/ in order, once each. Implements the schema delivery of
// spec/storage/interfaces.md §1 for PostgreSQL.
//
// - Each file runs in its own transaction together with its bookkeeping row, so a failed migration
//   leaves no partial schema behind.
// - A session-level advisory lock serializes concurrent migrators (several processes starting at
//   once), and already-applied versions are skipped, so running it again is a no-op.
import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { mapPgError } from './errors.js';
import type { PostgresClient } from './postgresClient.js';

/** Arbitrary constant identifying the Aegis migration lock. */
const MIGRATION_LOCK_KEY = 0x6165676973; // "aegis"

/** `migrations/` at the package root, from either `src/` (tsx) or `dist/src/` (compiled). */
export function defaultMigrationsDir(): string {
  const compiled = import.meta.url.includes('/dist/');
  return fileURLToPath(
    new URL(compiled ? '../../../../migrations/' : '../../../migrations/', import.meta.url),
  );
}

/** Applies pending migrations. Returns the versions applied by this call. */
export async function migrate(
  pg: PostgresClient,
  dir: string = defaultMigrationsDir(),
): Promise<string[]> {
  const files = (await readdir(dir)).filter((f) => /^\d{3}_.+\.sql$/.test(f)).sort();
  const client = await pg.connect();
  const applied: string[] = [];
  try {
    await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK_KEY]);
    try {
      await client.query('CREATE SCHEMA IF NOT EXISTS aegis');
      await client.query(
        `CREATE TABLE IF NOT EXISTS aegis.schema_migrations (
           version    text PRIMARY KEY,
           applied_at timestamptz NOT NULL DEFAULT now()
         )`,
      );
      const done = new Set(
        (
          await client.query<{ version: string }>('SELECT version FROM aegis.schema_migrations')
        ).rows.map((r) => r.version),
      );
      for (const file of files) {
        const version = file.replace(/\.sql$/, '');
        if (done.has(version)) continue;
        const sql = await readFile(`${dir}/${file}`, 'utf8');
        await client.query('BEGIN');
        try {
          await client.query(sql);
          await client.query('INSERT INTO aegis.schema_migrations (version) VALUES ($1)', [
            version,
          ]);
          await client.query('COMMIT');
          applied.push(version);
        } catch (e) {
          await client.query('ROLLBACK').catch(() => undefined);
          throw e;
        }
      }
    } finally {
      await client
        .query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK_KEY])
        .catch(() => undefined);
    }
  } catch (e) {
    throw mapPgError(e);
  } finally {
    client.release();
  }
  return applied;
}
