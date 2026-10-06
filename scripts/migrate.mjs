#!/usr/bin/env node
// Applies pending SQL migrations (migrations/*.sql, once each, in order) to DATABASE_URL.
// Safe to run repeatedly. Requires a build (`npm run build`), as it uses the compiled adapter.
//
//   DATABASE_URL=postgres://user:pass@host:5432/db npm run migrate
const url = process.env.DATABASE_URL;
if (!url) {
  console.error('DATABASE_URL is required');
  process.exit(2);
}
const { createPostgresStorage } = await import('../dist/src/storage/postgres/index.js');
const storage = createPostgresStorage({ connectionString: url });
try {
  const applied = await storage.migrate();
  console.log(applied.length > 0 ? `applied: ${applied.join(', ')}` : 'schema up to date');
} catch (e) {
  console.error(`migration failed: ${e?.code ?? ''} ${e?.message ?? e}`);
  process.exitCode = 1;
} finally {
  await storage.close();
}
