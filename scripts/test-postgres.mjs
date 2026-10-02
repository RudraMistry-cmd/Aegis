#!/usr/bin/env node
// Runs the PostgreSQL adapter test suite (test/postgres/*.pg-test.ts) against a real server.
//
// - If AEGIS_PG_URL is set (CI: a postgres service container), that server is used.
// - Otherwise a throwaway PostgreSQL 17 is started with `embedded-postgres` (prebuilt binaries, no
//   Docker, no native build), used, and deleted afterwards.
//
// AEGIS_PG_URL must point at a database the user may CREATE DATABASE from (e.g. `postgres`): each
// test file creates and drops its own database so files can run in parallel without interfering.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

async function startEmbedded() {
  const { default: EmbeddedPostgres } = await import('embedded-postgres');
  const dir = mkdtempSync(join(tmpdir(), 'aegis-pg-'));
  const port = await freePort();
  const server = new EmbeddedPostgres({
    databaseDir: dir,
    user: 'aegis',
    password: 'aegis',
    port,
    persistent: false,
    onLog: () => undefined,
    onError: () => undefined,
  });
  await server.initialise();
  await server.start();
  const stop = async () => {
    await server.stop().catch(() => undefined);
    rmSync(dir, { recursive: true, force: true });
  };
  return { url: `postgres://aegis:aegis@127.0.0.1:${port}/postgres`, stop };
}

const external = process.env.AEGIS_PG_URL;
const embedded = external ? null : await startEmbedded();
const url = external ?? embedded.url;
console.log(external ? `==> Using AEGIS_PG_URL` : `==> Started embedded PostgreSQL`);

const args = process.argv.slice(2);
const child = spawn(
  process.execPath,
  [
    '--test',
    '--test-concurrency=4',
    ...(args.length > 0 ? args : ['dist/test/postgres/**/*.pg-test.js']),
  ],
  { stdio: 'inherit', env: { ...process.env, AEGIS_PG_URL: url } },
);
const code = await new Promise((resolve) => child.on('exit', (c) => resolve(c ?? 1)));
if (embedded) await embedded.stop();
process.exit(code);
