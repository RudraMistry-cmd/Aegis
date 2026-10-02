// Transaction semantics, error mapping and database-enforced invariants of the PostgreSQL adapter
// (spec/storage/interfaces.md §1.1, §11; migrations/001_init.sql triggers).
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import pg from 'pg';
import { digest, isAuthError, type AuditEvent, type NewSession } from '../../src/index.js';
import {
  createPostgresStorage,
  PostgresAuditSink,
  type PostgresStorage,
} from '../../src/storage/postgres/index.js';
import { createPgStorage, START, type PgStorageHandle } from './harness.js';

const DAY = 86_400_000;
let n = 0;
const uid = (p: string): string => `${p}-${++n}`;

async function codeOf(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (e) {
    assert.ok(isAuthError(e), `expected an AuthError, got ${String(e)}`);
    return e.code;
  }
  return 'OK';
}

function session(id: string, userId: string, overrides: Partial<NewSession> = {}): NewSession {
  return {
    id,
    userId,
    subjectType: 'user',
    authMethod: 'password',
    amr: ['pwd'],
    authenticatedAt: START,
    createdAt: START,
    lastSeenAt: START,
    idleExpiresAt: START + DAY,
    absoluteExpiresAt: START + 2 * DAY,
    securityVersionAtIssue: 0,
    ...overrides,
  };
}

describe('PostgreSQL transactions and integrity', () => {
  let h: PgStorageHandle;
  let s: PostgresStorage;
  /** A raw connection to the same database, bypassing the adapter. */
  let raw: pg.Client;

  before(async () => {
    h = await createPgStorage();
    s = h.storage;
    raw = new pg.Client({ connectionString: h.url });
    await raw.connect();
  });
  after(async () => {
    await raw.end();
    await h.dispose();
  });

  const user = async (): Promise<string> => {
    const id = uid('u');
    await s.users.create({ id, status: 'active', metadata: {}, createdAt: START });
    return id;
  };

  // ---------------------------------------------------------------- rollback

  it('rolls back every write when the unit throws', async () => {
    const id = uid('u');
    const sid = uid('s');
    await assert.rejects(
      s.uow.run(async (tx) => {
        await tx.users.create({ id, status: 'active', metadata: {}, createdAt: START });
        await tx.sessions.createWithLimit(session(sid, id), null, 'reject', START);
        await tx.refreshTokens.insert({
          id: uid('rt'),
          hash: digest(sid),
          sessionId: sid,
          userId: id,
          createdAt: START,
          expiresAt: START + DAY,
        });
        throw new Error('boom');
      }),
      /boom/,
    );
    const counts = await raw.query(
      `SELECT (SELECT count(*) FROM aegis.users WHERE id = $1)::int AS u,
              (SELECT count(*) FROM aegis.sessions WHERE id = $2)::int AS s,
              (SELECT count(*) FROM aegis.user_id_registry WHERE id = $1)::int AS r`,
      [id, sid],
    );
    assert.deepEqual(counts.rows[0], { u: 0, s: 0, r: 0 });
  });

  it('refuses to commit a unit that swallowed a database error', async () => {
    const existing = await user();
    const fresh = uid('u');
    // PostgreSQL aborts the transaction on the failed INSERT and would turn COMMIT into ROLLBACK.
    // The runner must report that as a failure, not as success.
    const code = await codeOf(() =>
      s.uow.run(async (tx) => {
        await tx.users
          .create({ id: existing, status: 'active', metadata: {}, createdAt: START })
          .catch(() => undefined);
        await tx.users
          .create({ id: fresh, status: 'active', metadata: {}, createdAt: START })
          .catch(() => undefined);
        return 'looked fine';
      }),
    );
    assert.equal(code, 'CONFLICT');
    assert.equal(await s.users.getById(fresh), null);
  });

  it('retries a transaction the server aborted for serialization, re-running fn from scratch', async () => {
    const serial = createPostgresStorage({
      connectionString: h.url,
      isolation: 'serializable',
      maxConnections: 4,
    });
    try {
      const a = await user();
      const b = await user();
      // Classic write skew: each transaction reads one row and writes the other. Under SERIALIZABLE
      // one of them must be aborted with 40001; the runner retries it and both end up applied.
      let arrived = 0;
      let open!: () => void;
      const bothRead = new Promise<void>((r) => (open = r));
      let attempts = 0;
      const skew = (readId: string, writeId: string) =>
        serial.uow.run(async (tx) => {
          attempts += 1;
          await tx.users.getById(readId);
          if (++arrived === 2) open();
          await Promise.race([bothRead, new Promise((r) => setTimeout(r, 2000))]);
          await tx.users.updateMetadata(writeId, { touchedBy: readId }, undefined, START);
        });
      await Promise.all([skew(a, b), skew(b, a)]);
      assert.ok(serial.runner.retries >= 1, `expected a retry, got ${serial.runner.retries}`);
      assert.ok(attempts >= 3, 'fn was re-executed');
      assert.deepEqual({ ...(await serial.users.getById(b))?.metadata }, { touchedBy: a });
      assert.deepEqual({ ...(await serial.users.getById(a))?.metadata }, { touchedBy: b });
    } finally {
      await serial.close();
    }
  });

  // ---------------------------------------------------------------- ambient routing

  it('routes non-transactional handles into the ambient unit (no self-deadlock)', async () => {
    const id = await user();
    const sid = uid('s');
    await s.sessions.createWithLimit(session(sid, id), null, 'reject', START);
    // Inside the unit, the user row is locked. A call through the *non-transactional* handle that
    // needs the same lock would wait forever on a second connection; ambient routing runs it on
    // the unit's own connection instead.
    const revoked = await s.uow.run(async (tx) => {
      await tx.users.bumpSecurityVersion(id, START);
      return s.sessions.revoke(sid, 'logout', START + 1);
    });
    assert.equal(revoked, true);
  });

  it('rejects a query issued after its unit has finished', async () => {
    const id = await user();
    let late: unknown;
    await s.uow.run(async () => {
      setTimeout(() => {
        s.users.getById(id).catch((e: unknown) => (late = e));
      }, 30);
    });
    await new Promise((r) => setTimeout(r, 120));
    assert.ok(isAuthError(late) && late.code === 'INTERNAL', String(late));
  });

  // ---------------------------------------------------------------- error mapping

  it('maps PostgreSQL errors to spec codes and strips the driver text', async () => {
    const id = await user();
    // 23505 unique_violation -> CONFLICT
    assert.equal(
      await codeOf(() => s.users.create({ id, status: 'active', metadata: {}, createdAt: START })),
      'CONFLICT',
    );
    // 23503 foreign_key_violation -> NOT_FOUND
    assert.equal(
      await codeOf(() =>
        s.identifiers.add('ghost-user', 'email', 'x', `${uid('x')}@e.com`, false, START),
      ),
      'NOT_FOUND',
    );
    // 23514 / domain check -> VALIDATION_FAILED
    assert.equal(
      await codeOf(() =>
        s.users.create({
          id: 'bad id with spaces',
          status: 'active',
          metadata: {},
          createdAt: START,
        }),
      ),
      'VALIDATION_FAILED',
    );
    assert.equal(
      await codeOf(() =>
        s.users.create({ id: uid('u'), status: 'Not-A-State', metadata: {}, createdAt: START }),
      ),
      'VALIDATION_FAILED',
    );
    try {
      await s.users.create({ id, status: 'active', metadata: {}, createdAt: START });
    } catch (e) {
      assert.ok(isAuthError(e));
      const wire = JSON.stringify(e.toJSON());
      assert.ok(!/duplicate key|aegis\.|users_pkey|violates/i.test(wire), wire);
    }
  });

  it('maps an unreachable server to STORAGE_UNAVAILABLE', async () => {
    const dead = createPostgresStorage({
      connectionString: 'postgres://aegis:aegis@127.0.0.1:1/none',
    });
    try {
      assert.equal(await codeOf(() => dead.users.getById('x')), 'STORAGE_UNAVAILABLE');
      assert.equal(
        await codeOf(() => dead.uow.run(async (tx) => tx.users.getById('x'))),
        'STORAGE_UNAVAILABLE',
      );
    } finally {
      await dead.close();
    }
  });

  it('fails with STORAGE_UNAVAILABLE instead of waiting forever on a held lock', async () => {
    const id = await user();
    const impatient = createPostgresStorage({
      connectionString: h.url,
      lockTimeoutMs: 150,
      maxConnections: 2,
    });
    const blocker = new pg.Client({ connectionString: h.url });
    await blocker.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query('SELECT 1 FROM aegis.users WHERE id = $1 FOR UPDATE', [id]);
      const started = Date.now();
      assert.equal(
        await codeOf(() =>
          impatient.sessions.createWithLimit(session(uid('s'), id), 3, 'reject', START),
        ),
        'STORAGE_UNAVAILABLE',
      );
      assert.ok(Date.now() - started < 3000);
    } finally {
      await blocker.query('ROLLBACK');
      await blocker.end();
      await impatient.close();
    }
  });

  // ---------------------------------------------------------------- database-enforced invariants

  it('the schema refuses to resurrect a revoked session (INV-SESS-02)', async () => {
    const id = await user();
    const sid = uid('s');
    await s.sessions.createWithLimit(session(sid, id), null, 'reject', START);
    await s.sessions.revoke(sid, 'logout', START + 1);
    await assert.rejects(
      raw.query(
        'UPDATE aegis.sessions SET revoked_at_ms = NULL, revoked_reason = NULL WHERE id = $1',
        [sid],
      ),
      (e: { code?: string }) => e.code === 'AE001',
    );
    await assert.rejects(
      raw.query("UPDATE aegis.sessions SET revoked_reason = 'admin' WHERE id = $1", [sid]),
      (e: { code?: string }) => e.code === 'AE001',
    );
  });

  it('the schema refuses to change immutable session fields (INV-SESS-04)', async () => {
    const id = await user();
    const sid = uid('s');
    await s.sessions.createWithLimit(session(sid, id), null, 'reject', START);
    await assert.rejects(
      raw.query(
        'UPDATE aegis.sessions SET absolute_expires_at_ms = absolute_expires_at_ms + 1 WHERE id = $1',
        [sid],
      ),
      (e: { code?: string }) => e.code === 'AE002' || e.code === '23514',
    );
    await assert.rejects(
      raw.query("UPDATE aegis.sessions SET amr = '{pwd,totp}' WHERE id = $1", [sid]),
      (e: { code?: string }) => e.code === 'AE002',
    );
  });

  it('the schema refuses to reactivate a token or fork a family (INV-TOK-02)', async () => {
    const id = await user();
    const sid = uid('s');
    await s.sessions.createWithLimit(session(sid, id), null, 'reject', START);
    const t = {
      id: uid('rt'),
      hash: digest(`a-${sid}`),
      sessionId: sid,
      userId: id,
      createdAt: START,
      expiresAt: START + DAY,
    };
    await s.refreshTokens.insert(t);
    // A second active token in the same family violates the partial unique index.
    await assert.rejects(
      raw.query(
        `INSERT INTO aegis.refresh_tokens (id, hash, session_id, user_id, status, created_at_ms, expires_at_ms)
         VALUES ($1, $2, $3, $4, 'active', $5, $6)`,
        [uid('rt'), digest(`b-${sid}`), sid, id, START, START + DAY],
      ),
      (e: { code?: string }) => e.code === '23505',
    );
    await s.refreshTokens.consume(t.hash, START + 1);
    await assert.rejects(
      raw.query("UPDATE aegis.refresh_tokens SET status = 'active' WHERE id = $1", [t.id]),
      (e: { code?: string }) => e.code === 'AE006' || e.code === '23514',
    );
  });

  it('the audit table is append-only (INV-AUD-02)', async () => {
    const sink = new PostgresAuditSink(s.client);
    const event: AuditEvent = {
      id: uid('evt'),
      type: 'login.succeeded',
      at: START,
      severity: 'info',
      actor: { id: 'u-1' },
      target: { type: 'user', id: 'u-1' },
      outcome: 'success',
      context: {},
      details: { authMethod: 'password' },
    };
    sink.write(event);
    await sink.flush();
    assert.equal(sink.failures, 0);
    const row = await raw.query('SELECT type, details FROM aegis.audit_events WHERE id = $1', [
      event.id,
    ]);
    assert.deepEqual(row.rows[0], { type: 'login.succeeded', details: { authMethod: 'password' } });
    for (const sql of [
      `UPDATE aegis.audit_events SET type = 'x' WHERE id = '${event.id}'`,
      `DELETE FROM aegis.audit_events WHERE id = '${event.id}'`,
      'TRUNCATE aegis.audit_events',
    ]) {
      await assert.rejects(raw.query(sql), (e: { code?: string }) => e.code === 'AE020', sql);
    }
  });

  it('an audit failure is contained and never thrown into the caller', async () => {
    let reported = 0;
    const sink = new PostgresAuditSink(s.client, { onError: () => (reported += 1) });
    const dup: AuditEvent = {
      id: uid('evt'),
      type: 'x',
      at: START,
      severity: 'info',
      actor: {},
      target: {},
      outcome: 'success',
      context: {},
      details: {},
    };
    sink.write(dup);
    sink.write(dup); // duplicate id -> insert fails
    await sink.flush();
    assert.equal(sink.failures, 1);
    assert.equal(reported, 1);
  });

  // ---------------------------------------------------------------- operations

  it('migrations are idempotent', async () => {
    assert.deepEqual(await s.migrate(), []);
    const versions = await raw.query(
      'SELECT version FROM aegis.schema_migrations ORDER BY version',
    );
    assert.deepEqual(
      versions.rows.map((r: { version: string }) => r.version),
      ['001_init', '002_indexes'],
    );
  });

  it('housekeeping deletes only sessions terminal before the cutoff, with their tokens', async () => {
    const id = await user();
    const live = uid('s');
    const revoked = uid('s');
    const expired = uid('s');
    await s.sessions.createWithLimit(session(live, id), null, 'reject', START);
    await s.sessions.createWithLimit(session(revoked, id), null, 'reject', START);
    await s.sessions.createWithLimit(
      session(expired, id, { idleExpiresAt: START + 10 }),
      null,
      'reject',
      START,
    );
    const t = {
      id: uid('rt'),
      hash: digest(`h-${revoked}`),
      sessionId: revoked,
      userId: id,
      createdAt: START,
      expiresAt: START + DAY,
    };
    await s.refreshTokens.insert(t);
    await s.sessions.revoke(revoked, 'logout', START + 5);

    const deleted = await s.housekeep(START + 100);
    assert.ok(deleted >= 2);
    assert.ok(await s.sessions.get(live));
    assert.equal(await s.sessions.get(revoked), null);
    assert.equal(await s.sessions.get(expired), null);
    assert.equal(await s.refreshTokens.getById(t.id), null);
  });

  it('a deleted user id can never be issued again (INV-ID-01)', async () => {
    const id = await user();
    await s.users.delete(id);
    assert.equal(
      await codeOf(() => s.users.create({ id, status: 'active', metadata: {}, createdAt: START })),
      'CONFLICT',
    );
  });
});
