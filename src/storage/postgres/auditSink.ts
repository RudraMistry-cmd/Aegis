// Implements spec/storage/interfaces.md §10 for PostgreSQL: an append-only audit sink.
//
// DESIGN
// - Non-blocking (§10.1 SHOULD): `write` enqueues the insert and returns immediately; `flush`
//   awaits everything in flight. The core already never awaits an audit outcome for correctness.
// - Never joins a unit of work. Audit inserts go straight to the pool, bypassing ambient-transaction
//   routing, for two reasons: an audit failure inside a business transaction would abort it (an
//   audit failure must never change an outcome, policy.md §7.3), and the core emits audit events
//   after commit anyway (§11.4).
// - Append-only is enforced by triggers on the table (INV-AUD-02), not merely by this API.
// - Durability trade-off: events accepted by `write` but not yet flushed are lost if the process
//   dies in between. Call `flush` on shutdown.
import type { AuditEvent, AuditSink } from '../../ports/index.js';
import type { PostgresClient } from './postgresClient.js';

export interface PostgresAuditSinkOptions {
  /** Called with the internal error when an insert fails. Never throws back into the core. */
  readonly onError?: (error: unknown, event: AuditEvent) => void;
}

export class PostgresAuditSink implements AuditSink {
  private readonly inFlight = new Set<Promise<void>>();
  /** Number of events that failed to persist (for monitoring and tests). */
  failures = 0;

  constructor(
    private readonly pg: PostgresClient,
    private readonly options: PostgresAuditSinkOptions = {},
  ) {}

  write(event: AuditEvent): void {
    const p = this.insert(event)
      .catch((e: unknown) => {
        this.failures += 1;
        try {
          this.options.onError?.(e, event);
        } catch {
          // A failing error handler must not escape either.
        }
      })
      .finally(() => {
        this.inFlight.delete(p);
      });
    this.inFlight.add(p);
  }

  /** Resolves once every event written so far has been persisted or has failed. */
  async flush(): Promise<void> {
    while (this.inFlight.size > 0) await Promise.all([...this.inFlight]);
  }

  private async insert(e: AuditEvent): Promise<void> {
    // Directly on the pool: deliberately not `pg.query`, which would join an ambient transaction.
    await this.pg.pool.query(
      `INSERT INTO aegis.audit_events
         (id, type, at_ms, severity, outcome, reason, actor_id, actor_type, actor_session,
          target_type, target_id, context, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
      [
        e.id,
        e.type,
        e.at,
        e.severity,
        e.outcome,
        e.reason ?? null,
        e.actor.id ?? null,
        e.actor.type ?? null,
        e.actor.sessionId ?? null,
        e.target.type ?? null,
        e.target.id ?? null,
        JSON.stringify(e.context),
        JSON.stringify(e.details),
      ],
    );
  }
}
