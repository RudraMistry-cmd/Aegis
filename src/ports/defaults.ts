// Implements spec/storage/interfaces.md §9 (Clock, Random, IdGenerator, PasswordHasher, RateLimiter)
// and §10 (AuditSink) as simple reference implementations.
import { randomBytes, randomUUID, scrypt, timingSafeEqual } from 'node:crypto';
import type { Timestamp } from '../domain/index.js';
import type {
  AuditEvent,
  AuditSink,
  Clock,
  IdGenerator,
  PasswordHasher,
  RateLimiter,
  Random,
} from './index.js';

/** Real-time clock. */
export class SystemClock implements Clock {
  now(): Timestamp {
    return Date.now();
  }
}

/** Controllable clock for tests and demos (spec/conformance.md §2.1). */
export class ManualClock implements Clock {
  private t: Timestamp;
  constructor(start: Timestamp = Date.UTC(2030, 0, 1)) {
    this.t = start;
  }
  now(): Timestamp {
    return this.t;
  }
  set(t: Timestamp): void {
    this.t = t;
  }
  advance(ms: number): void {
    this.t += ms;
  }
}

/** CSPRNG-backed Random. */
export class CryptoRandom implements Random {
  bytes(n: number): Uint8Array {
    return new Uint8Array(randomBytes(n));
  }
}

/** UUIDv4 ids (122 random bits, spec §9.3). */
export class CryptoIdGenerator implements IdGenerator {
  newId(): string {
    return randomUUID();
  }
}

/** Deterministic sequential ids. TEST ONLY (spec §9.2: fakes must not be production-selectable). */
export class SequentialIdGenerator implements IdGenerator {
  private n = 0;
  constructor(private readonly prefix = 'id') {}
  newId(): string {
    this.n += 1;
    return `${this.prefix}-${this.n}`;
  }
}

// ---------------------------------------------------------------- password hasher

export interface ScryptHasherOptions {
  /**
   * CPU/memory cost (power of two). Default 2^17 (about 128 MiB and ~0.3 s per hash). Tests and
   * demos pass a smaller value explicitly for speed; hashes made with other parameters still verify
   * and are flagged by `needsRehash`.
   */
  readonly N?: number;
  readonly r?: number;
  readonly p?: number;
  /** Maximum concurrent hash computations (spec §9.4.3). */
  readonly maxConcurrency?: number;
}

/**
 * Reference PasswordHasher using scrypt from node:crypto (no native build step).
 * NOTE: spec/auth/principal.md §5.1.3 names Argon2id as the default; scrypt is an explicitly
 * selected alternative permitted by the same clause. Pepper support is not implemented
 * (TODO spec/auth/principal.md §5.1.4).
 */
export class ScryptHasher implements PasswordHasher {
  private readonly N: number;
  private readonly r: number;
  private readonly p: number;
  private readonly maxConcurrency: number;
  private active = 0;
  private readonly waiting: Array<() => void> = [];
  /** Observed peak concurrency (for tests of spec §9.4.3). */
  peakConcurrency = 0;
  /** Call counters for timing/equal-work tests (spec/conformance.md AUTH-TIM-01). */
  readonly calls = { hash: 0, verify: 0, dummyVerify: 0 };

  constructor(opts: ScryptHasherOptions = {}) {
    this.N = opts.N ?? 1 << 17;
    this.r = opts.r ?? 8;
    this.p = opts.p ?? 1;
    this.maxConcurrency = opts.maxConcurrency ?? 4;
  }

  async hash(password: string): Promise<string> {
    this.calls.hash += 1;
    const salt = randomBytes(16);
    const dk = await this.derive(password, salt, this.N, this.r, this.p);
    return this.encode(salt, dk, this.N, this.r, this.p);
  }

  async verify(password: string, encoded: string): Promise<boolean> {
    this.calls.verify += 1;
    const parsed = this.parse(encoded);
    if (!parsed) return false;
    try {
      const dk = await this.derive(password, parsed.salt, parsed.N, parsed.r, parsed.p);
      return dk.length === parsed.dk.length && timingSafeEqual(dk, parsed.dk);
    } catch {
      return false;
    }
  }

  needsRehash(encoded: string): boolean {
    const parsed = this.parse(encoded);
    return !parsed || parsed.N < this.N || parsed.r < this.r || parsed.p < this.p;
  }

  async dummyVerify(password: string): Promise<void> {
    // Equal cost to a real verify at current parameters; fixed salt; result discarded.
    this.calls.dummyVerify += 1;
    await this.derive(password, Buffer.alloc(16, 7), this.N, this.r, this.p);
  }

  private encode(salt: Buffer, dk: Buffer, N: number, r: number, p: number): string {
    const ln = Math.log2(N);
    return `$scrypt$ln=${ln},r=${r},p=${p}$${salt.toString('base64')}$${dk.toString('base64')}`;
  }

  private parse(
    encoded: string,
  ): { N: number; r: number; p: number; salt: Buffer; dk: Buffer } | null {
    if (typeof encoded !== 'string') return null;
    const m =
      /^\$scrypt\$ln=(\d{1,2}),r=(\d{1,3}),p=(\d{1,3})\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$/.exec(
        encoded,
      );
    if (!m) return null;
    const ln = Number(m[1]);
    if (ln < 1 || ln > 20) return null;
    return {
      N: 2 ** ln,
      r: Number(m[2]),
      p: Number(m[3]),
      salt: Buffer.from(m[4] as string, 'base64'),
      dk: Buffer.from(m[5] as string, 'base64'),
    };
  }

  private async derive(
    password: string,
    salt: Buffer,
    N: number,
    r: number,
    p: number,
  ): Promise<Buffer> {
    await this.acquire();
    try {
      return await new Promise<Buffer>((resolve, reject) => {
        scrypt(
          password.normalize('NFKC'),
          salt,
          32,
          { N, r, p, maxmem: 256 * N * r },
          (err, key) => (err ? reject(err) : resolve(key)),
        );
      });
    } finally {
      this.release();
    }
  }

  private async acquire(): Promise<void> {
    if (this.active >= this.maxConcurrency) {
      await new Promise<void>((resolve) => this.waiting.push(resolve));
    }
    this.active += 1;
    this.peakConcurrency = Math.max(this.peakConcurrency, this.active);
  }

  private release(): void {
    this.active -= 1;
    this.waiting.shift()?.();
  }
}

// ---------------------------------------------------------------- rate limiter

export interface RateRule {
  readonly max: number;
  readonly windowMs: number;
}

/**
 * Sliding-window failure limiter (spec §9.8). Blocks expire with the window, so there is no
 * permanent lock (spec/flows/login.md §5.8). Rules are selected by key prefix.
 */
export class MemoryRateLimiter implements RateLimiter {
  private readonly failures = new Map<string, Timestamp[]>();

  constructor(
    private readonly rules: ReadonlyArray<{ prefix: string; rule: RateRule }> = [
      { prefix: 'login-ip:', rule: { max: 50, windowMs: 15 * 60_000 } },
      { prefix: 'login-global', rule: { max: 10_000, windowMs: 15 * 60_000 } },
      { prefix: 'login:', rule: { max: 5, windowMs: 15 * 60_000 } },
    ],
  ) {}

  private ruleFor(key: string): RateRule {
    return (
      this.rules.find((r) => key.startsWith(r.prefix))?.rule ?? { max: 5, windowMs: 15 * 60_000 }
    );
  }

  private live(key: string, now: Timestamp): Timestamp[] {
    const rule = this.ruleFor(key);
    const list = (this.failures.get(key) ?? []).filter((t) => t > now - rule.windowMs);
    if (list.length > 0) this.failures.set(key, list);
    else this.failures.delete(key);
    return list;
  }

  async peek(
    key: string,
    now: Timestamp,
  ): Promise<{ blocked: boolean; retryAfterMs?: number; failures: number }> {
    const rule = this.ruleFor(key);
    const list = this.live(key, now);
    if (list.length >= rule.max) {
      const oldest = list[0] as number;
      return {
        blocked: true,
        retryAfterMs: Math.max(1, oldest + rule.windowMs - now),
        failures: list.length,
      };
    }
    return { blocked: false, failures: list.length };
  }

  async recordFailure(key: string, now: Timestamp): Promise<void> {
    const list = this.live(key, now);
    list.push(now);
    this.failures.set(key, list);
  }

  async reset(key: string): Promise<void> {
    this.failures.delete(key);
  }
}

// ---------------------------------------------------------------- audit sink

/** In-memory append-only audit list (spec §10). Reading is for tests and diagnostics only. */
export class MemoryAuditSink implements AuditSink {
  private readonly list: AuditEvent[] = [];

  write(event: AuditEvent): void {
    this.list.push(structuredClone(event));
  }

  /** Snapshot copy of all events written so far. */
  events(): readonly AuditEvent[] {
    return this.list.map((e) => structuredClone(e));
  }

  /** Convenience for tests. */
  ofType(type: string): readonly AuditEvent[] {
    return this.events().filter((e) => e.type === type);
  }
}
