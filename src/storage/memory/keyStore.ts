// Implements the KeyStore port (src/ports/index.ts; spec/auth/tokens.md §6) in memory, and the
// keyring lifecycle rules shared with the file-backed store.
//
// The rules live in `KeyringState` — plain data plus pure, synchronous operations — so the memory
// and file stores cannot drift apart. The PostgreSQL store implements the same rules in SQL; the
// shared contract suite (test/support/keyStoreContract.ts) runs against all three.
import { AsyncLocalStorage } from 'node:async_hooks';
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
import { Mutex } from './database.js';

const KID_RE = /^[A-Za-z0-9_.-]{1,64}$/;
/** Members that make a JWK private. None may ever be stored as "public" material. */
const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'];

/** The serializable state of a keyring. */
export interface KeyringData {
  /** Every kid ever created, including removed ones: a kid is never reused. */
  registry: string[];
  keys: StoredKeyData[];
}

/** A stored key in plain JSON-friendly form (private material base64-encoded). */
export interface StoredKeyData {
  kid: string;
  type: StoredKeyType;
  status: StoredKeyStatus;
  createdAt: number;
  activatedAt: number | null;
  retiredAt: number | null;
  publicMaterial: PublicJwkMaterial | null;
  privateMaterial: string;
  metadata: Record<string, Json>;
}

export function emptyKeyring(): KeyringData {
  return { registry: [], keys: [] };
}

function toStored(k: StoredKeyData): StoredKey {
  return Object.freeze({
    kid: k.kid,
    type: k.type,
    status: k.status,
    createdAt: k.createdAt,
    activatedAt: k.activatedAt,
    retiredAt: k.retiredAt,
    publicMaterial: k.publicMaterial ? Object.freeze({ ...k.publicMaterial }) : null,
    privateMaterial: new Uint8Array(Buffer.from(k.privateMaterial, 'base64')),
    metadata: Object.freeze(structuredClone(k.metadata)),
  });
}

/** Validates the public half: RSA needs exactly {kty, n, e}; HMAC publishes nothing. */
export function validatePublicMaterial(
  type: StoredKeyType,
  pub: PublicJwkMaterial | null,
): string | null {
  if (type !== 'RSA' && type !== 'HMAC') return 'key.type';
  if (type === 'HMAC') return pub === null ? null : 'key.hmac_public';
  if (pub === null || typeof pub !== 'object') return 'key.rsa_public';
  if (PRIVATE_JWK_MEMBERS.some((m) => Object.hasOwn(pub, m))) return 'key.private_in_public';
  if (pub.kty !== 'RSA' || typeof pub.n !== 'string' || typeof pub.e !== 'string') {
    return 'key.rsa_public';
  }
  if (Object.keys(pub).some((m) => !['kty', 'n', 'e'].includes(m))) return 'key.rsa_public';
  return null;
}

/** The keyring lifecycle rules, applied to plain data. Every method is synchronous and total. */
export class KeyringState {
  constructor(readonly data: KeyringData) {}

  private find(kid: string): StoredKeyData | undefined {
    return this.data.keys.find((k) => k.kid === kid);
  }

  createKey(
    material: KeyStoreMaterial,
    meta: { readonly createdAt: Timestamp; readonly metadata?: Record<string, Json> },
  ): StoredKey {
    if (typeof material.kid !== 'string' || !KID_RE.test(material.kid)) {
      throw authError('VALIDATION_FAILED', { details: { field: 'kid', rule: 'key.kid' } });
    }
    const pubError = validatePublicMaterial(material.type, material.publicMaterial);
    if (pubError) {
      throw authError('VALIDATION_FAILED', {
        details: { field: 'publicMaterial', rule: pubError },
      });
    }
    if (
      !(material.privateMaterial instanceof Uint8Array) ||
      material.privateMaterial.length === 0
    ) {
      throw authError('VALIDATION_FAILED', {
        details: { field: 'privateMaterial', rule: 'key.private' },
      });
    }
    if (this.data.registry.includes(material.kid)) {
      throw authError('CONFLICT', { details: { field: 'kid' } });
    }
    const row: StoredKeyData = {
      kid: material.kid,
      type: material.type,
      status: 'pending',
      createdAt: meta.createdAt,
      activatedAt: null,
      retiredAt: null,
      publicMaterial: material.publicMaterial ? { ...material.publicMaterial } : null,
      privateMaterial: Buffer.from(material.privateMaterial).toString('base64'),
      metadata: structuredClone(meta.metadata ?? {}),
    };
    this.data.registry.push(material.kid);
    this.data.keys.push(row);
    return toStored(row);
  }

  getActiveKey(): StoredKey | null {
    const k = this.data.keys.find((x) => x.status === 'active');
    return k ? toStored(k) : null;
  }

  getKeyById(kid: string): StoredKey | null {
    const k = this.find(kid);
    return k ? toStored(k) : null;
  }

  listKeys(): readonly StoredKey[] {
    return [...this.data.keys]
      .sort((a, b) => a.createdAt - b.createdAt || (a.kid < b.kid ? -1 : a.kid > b.kid ? 1 : 0))
      .map(toStored);
  }

  markPending(kid: string): void {
    const k = this.find(kid);
    if (!k) throw authError('NOT_FOUND');
    if (k.status !== 'pending') throw authError('PRECONDITION_FAILED');
  }

  activate(kid: string, now: Timestamp): { activated: string; retired: string | null } {
    const k = this.find(kid);
    if (!k) throw authError('NOT_FOUND');
    if (k.status === 'active') return { activated: kid, retired: null };
    if (k.status === 'retired') throw authError('PRECONDITION_FAILED');
    const previous = this.data.keys.find((x) => x.status === 'active');
    // An activation instant before the key's creation, or before the current key's activation (a
    // skewed clock), would record an impossible lifecycle: refuse rather than adjust it.
    if (now < k.createdAt || (previous?.activatedAt != null && now < previous.activatedAt)) {
      throw authError('VALIDATION_FAILED', { details: { field: 'now', rule: 'key.activated_at' } });
    }
    if (previous) {
      previous.status = 'retired';
      previous.retiredAt = now;
    }
    k.status = 'active';
    k.activatedAt = now;
    return { activated: kid, retired: previous ? previous.kid : null };
  }

  retire(kid: string, retiredAt: Timestamp): boolean {
    const k = this.find(kid);
    if (!k) throw authError('NOT_FOUND');
    if (k.status === 'retired') return false;
    if (retiredAt < k.createdAt || (k.activatedAt !== null && retiredAt < k.activatedAt)) {
      throw authError('VALIDATION_FAILED', {
        details: { field: 'retiredAt', rule: 'key.retired_at' },
      });
    }
    k.status = 'retired';
    k.retiredAt = retiredAt;
    return true;
  }

  remove(kid: string): void {
    const k = this.find(kid);
    if (!k) return;
    if (k.status === 'active') throw authError('PRECONDITION_FAILED');
    this.data.keys = this.data.keys.filter((x) => x.kid !== kid);
  }

  prune(olderThan: Timestamp): number {
    const before = this.data.keys.length;
    this.data.keys = this.data.keys.filter(
      (k) => !(k.status === 'retired' && k.retiredAt !== null && k.retiredAt < olderThan),
    );
    return before - this.data.keys.length;
  }
}

/**
 * Re-entrant, async-context-aware lock: `run` inside `run` joins instead of deadlocking, exactly like
 * the UnitOfWork's nested-join semantics. Shared by the memory and file key stores.
 */
export class KeyringLock {
  private readonly mutex = new Mutex();
  private readonly held = new AsyncLocalStorage<true>();

  run<T>(fn: () => Promise<T>): Promise<T> {
    if (this.isHeld()) return fn();
    return this.mutex.run(() => this.held.run(true, fn));
  }

  /** True inside a `run` of this lock, in the current async context. */
  isHeld(): boolean {
    return this.held.getStore() === true;
  }
}

/**
 * In-memory KeyStore: for tests and single-process demos. Keys vanish when the process exits, so
 * tokens do not survive a restart — use the file store (dev) or PostgreSQL (production) for that.
 */
export class InMemoryKeyStore implements KeyStore {
  readonly kind = 'memory' as const;
  private readonly state = new KeyringState(emptyKeyring());
  private readonly lock = new KeyringLock();

  private op<T>(fn: (s: KeyringState) => T): Promise<T> {
    return this.lock.run(async () => fn(this.state));
  }

  createKey(
    material: KeyStoreMaterial,
    meta: { readonly createdAt: Timestamp; readonly metadata?: Record<string, Json> },
  ): Promise<StoredKey> {
    return this.op((s) => s.createKey(material, meta));
  }
  getActiveKey(): Promise<StoredKey | null> {
    return this.op((s) => s.getActiveKey());
  }
  getKeyById(kid: string): Promise<StoredKey | null> {
    return this.op((s) => s.getKeyById(kid));
  }
  listKeys(): Promise<readonly StoredKey[]> {
    return this.op((s) => s.listKeys());
  }
  markPending(kid: string): Promise<void> {
    return this.op((s) => s.markPending(kid));
  }
  activate(kid: string, now: Timestamp): Promise<{ activated: string; retired: string | null }> {
    return this.op((s) => s.activate(kid, now));
  }
  retire(kid: string, retiredAt: Timestamp): Promise<boolean> {
    return this.op((s) => s.retire(kid, retiredAt));
  }
  remove(kid: string): Promise<void> {
    return this.op((s) => s.remove(kid));
  }
  prune(olderThan: Timestamp): Promise<number> {
    return this.op((s) => s.prune(olderThan));
  }
  /** All-or-nothing: if `fn` throws, every change it made is undone. Nested calls join. */
  atomically<T>(fn: () => Promise<T>): Promise<T> {
    if (this.lock.isHeld()) return fn();
    return this.lock.run(async () => {
      const snapshot = structuredClone(this.state.data);
      try {
        return await fn();
      } catch (e) {
        this.state.data.registry = snapshot.registry;
        this.state.data.keys = snapshot.keys;
        throw e;
      }
    });
  }
}
