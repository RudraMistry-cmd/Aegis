// A file-backed KeyStore for local development (spec/auth/tokens.md §6). Keys survive restarts.
//
// - The lifecycle rules are the shared `KeyringState` (identical to the memory store).
// - Writes are atomic: the new state goes to a temporary file in the same directory, is flushed to
//   disk, and then renamed over the old file, so a crash leaves either the old or the new keyring,
//   never a torn one. The file is created with mode 0600 (owner-only) where the OS supports it.
// - Private material is whatever the key provider sealed: AES-256-GCM ciphertext when a master key
//   is configured, plaintext otherwise — and the provider then logs an explicit warning.
// - SINGLE PROCESS ONLY. Mutations are serialized in-process; two processes writing the same file
//   could lose an update. For several instances use the PostgreSQL store.
import { open, readFile, rename, unlink } from 'node:fs/promises';
import { dirname, basename, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { Json, Timestamp } from '../../domain/index.js';
import { authError, toInfraError } from '../../errors/index.js';
import type { KeyStore, KeyStoreMaterial, StoredKey } from '../../ports/index.js';
import { emptyKeyring, KeyringLock, KeyringState, type KeyringData } from '../memory/keyStore.js';

const FILE_VERSION = 1;

export class FileKeyStore implements KeyStore {
  readonly kind = 'file' as const;
  private readonly lock = new KeyringLock();
  /** The state of the current `atomically` block, so nested calls see uncommitted changes. */
  private pending: { state: KeyringState; dirty: boolean } | null = null;

  /** @param path the keyring file; created on first write. */
  constructor(readonly path: string) {}

  private async load(): Promise<KeyringData> {
    let text: string;
    try {
      text = await readFile(this.path, 'utf8');
    } catch (e) {
      if ((e as { code?: string }).code === 'ENOENT') return emptyKeyring();
      throw toInfraError(e);
    }
    try {
      const parsed = JSON.parse(text) as { version?: unknown } & Partial<KeyringData>;
      if (
        parsed.version !== FILE_VERSION ||
        !Array.isArray(parsed.registry) ||
        !Array.isArray(parsed.keys)
      ) {
        throw new Error('unsupported keyring file');
      }
      return { registry: parsed.registry, keys: parsed.keys };
    } catch (e) {
      // A corrupt keyring is never silently replaced by an empty one.
      throw authError('STORAGE_UNAVAILABLE', { cause: e });
    }
  }

  private async save(data: KeyringData): Promise<void> {
    const tmp = join(
      dirname(this.path),
      `.${basename(this.path)}.${randomBytes(6).toString('hex')}.tmp`,
    );
    const body = JSON.stringify({ version: FILE_VERSION, ...data }, null, 2);
    try {
      const handle = await open(tmp, 'wx', 0o600);
      try {
        await handle.writeFile(body, 'utf8');
        await handle.sync();
      } finally {
        await handle.close();
      }
      await rename(tmp, this.path);
    } catch (e) {
      await unlink(tmp).catch(() => undefined);
      throw toInfraError(e);
    }
  }

  /** Runs `fn` on the state; writes it back only if `fn` changed it. Joins an open `atomically`. */
  private op<T>(write: boolean, fn: (s: KeyringState) => T): Promise<T> {
    return this.lock.run(async () => {
      if (this.pending) {
        const result = fn(this.pending.state);
        if (write) this.pending.dirty = true;
        return result;
      }
      const state = new KeyringState(await this.load());
      const result = fn(state);
      if (write) await this.save(state.data);
      return result;
    });
  }

  createKey(
    material: KeyStoreMaterial,
    meta: { readonly createdAt: Timestamp; readonly metadata?: Record<string, Json> },
  ): Promise<StoredKey> {
    return this.op(true, (s) => s.createKey(material, meta));
  }
  getActiveKey(): Promise<StoredKey | null> {
    return this.op(false, (s) => s.getActiveKey());
  }
  getKeyById(kid: string): Promise<StoredKey | null> {
    return this.op(false, (s) => s.getKeyById(kid));
  }
  listKeys(): Promise<readonly StoredKey[]> {
    return this.op(false, (s) => s.listKeys());
  }
  markPending(kid: string): Promise<void> {
    return this.op(false, (s) => s.markPending(kid));
  }
  activate(kid: string, now: Timestamp): Promise<{ activated: string; retired: string | null }> {
    return this.op(true, (s) => s.activate(kid, now));
  }
  retire(kid: string, retiredAt: Timestamp): Promise<boolean> {
    return this.op(true, (s) => s.retire(kid, retiredAt));
  }
  remove(kid: string): Promise<void> {
    return this.op(true, (s) => s.remove(kid));
  }
  prune(olderThan: Timestamp): Promise<number> {
    return this.op(true, (s) => s.prune(olderThan));
  }

  /**
   * All calls inside `fn` operate on one in-memory copy, written once at the end — and not at all if
   * `fn` throws, so a failed multi-step change (e.g. create + activate) leaves the file untouched.
   */
  atomically<T>(fn: () => Promise<T>): Promise<T> {
    return this.lock.run(async () => {
      if (this.pending) return fn(); // nested: join
      this.pending = { state: new KeyringState(await this.load()), dirty: false };
      try {
        const result = await fn();
        if (this.pending.dirty) await this.save(this.pending.state.data);
        return result;
      } finally {
        this.pending = null;
      }
    });
  }
}
