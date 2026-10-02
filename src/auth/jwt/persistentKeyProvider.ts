// Implements spec/auth/tokens.md §6 with DURABLE keys: a KeyProvider backed by a KeyStore, so tokens
// stay verifiable across restarts and across instances.
//
// WHAT IS UNCHANGED FROM PHASE 3
//   The verification rules are the same code: key material is validated by `importKey` and the
//   retired-key window by `canVerifyAt` (keyProvider.ts), and the JWT provider still verifies the
//   signature first and leaves the decision to the session (strict revocation, tokens.md §2.5).
//
// CACHE AND PROPAGATION
//   `getActiveKey` / `getKeyById` are synchronous (the JWT provider is), so they read an in-memory
//   copy of the keyring. The copy is reloaded every `refreshIntervalMs` (default 30 s) and, at most
//   once per second, when a token names a kid this instance has not seen — which is how an instance
//   learns about a key another instance staged or activated. A refresh that fails keeps the previous
//   copy and reports the error; it never invents keys. Operational consequence (docs/JWKS.md):
//   after a rotation or a removal, other instances follow within one refresh interval.
//
// FAIL CLOSED
//   Startup fails with CONFIG_INVALID when the store holds no active key (unless `generateIfMissing`
//   and the store is completely empty), when a key cannot be decrypted or is weak, of the wrong type,
//   or inconsistent with its stored public half. At runtime, if no key is active (the active key was
//   retired before a replacement was activated) signing fails with STORAGE_UNAVAILABLE rather than
//   using anything else.
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  type KeyObject,
} from 'node:crypto';
import type { Timestamp } from '../../domain/index.js';
import { authError, configInvalid, isAuthError, type ConfigViolation } from '../../errors/index.js';
import type {
  Clock,
  IdGenerator,
  KeyStore,
  PublicJwkMaterial,
  StoredKey,
} from '../../ports/index.js';
import { createJwksHandler, type JwksHandler } from './jwks.js';
import { JwtAccessTokenProvider, resolveJwtConfig, type JwtConfigInput } from './jwtProvider.js';
import {
  canVerifyAt,
  importKey,
  type JwtAlgorithm,
  type KeyInfo,
  type KeyMaterial,
  type KeyProvider,
  type KeyStatus,
  type SigningKey,
  type VerificationKey,
} from './keyProvider.js';
import { isSealed, parseMasterKey, seal, unseal } from './keySealing.js';

/** Where warnings go (missing master key, plaintext keys, failed refreshes). Never receives material. */
export interface KeyLogger {
  warn(message: string): void;
}

export interface PersistentKeyProviderOptions {
  readonly store: KeyStore;
  readonly algorithm: JwtAlgorithm;
  readonly rotationEnabled: boolean;
  /** How long a retired key keeps verifying: ttl + leeway (computed by `openJwtAccessTokens`). */
  readonly retiredKeyGraceMs: number;
  readonly generateIfMissing: boolean;
  /** 32-byte AES key; null means private material is stored unencrypted (dev only). */
  readonly masterKey: Buffer | null;
  readonly clock: Clock;
  /** Periodic reload of the keyring; 0 disables. Default 30 000 ms. */
  readonly refreshIntervalMs?: number;
  readonly logger?: KeyLogger;
}

interface CachedKey {
  readonly kid: string;
  readonly status: KeyStatus;
  readonly createdAt: Timestamp;
  readonly retiredAt?: Timestamp;
  readonly signing: KeyObject;
  readonly verification: KeyObject;
}

const ON_DEMAND_REFRESH_MIN_MS = 1000;
const TYPE_FOR: Record<JwtAlgorithm, StoredKey['type']> = { HS256: 'HMAC', RS256: 'RSA' };

function publicJwkOf(key: KeyObject): PublicJwkMaterial {
  const jwk = createPublicKey(key).export({ format: 'jwk' });
  return { kty: 'RSA', n: jwk.n as string, e: jwk.e as string };
}

export class PersistentKeyProvider implements KeyProvider {
  readonly algorithm: JwtAlgorithm;
  readonly retiredKeyGraceMs: number;
  readonly rotationEnabled: boolean;
  private cache = new Map<string, CachedKey>();
  private readonly warnedPlaintext = new Set<string>();
  private timer: NodeJS.Timeout | undefined;
  private lastOnDemand = 0;
  private refreshing: Promise<void> | null = null;

  private constructor(private readonly o: PersistentKeyProviderOptions) {
    this.algorithm = o.algorithm;
    this.retiredKeyGraceMs = o.retiredKeyGraceMs;
    this.rotationEnabled = o.rotationEnabled;
  }

  /**
   * Loads (and, if allowed and the store is empty, creates) the keyring. Every failure that would let
   * this instance start without a trustworthy signing key is CONFIG_INVALID.
   */
  static async open(options: PersistentKeyProviderOptions): Promise<PersistentKeyProvider> {
    const p = new PersistentKeyProvider(options);
    if (options.generateIfMissing) {
      // Under the keyring lock, so instances starting together on an empty store create one key.
      await options.store.atomically(async () => {
        if ((await options.store.listKeys()).length > 0) return;
        const material = p.generateMaterial();
        await p.persist(material);
        await options.store.activate(material.kid, options.clock.now());
      });
    }
    await p.refresh();

    const v: ConfigViolation[] = [];
    const active = [...p.cache.values()].filter((k) => k.status === 'active');
    if (active.length !== 1) {
      v.push({
        path: 'keys',
        rule: 'keys.no_active_key',
        message: options.generateIfMissing
          ? 'the key store holds keys but none is active; activate one'
          : 'the key store has no active key; activate one or set keys.generateIfMissing',
      });
    }
    if (!options.rotationEnabled && p.cache.size !== 1) {
      v.push({
        path: 'keys',
        rule: 'keys.rotation_disabled',
        message: 'exactly one key when rotation is disabled',
      });
    }
    if (v.length > 0) throw configInvalid(v);

    const interval = options.refreshIntervalMs ?? 30_000;
    if (interval > 0) {
      p.timer = setInterval(() => {
        p.refresh().catch((e: unknown) =>
          p.warn(
            `[aegis] signing-key refresh failed (${isAuthError(e) ? e.code : 'error'}); keeping the previous keyring`,
          ),
        );
      }, interval);
      p.timer.unref?.();
    }
    return p;
  }

  // ---------------------------------------------------------------- KeyProvider (synchronous)

  getActiveKey(): SigningKey {
    for (const k of this.cache.values()) {
      if (k.status === 'active') return { kid: k.kid, algorithm: this.algorithm, key: k.signing };
    }
    // Reachable only if the active key was retired before a replacement was activated. Fail closed.
    throw authError('STORAGE_UNAVAILABLE');
  }

  getKeyById(kid: string, now: Timestamp): VerificationKey | null {
    const k = this.cache.get(kid);
    if (!k) {
      this.refreshSoon();
      return null;
    }
    if (!canVerifyAt(k.status, k.retiredAt, now, this.retiredKeyGraceMs)) return null;
    return {
      kid: k.kid,
      algorithm: this.algorithm,
      key: k.verification,
      status: k.status,
      ...(k.retiredAt !== undefined ? { retiredAt: k.retiredAt } : {}),
    };
  }

  verificationKeys(now: Timestamp): readonly VerificationKey[] {
    return [...this.cache.keys()]
      .map((kid) => this.getKeyById(kid, now))
      .filter((k): k is VerificationKey => k !== null);
  }

  /** Metadata of the cached keyring. Never contains material. */
  list(): readonly KeyInfo[] {
    return [...this.cache.values()].map((k) => ({
      kid: k.kid,
      algorithm: this.algorithm,
      status: k.status,
      createdAt: k.createdAt,
      ...(k.retiredAt !== undefined ? { retiredAt: k.retiredAt } : {}),
    }));
  }

  // ---------------------------------------------------------------- lifecycle (asynchronous)

  /**
   * Reloads the keyring from the store and validates every key. On any invalid key nothing is
   * replaced and CONFIG_INVALID is thrown.
   */
  async refresh(): Promise<void> {
    const stored = await this.o.store.listKeys();
    const v: ConfigViolation[] = [];
    const next = new Map<string, CachedKey>();
    for (const s of stored) {
      const path = `keys.${s.kid}`;
      if (s.type !== TYPE_FOR[this.algorithm]) {
        v.push({
          path,
          rule: 'keys.type_mismatch',
          message: `${s.type} key cannot be used for ${this.algorithm}`,
        });
        continue;
      }
      let privateBytes: Buffer;
      try {
        privateBytes = unseal(s.kid, s.privateMaterial, this.o.masterKey);
      } catch (e) {
        const detail = isAuthError(e)
          ? (e.details?.['violations'] as ConfigViolation[] | undefined)
          : undefined;
        v.push(...(detail ?? [{ path, rule: 'keys.decrypt', message: 'key could not be opened' }]));
        continue;
      }
      if (this.o.masterKey && !isSealed(s.privateMaterial) && !this.warnedPlaintext.has(s.kid)) {
        this.warnedPlaintext.add(s.kid);
        this.warn(
          `[aegis] signing key ${s.kid} is stored UNENCRYPTED although a master key is set; rotate it`,
        );
      }
      let material: KeyMaterial;
      if (this.algorithm === 'HS256') {
        material = { kid: s.kid, secret: privateBytes };
      } else {
        const privateKey = this.importPkcs8(privateBytes, path, v);
        if (!privateKey) continue;
        material = { kid: s.kid, privateKey };
      }
      const imported = importKey(this.algorithm, material, path, v);
      if (!imported) continue;
      if (this.algorithm === 'RS256') {
        const derived = publicJwkOf(imported.signing);
        if (
          !s.publicMaterial ||
          s.publicMaterial.n !== derived.n ||
          s.publicMaterial.e !== derived.e
        ) {
          v.push({
            path,
            rule: 'keys.public_mismatch',
            message: 'stored public key does not match the private key',
          });
          continue;
        }
      }
      next.set(s.kid, {
        kid: s.kid,
        status: s.status,
        createdAt: s.createdAt,
        ...(s.retiredAt !== null ? { retiredAt: s.retiredAt } : {}),
        ...imported,
      });
    }
    if ([...next.values()].filter((k) => k.status === 'active').length > 1) {
      v.push({ path: 'keys', rule: 'keys.one_active', message: 'more than one active key' });
    }
    if (v.length > 0) throw configInvalid(v);
    this.cache = next;
  }

  /** Stages a new key (pending): it verifies but does not sign. Returns its kid. */
  async stage(material?: KeyMaterial): Promise<string> {
    this.assertRotationEnabled();
    const m = material ?? this.generateMaterial();
    await this.persist(m);
    await this.refresh();
    return m.kid;
  }

  /** The pending key becomes the signer; the previous signer is retired now (atomic in the store). */
  async activate(kid: string): Promise<void> {
    this.assertRotationEnabled();
    await this.o.store.activate(kid, this.o.clock.now());
    await this.refresh();
  }

  /** Single-leader rotation: create and activate a new key atomically. Returns its kid. */
  async rotate(material?: KeyMaterial): Promise<string> {
    this.assertRotationEnabled();
    const m = material ?? this.generateMaterial();
    await this.o.store.atomically(async () => {
      await this.persist(m);
      await this.o.store.activate(m.kid, this.o.clock.now());
    });
    await this.refresh();
    return m.kid;
  }

  /**
   * Retires a key at `at` (default now). A future `at` is refused: a retired key vouches only for
   * tokens issued before its retirement, and a future retirement would let a leaked key mint tokens
   * until then. Retiring the active key without activating a replacement stops all signing.
   */
  async retire(kid: string, at?: Timestamp): Promise<boolean> {
    this.assertRotationEnabled();
    const now = this.o.clock.now();
    const retiredAt = at ?? now;
    if (!Number.isSafeInteger(retiredAt) || retiredAt > now) {
      throw authError('VALIDATION_FAILED', {
        details: { field: 'retiredAt', rule: 'key.retired_at_future' },
      });
    }
    const changed = await this.o.store.retire(kid, retiredAt);
    await this.refresh();
    return changed;
  }

  /** Removes a pending or retired key at once (compromise response). Its kid is never reused. */
  async remove(kid: string): Promise<void> {
    this.assertRotationEnabled();
    await this.o.store.remove(kid);
    await this.refresh();
  }

  /** Deletes retired keys whose verification window has ended. Returns the count. */
  async prune(): Promise<number> {
    // A retired key stops verifying once `now >= retiredAt + grace` (canVerifyAt), i.e. when
    // `retiredAt <= now - grace`; the store deletes `retiredAt < olderThan`, hence the + 1.
    const n = await this.o.store.prune(this.o.clock.now() - this.retiredKeyGraceMs + 1);
    await this.refresh();
    return n;
  }

  /** Stops the periodic refresh. */
  close(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  // ---------------------------------------------------------------- internals

  private importPkcs8(der: Buffer, path: string, v: ConfigViolation[]): KeyObject | null {
    try {
      return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    } catch {
      v.push({ path, rule: 'key.unreadable', message: 'private key could not be parsed' });
      return null;
    }
  }

  /** A fresh key: RSA-2048 or a 256-bit HMAC secret, with an unguessable, never-reused kid. */
  private generateMaterial(): KeyMaterial {
    const day = new Date(this.o.clock.now()).toISOString().slice(0, 10).replace(/-/g, '');
    const kid = `${this.algorithm.toLowerCase()}-${day}-${randomBytes(6).toString('hex')}`;
    if (this.algorithm === 'HS256') return { kid, secret: randomBytes(32) };
    return { kid, privateKey: generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey };
  }

  /** Validates material with the Phase 3 rules, seals the private half and creates a pending key. */
  private async persist(material: KeyMaterial): Promise<void> {
    const v: ConfigViolation[] = [];
    const imported = importKey(this.algorithm, material, 'key', v);
    if (!imported) {
      throw authError('VALIDATION_FAILED', {
        details: { field: 'key', rule: v[0]?.rule ?? 'key.invalid' },
      });
    }
    const privateBytes =
      this.algorithm === 'HS256'
        ? imported.signing.export()
        : imported.signing.export({ type: 'pkcs8', format: 'der' });
    await this.o.store.createKey(
      {
        kid: material.kid,
        type: TYPE_FOR[this.algorithm],
        publicMaterial: this.algorithm === 'RS256' ? publicJwkOf(imported.signing) : null,
        privateMaterial: seal(material.kid, privateBytes, this.o.masterKey),
      },
      { createdAt: this.o.clock.now() },
    );
  }

  /** At most one on-demand reload per second, triggered by an unseen kid; failures are ignored. */
  private refreshSoon(): void {
    const now = Date.now();
    if (this.refreshing || now - this.lastOnDemand < ON_DEMAND_REFRESH_MIN_MS) return;
    this.lastOnDemand = now;
    this.refreshing = this.refresh()
      .catch(() => undefined)
      .finally(() => {
        this.refreshing = null;
      });
  }

  private assertRotationEnabled(): void {
    if (!this.rotationEnabled) {
      throw authError('VALIDATION_FAILED', {
        details: { field: 'keys', rule: 'keys.rotation_disabled' },
      });
    }
  }

  private warn(message: string): void {
    try {
      (this.o.logger ?? console).warn(message);
    } catch {
      // A failing logger must not break key handling.
    }
  }
}

// ---------------------------------------------------------------- configuration and wiring

export interface PersistentJwtConfigInput {
  readonly tokens: JwtConfigInput['tokens'];
  readonly keys: {
    readonly rotationEnabled: boolean;
    /** Must name the adapter passed as `keyStore` ('memory' is for tests only). */
    readonly storage: 'postgres' | 'file' | 'memory';
    /** Create one key when the store is completely empty. Default false. */
    readonly generateIfMissing?: boolean;
    /** Environment variable holding the 32-byte master key. Default 'AEGIS_MASTER_KEY'. */
    readonly masterKeyEnvVar?: string;
    /** JWKS endpoint (RS256 only). */
    readonly jwks?: { readonly path?: string; readonly cacheTtlSec?: number };
    /** Keyring reload interval, 0..300 000 ms; 0 disables. Default 30 000. */
    readonly refreshIntervalMs?: number;
  };
}

export interface OpenJwtDeps {
  readonly keyStore: KeyStore;
  readonly clock: Clock;
  readonly ids: IdGenerator;
  /** Where the master key is read from. Default `process.env`; only the named variable is read. */
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly logger?: KeyLogger;
}

export interface OpenedJwt {
  readonly accessTokens: JwtAccessTokenProvider;
  readonly keys: PersistentKeyProvider;
  /** Null for HS256: shared secrets are never published. */
  readonly jwks: JwksHandler | null;
}

function violationsOf(e: unknown): ConfigViolation[] {
  if (!isAuthError(e) || e.code !== 'CONFIG_INVALID') throw e;
  return (e.details?.['violations'] as ConfigViolation[] | undefined) ?? [];
}

/**
 * Validates the configuration, reads the master key, opens the durable keyring and wires the JWT
 * provider (and, for RS256, the JWKS endpoint).
 *
 * Master key policy: PostgreSQL REQUIRES it — a shared database never holds plaintext private keys,
 * and the schema rejects them too. The file and memory stores accept its absence for local
 * development and log an explicit warning.
 *
 * @throws CONFIG_INVALID listing every violation.
 */
export async function openJwtAccessTokens(
  input: PersistentJwtConfigInput,
  deps: OpenJwtDeps,
): Promise<OpenedJwt> {
  const v: ConfigViolation[] = [];
  let base: ReturnType<typeof resolveJwtConfig> | null = null;
  try {
    base = resolveJwtConfig({
      tokens: input?.tokens,
      keys: { rotationEnabled: input?.keys?.rotationEnabled },
    });
  } catch (e) {
    v.push(...violationsOf(e));
  }
  const k = input?.keys ?? ({} as Partial<PersistentJwtConfigInput['keys']>);
  if (k.storage !== 'postgres' && k.storage !== 'file' && k.storage !== 'memory') {
    v.push({
      path: 'keys.storage',
      rule: 'keys.storage',
      message: "must be 'postgres', 'file' or 'memory'",
    });
  } else if (k.storage !== deps.keyStore.kind) {
    v.push({
      path: 'keys.storage',
      rule: 'keys.storage_mismatch',
      message: `configured '${k.storage}' but the key store is '${deps.keyStore.kind}'`,
    });
  }
  const generateIfMissing = k.generateIfMissing ?? false;
  if (typeof generateIfMissing !== 'boolean') {
    v.push({ path: 'keys.generateIfMissing', rule: 'keys.generate', message: 'must be a boolean' });
  }
  const envVar = k.masterKeyEnvVar ?? 'AEGIS_MASTER_KEY';
  if (typeof envVar !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(envVar)) {
    v.push({
      path: 'keys.masterKeyEnvVar',
      rule: 'keys.master_key_var',
      message: 'must be an environment variable name',
    });
  }
  const refreshIntervalMs = k.refreshIntervalMs ?? 30_000;
  if (
    !Number.isInteger(refreshIntervalMs) ||
    refreshIntervalMs < 0 ||
    refreshIntervalMs > 300_000
  ) {
    v.push({
      path: 'keys.refreshIntervalMs',
      rule: 'keys.refresh',
      message: 'must be an integer in 0..300000',
    });
  }
  if (input?.tokens?.algorithm === 'HS256' && k.jwks !== undefined) {
    v.push({
      path: 'keys.jwks',
      rule: 'jwks.hmac',
      message: 'HS256 secrets cannot be published; remove keys.jwks or use RS256',
    });
  }

  // The master key: only the named variable is read, and its value never appears in any message.
  let masterKey: Buffer | null = null;
  const raw = typeof envVar === 'string' ? (deps.env ?? process.env)[envVar] : undefined;
  if (raw !== undefined && raw.trim() !== '') {
    try {
      masterKey = parseMasterKey(raw, envVar);
    } catch (e) {
      v.push(...violationsOf(e));
    }
  } else if (deps.keyStore.kind === 'postgres') {
    v.push({
      path: envVar,
      rule: 'keys.master_key_required',
      message: `the PostgreSQL key store requires a master key in ${envVar}; private keys are never stored in plaintext`,
    });
  }
  if (v.length > 0 || !base) throw configInvalid(v);

  const logger = deps.logger ?? console;
  if (!masterKey) {
    logger.warn(
      `[aegis] ${envVar} is not set: private signing keys are stored UNENCRYPTED in the ` +
        `${deps.keyStore.kind} key store. This is acceptable for local development only.`,
    );
  }

  const keys = await PersistentKeyProvider.open({
    store: deps.keyStore,
    algorithm: base.tokens.algorithm,
    rotationEnabled: base.keys.rotationEnabled,
    retiredKeyGraceMs: base.tokens.ttl + base.tokens.leewayMs,
    generateIfMissing,
    masterKey,
    clock: deps.clock,
    refreshIntervalMs,
    logger,
  });
  try {
    const accessTokens = new JwtAccessTokenProvider(base, keys, deps.ids);
    const jwks =
      base.tokens.algorithm === 'RS256'
        ? createJwksHandler(keys, {
            ...(k.jwks?.path !== undefined ? { path: k.jwks.path } : {}),
            ...(k.jwks?.cacheTtlSec !== undefined ? { cacheTtlSec: k.jwks.cacheTtlSec } : {}),
            clock: deps.clock,
          })
        : null;
    return { accessTokens, keys, jwks };
  } catch (e) {
    keys.close();
    throw e;
  }
}
