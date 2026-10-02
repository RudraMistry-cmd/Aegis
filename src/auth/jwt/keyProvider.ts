// Implements spec/auth/tokens.md §6: signing keys, key identifiers (kid) and key rotation for the
// JWT access-token provider.
//
// KEY LIFECYCLE
//   pending  — verifies, never signs. Spec §6.2 step 1: in a multi-process deployment a new key is
//              first staged everywhere, so every instance can verify tokens signed with it before
//              any instance starts signing with it.
//   active   — the single signing key. Also verifies.
//   retired  — verifies only (a) for `retiredKeyGraceMs` after retirement, which is at least
//              accessTtl + leeway, so every token it signed can live out its lifetime and no longer
//              (spec §6.2 steps 3-4); and (b) for tokens issued before it was retired, so a leaked
//              old key cannot be used to mint fresh tokens.
//   (removed) — gone; its kid can never be reused, so an old token cannot be re-validated by a
//              different key that happens to share its kid.
//
// Key material never leaves this module except as a node:crypto KeyObject handed to the signer and
// verifier. `list()` exposes metadata only, and no error message contains material (spec §6.3).
import { createPrivateKey, createPublicKey, createSecretKey, type KeyObject } from 'node:crypto';
import type { Timestamp } from '../../domain/index.js';
import { authError, configInvalid, type ConfigViolation } from '../../errors/index.js';
import type { Clock } from '../../ports/index.js';

export type JwtAlgorithm = 'HS256' | 'RS256';
export type KeyStatus = 'pending' | 'active' | 'retired';

/** Key metadata, safe to log or display. Never contains material. */
export interface KeyInfo {
  readonly kid: string;
  readonly algorithm: JwtAlgorithm;
  readonly status: KeyStatus;
  readonly createdAt: Timestamp;
  readonly retiredAt?: Timestamp;
}

/** The key used to sign new tokens. */
export interface SigningKey {
  readonly kid: string;
  readonly algorithm: JwtAlgorithm;
  readonly key: KeyObject;
}

/** A key acceptable for verification at a given instant. */
export interface VerificationKey {
  readonly kid: string;
  readonly algorithm: JwtAlgorithm;
  readonly key: KeyObject;
  readonly status: KeyStatus;
  readonly retiredAt?: Timestamp;
}

/** The KeyProvider contract the JWT provider depends on (spec/auth/tokens.md §6). */
export interface KeyProvider {
  /** Every key of a provider uses this one algorithm (spec §2.6.2: no algorithm mixing). */
  readonly algorithm: JwtAlgorithm;
  /** How long a retired key keeps verifying; the JWT provider requires >= accessTtl + leeway. */
  readonly retiredKeyGraceMs: number;
  /** The single signing key. */
  getActiveKey(): SigningKey;
  /** The key for `kid` if it may verify at `now`; null for unknown, removed or expired keys. */
  getKeyById(kid: string, now: Timestamp): VerificationKey | null;
  /** Every key that may verify at `now` — exactly what a JWKS document may publish. */
  verificationKeys(now: Timestamp): readonly VerificationKey[];
}

/** Key material: an HMAC secret for HS256, an RSA private key (PEM or KeyObject) for RS256. */
export type KeyMaterial =
  | { readonly kid: string; readonly secret: string | Uint8Array }
  | { readonly kid: string; readonly privateKey: string | KeyObject };

/** A key supplied at construction, e.g. reloaded from a secret manager after a restart. */
export type KeyInput = KeyMaterial & {
  readonly status?: KeyStatus;
  readonly createdAt?: Timestamp;
  readonly retiredAt?: Timestamp;
};

export interface InMemoryKeyProviderOptions {
  readonly algorithm: JwtAlgorithm;
  readonly keys: readonly KeyInput[];
  /** When false, exactly one key is allowed and every rotation operation is refused. */
  readonly rotationEnabled: boolean;
  /** How long a retired key keeps verifying. Must be >= accessTtl + leeway. */
  readonly retiredKeyGraceMs: number;
  readonly clock: Clock;
}

const KID_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const MIN_HMAC_BYTES = 32;
const MIN_RSA_BITS = 2048;
const PLACEHOLDER_RE =
  /^(?:changeme|change-me|secret|password|test|default|example|placeholder)+$/i;

interface KeyEntry {
  readonly kid: string;
  status: KeyStatus;
  readonly createdAt: Timestamp;
  retiredAt?: Timestamp;
  readonly signing: KeyObject;
  readonly verification: KeyObject;
}

/**
 * Validates and imports key material. Pushes violations (never including material) and returns
 * null when the material is unusable. Shared by every key provider, so the rules are one rule set.
 */
export function importKey(
  algorithm: JwtAlgorithm,
  material: KeyMaterial,
  path: string,
  v: ConfigViolation[],
): { signing: KeyObject; verification: KeyObject } | null {
  if (typeof material.kid !== 'string' || !KID_RE.test(material.kid)) {
    v.push({ path, rule: 'key.kid', message: 'kid must match [A-Za-z0-9_.-]{1,64}' });
    return null;
  }
  if (algorithm === 'HS256') {
    if (!('secret' in material) || material.secret === undefined) {
      v.push({ path, rule: 'key.algorithm_mismatch', message: 'HS256 keys need a secret' });
      return null;
    }
    const bytes =
      typeof material.secret === 'string'
        ? Buffer.from(material.secret, 'utf8')
        : Buffer.from(material.secret);
    if (bytes.length < MIN_HMAC_BYTES) {
      v.push({
        path,
        rule: 'key.min_length',
        message: `HS256 secrets need >= ${MIN_HMAC_BYTES} bytes`,
      });
      return null;
    }
    if (new Set(bytes).size < 8 || PLACEHOLDER_RE.test(bytes.toString('utf8'))) {
      v.push({ path, rule: 'key.placeholder', message: 'weak or placeholder secret rejected' });
      return null;
    }
    const key = createSecretKey(bytes);
    return { signing: key, verification: key };
  }

  // RS256
  if (!('privateKey' in material) || material.privateKey === undefined) {
    v.push({ path, rule: 'key.algorithm_mismatch', message: 'RS256 keys need an RSA private key' });
    return null;
  }
  let privateKey: KeyObject;
  try {
    privateKey =
      typeof material.privateKey === 'string'
        ? createPrivateKey(material.privateKey)
        : material.privateKey;
  } catch {
    v.push({ path, rule: 'key.unreadable', message: 'private key could not be parsed' });
    return null;
  }
  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'rsa') {
    v.push({ path, rule: 'key.type', message: 'RS256 needs an RSA private key' });
    return null;
  }
  const bits = privateKey.asymmetricKeyDetails?.modulusLength ?? 0;
  if (bits < MIN_RSA_BITS) {
    v.push({ path, rule: 'key.min_length', message: `RSA keys need >= ${MIN_RSA_BITS} bits` });
    return null;
  }
  return { signing: privateKey, verification: createPublicKey(privateKey) };
}

/**
 * The verification window of spec §6.2: pending and active keys verify; a retired key verifies only
 * while `now < retiredAt + graceMs` (grace = ttl + leeway). The one definition used by every provider.
 */
export function canVerifyAt(
  status: KeyStatus,
  retiredAt: Timestamp | undefined,
  now: Timestamp,
  graceMs: number,
): boolean {
  if (status !== 'retired') return true;
  return retiredAt !== undefined && now < retiredAt + graceMs;
}

/** Throws the single violation of a runtime (admin) key operation as VALIDATION_FAILED. */
function rejectRuntime(v: readonly ConfigViolation[]): never {
  throw authError('VALIDATION_FAILED', {
    details: { field: 'key', rule: v[0]?.rule ?? 'key.invalid' },
  });
}

/**
 * In-process key store with rotation. Keys come from configuration or a secret manager; this class
 * never persists them. In a multi-process deployment, distribute a new key to every instance with
 * `stage`, then call `activate` (spec §6.2); a single process may simply `rotate`.
 */
export class InMemoryKeyProvider implements KeyProvider {
  readonly algorithm: JwtAlgorithm;
  readonly rotationEnabled: boolean;
  readonly retiredKeyGraceMs: number;
  private readonly clock: Clock;
  private readonly entries = new Map<string, KeyEntry>();
  /** Every kid ever accepted, including removed ones: a kid is never reused. */
  private readonly everSeen = new Set<string>();

  /** @throws CONFIG_INVALID listing every violation. */
  constructor(options: InMemoryKeyProviderOptions) {
    const v: ConfigViolation[] = [];
    if (options.algorithm !== 'HS256' && options.algorithm !== 'RS256') {
      v.push({ path: 'keys.algorithm', rule: 'key.algorithm', message: 'must be HS256 or RS256' });
    }
    if (typeof options.rotationEnabled !== 'boolean') {
      v.push({ path: 'keys.rotationEnabled', rule: 'keys.rotation', message: 'must be a boolean' });
    }
    if (!Number.isInteger(options.retiredKeyGraceMs) || options.retiredKeyGraceMs < 0) {
      v.push({
        path: 'keys.retiredKeyGraceMs',
        rule: 'keys.grace',
        message: 'must be an integer >= 0',
      });
    }
    const keys = options.keys ?? [];
    if (keys.length === 0) {
      v.push({ path: 'keys', rule: 'keys.required', message: 'at least one key is required' });
    }
    if (options.rotationEnabled === false && keys.length > 1) {
      v.push({
        path: 'keys',
        rule: 'keys.rotation_disabled',
        message: 'exactly one key when rotation is disabled',
      });
    }
    const now = options.clock.now();
    keys.forEach((k, i) => {
      const path = `keys[${i}]`;
      const status: KeyStatus = k.status ?? (keys.length === 1 ? 'active' : 'pending');
      if (status !== 'pending' && status !== 'active' && status !== 'retired') {
        v.push({ path, rule: 'key.status', message: 'status must be pending, active or retired' });
        return;
      }
      if (this.everSeen.has(k.kid)) {
        v.push({ path, rule: 'key.kid_unique', message: 'duplicate kid' });
        return;
      }
      const imported = importKey(options.algorithm, k, path, v);
      if (!imported) return;
      this.everSeen.add(k.kid);
      this.entries.set(k.kid, {
        kid: k.kid,
        status,
        createdAt: k.createdAt ?? now,
        // A retired key reloaded without its retirement time is assumed retired now: it then
        // verifies for one more full grace window — conservative, never shorter than needed.
        ...(status === 'retired' ? { retiredAt: k.retiredAt ?? now } : {}),
        ...imported,
      });
    });
    const active = [...this.entries.values()].filter((e) => e.status === 'active');
    if (keys.length > 0 && active.length !== 1) {
      v.push({ path: 'keys', rule: 'keys.one_active', message: 'exactly one key must be active' });
    }
    if (v.length > 0) throw configInvalid(v);

    this.algorithm = options.algorithm;
    this.rotationEnabled = options.rotationEnabled;
    this.retiredKeyGraceMs = options.retiredKeyGraceMs;
    this.clock = options.clock;
  }

  getActiveKey(): SigningKey {
    for (const e of this.entries.values()) {
      if (e.status === 'active') return { kid: e.kid, algorithm: this.algorithm, key: e.signing };
    }
    // Unreachable: construction and every operation keep exactly one active key.
    throw authError('INTERNAL');
  }

  getKeyById(kid: string, now: Timestamp): VerificationKey | null {
    const e = this.entries.get(kid);
    if (!e) return null;
    if (!canVerifyAt(e.status, e.retiredAt, now, this.retiredKeyGraceMs)) return null;
    return {
      kid: e.kid,
      algorithm: this.algorithm,
      key: e.verification,
      status: e.status,
      ...(e.retiredAt !== undefined ? { retiredAt: e.retiredAt } : {}),
    };
  }

  verificationKeys(now: Timestamp): readonly VerificationKey[] {
    return [...this.entries.keys()]
      .map((kid) => this.getKeyById(kid, now))
      .filter((k): k is VerificationKey => k !== null);
  }

  /** Metadata of every key still held. Never contains material. */
  list(): readonly KeyInfo[] {
    return [...this.entries.values()].map((e) => ({
      kid: e.kid,
      algorithm: this.algorithm,
      status: e.status,
      createdAt: e.createdAt,
      ...(e.retiredAt !== undefined ? { retiredAt: e.retiredAt } : {}),
    }));
  }

  /** Spec §6.2 step 1: adds a key that verifies but does not sign yet. */
  stage(material: KeyMaterial): void {
    this.assertRotationEnabled();
    if (this.everSeen.has(material.kid)) {
      rejectRuntime([{ path: 'key', rule: 'key.kid_reused', message: 'kid already used' }]);
    }
    const v: ConfigViolation[] = [];
    const imported = importKey(this.algorithm, material, 'key', v);
    if (!imported) rejectRuntime(v);
    this.everSeen.add(material.kid);
    this.entries.set(material.kid, {
      kid: material.kid,
      status: 'pending',
      createdAt: this.clock.now(),
      ...imported,
    });
  }

  /** Spec §6.2 step 2: the pending key becomes the signer; the previous signer is retired. */
  activate(kid: string): void {
    this.assertRotationEnabled();
    const next = this.entries.get(kid);
    if (!next || next.status !== 'pending') {
      rejectRuntime([
        { path: 'key', rule: 'key.not_pending', message: 'only a pending key can be activated' },
      ]);
    }
    const now = this.clock.now();
    for (const e of this.entries.values()) {
      if (e.status === 'active') {
        e.status = 'retired';
        e.retiredAt = now;
      }
    }
    next.status = 'active';
  }

  /** Single-process rotation: stage and activate in one step. */
  rotate(material: KeyMaterial): void {
    this.stage(material);
    this.activate(material.kid);
  }

  /**
   * Removes a pending or retired key immediately — the response to a suspected key compromise.
   * Tokens it signed stop verifying at once. The active key cannot be removed; rotate first.
   */
  remove(kid: string): void {
    this.assertRotationEnabled();
    const e = this.entries.get(kid);
    if (!e) return; // idempotent
    if (e.status === 'active') {
      rejectRuntime([
        { path: 'key', rule: 'key.active_not_removable', message: 'rotate before removing' },
      ]);
    }
    this.entries.delete(kid);
  }

  /** Spec §6.2 step 4: drops retired keys whose grace window has ended. Returns the count. */
  prune(now: Timestamp = this.clock.now()): number {
    let n = 0;
    for (const [kid, e] of [...this.entries]) {
      if (!canVerifyAt(e.status, e.retiredAt, now, this.retiredKeyGraceMs)) {
        this.entries.delete(kid);
        n += 1;
      }
    }
    return n;
  }

  private assertRotationEnabled(): void {
    if (!this.rotationEnabled) {
      rejectRuntime([
        { path: 'keys', rule: 'keys.rotation_disabled', message: 'rotation is disabled' },
      ]);
    }
  }
}
