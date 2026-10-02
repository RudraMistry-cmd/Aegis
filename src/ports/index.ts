// Implements spec/storage/interfaces.md: storage and supporting port contracts (interfaces only).
//
// Failure convention: adapter-level failures (§1.1) are thrown as AuthError with the mapped code
// (CONFLICT, PRECONDITION_FAILED, NOT_FOUND, STORAGE_UNAVAILABLE, VALIDATION_FAILED). Normal
// alternative outcomes (e.g. `consume` results, `LimitReached`) are returned as values.
import type {
  ConsumeResult,
  Credential,
  DeviceInfo,
  Identifier,
  Id,
  NewRefreshToken,
  NewSession,
  NewUser,
  RefreshRevokedReason,
  RefreshTokenRecord,
  RevocationReason,
  RoleAssignment,
  Session,
  Timestamp,
  User,
  Json,
} from '../domain/index.js';

// ---------------------------------------------------------------- supporting ports (§9)

/** §9.1 Clock. Production implementations return UTC time; tests inject a controllable fake. */
export interface Clock {
  now(): Timestamp;
}

/** §9.2 Random. MUST be cryptographically secure in production. */
export interface Random {
  bytes(n: number): Uint8Array;
}

/** §9.3 IdGenerator. */
export interface IdGenerator {
  newId(): Id;
}

/** §9.4 PasswordHasher. */
export interface PasswordHasher {
  hash(password: string): Promise<string>;
  /** MUST NOT throw on malformed `encoded`; returns false. */
  verify(password: string, encoded: string): Promise<boolean>;
  needsRehash(encoded: string): boolean;
  /** Performs work equal in cost to a real verify (enumeration/timing resistance). */
  dummyVerify(password: string): Promise<void>;
}

/** §9.8 RateLimiter (login throttling). */
export interface RateLimiter {
  peek(
    key: string,
    now: Timestamp,
  ): Promise<{ blocked: boolean; retryAfterMs?: number; failures: number }>;
  recordFailure(key: string, now: Timestamp): Promise<void>;
  reset(key: string): Promise<void>;
}

/** §9.6 AttributeProvider (principal.md §2.3). */
export interface AttributeProvider {
  attributesFor(
    userId: Id,
    now: Timestamp,
  ): Promise<{ tenantId?: Id; attributes: Record<string, Json> }>;
}

/** §10 Audit. */
export type AuditSeverity = 'info' | 'notice' | 'warning' | 'high';

export interface AuditEvent {
  readonly id: Id;
  readonly type: string;
  readonly at: Timestamp;
  readonly severity: AuditSeverity;
  readonly actor: { readonly id?: Id; readonly type?: string; readonly sessionId?: Id };
  readonly target: { readonly type?: string; readonly id?: Id };
  readonly outcome: 'success' | 'failure' | 'denied';
  readonly reason?: string;
  readonly context: {
    readonly requestId?: string;
    readonly ip?: string;
    readonly userAgent?: string;
  };
  readonly details: Readonly<Record<string, Json>>;
}

/** Append-only from the core's viewpoint (§10.1). */
export interface AuditSink {
  write(event: AuditEvent): void | Promise<void>;
}

// ---------------------------------------------------------------- access-token provider (tokens.md §2.2)

export interface AccessTokenInput {
  readonly subjectId: Id;
  readonly sessionId: Id;
  readonly securityVersion: number;
  readonly ttlMs: number;
}

export interface IssuedAccessToken {
  readonly token: string;
  readonly jti: Id;
  readonly issuedAt: Timestamp;
  readonly expiresAt: Timestamp;
}

export interface VerifiedAccessToken {
  readonly subjectId: Id;
  readonly sessionId: Id;
  readonly securityVersion: number;
  readonly jti: Id;
  readonly issuedAt: Timestamp;
  readonly expiresAt: Timestamp;
}

export type VerifyFailure =
  | 'malformed'
  | 'bad_signature'
  | 'unknown_key'
  | 'expired'
  | 'not_yet_valid'
  | 'wrong_issuer'
  | 'wrong_audience'
  | 'wrong_type'
  | 'unsupported_algorithm';

/** `verify` MUST NOT throw for any input. */
export interface AccessTokenProvider {
  /**
   * The lifetime this provider issues, when it fixes one. createAuth then requires the core's
   * `tokens.accessTtlMs` to equal it (tokens.md §2.3.1: exp − iat equals the configured TTL).
   */
  readonly ttlMs?: number;
  issue(input: AccessTokenInput, now: Timestamp): IssuedAccessToken;
  /**
   * Proves only that this server issued the token and that it is unexpired. It is NEVER sufficient
   * on its own: request resolution must then apply strict revocation (tokens.md §2.5).
   */
  verify(
    token: string,
    now: Timestamp,
  ): { ok: true; token: VerifiedAccessToken } | { ok: false; failure: VerifyFailure };
}

// ---------------------------------------------------------------- storage ports (§2-§8)

export interface Page<T> {
  readonly items: readonly T[];
  readonly nextCursor?: string;
}
export interface PageReq {
  readonly limit: number;
  readonly cursor?: string;
}

/** §2 UserStore. */
export interface UserStore {
  create(user: NewUser): Promise<User>;
  getById(id: Id): Promise<User | null>;
  setStatus(id: Id, to: string, expectedVersion: number, now: Timestamp): Promise<User>;
  bumpSecurityVersion(id: Id, now: Timestamp): Promise<number>;
  updateMetadata(
    id: Id,
    patch: Record<string, Json>,
    expectedVersion: number | undefined,
    now: Timestamp,
  ): Promise<User>;
  delete(id: Id): Promise<void>;
}

/** §3 IdentifierStore. */
export interface IdentifierStore {
  add(
    userId: Id,
    type: string,
    value: string,
    normalized: string,
    verified: boolean,
    now: Timestamp,
  ): Promise<Identifier>;
  findByNormalized(type: string, normalized: string): Promise<Identifier | null>;
  listByUser(userId: Id): Promise<readonly Identifier[]>;
  markVerified(identifierId: Id, now: Timestamp): Promise<void>;
  remove(identifierId: Id): Promise<void>;
}

/** §4 CredentialStore. */
export interface CredentialStore {
  get(userId: Id, type: string): Promise<Credential | null>;
  put(userId: Id, type: string, payload: string, now: Timestamp): Promise<Credential>;
  touch(credentialId: Id, at: Timestamp): Promise<void>;
  delete(userId: Id, type: string): Promise<void>;
}

export type CreateWithLimitResult =
  | { readonly kind: 'created'; readonly session: Session; readonly evicted: readonly Id[] }
  | { readonly kind: 'limit_reached' };

/** §5 SessionStore. */
export interface SessionStore {
  createWithLimit(
    session: NewSession,
    limit: number | null,
    policy: 'evict-oldest' | 'reject',
    now: Timestamp,
  ): Promise<CreateWithLimitResult>;
  get(id: Id): Promise<Session | null>;
  listActiveByUser(userId: Id, page: PageReq, now: Timestamp): Promise<Page<Session>>;
  /** True iff this call revoked it (first reason wins; later calls return false). */
  revoke(id: Id, reason: RevocationReason, now: Timestamp): Promise<boolean>;
  revokeAllForUser(
    userId: Id,
    except: Id | null,
    reason: RevocationReason,
    now: Timestamp,
  ): Promise<number>;
  /** True iff applied. Never shrinks idle expiry, never exceeds absolute expiry, never touches revoked. */
  touch(id: Id, now: Timestamp, newIdleExpiresAt: Timestamp): Promise<boolean>;
  countActive(userId: Id, now: Timestamp): Promise<number>;
  // TODO(spec/storage/interfaces.md §5.7): deleteTerminalBefore (housekeeping) is not implemented in Phase 1.
}

/** §6 RefreshTokenStore. */
export interface RefreshTokenStore {
  insert(record: NewRefreshToken): Promise<void>;
  /** Atomic; see storage/interfaces.md §6.1 for the precedence. */
  consume(hash: string, now: Timestamp): Promise<ConsumeResult>;
  rotate(consumedTokenId: Id, successor: NewRefreshToken): Promise<void>;
  replaceActiveSuccessor(
    oldSuccessorId: Id,
    replacement: NewRefreshToken,
    parentId: Id,
  ): Promise<'replaced' | 'not_active'>;
  revokeFamily(sessionId: Id, reason: RefreshRevokedReason): Promise<number>;
  getById(id: Id): Promise<RefreshTokenRecord | null>;
  // TODO(spec/storage/interfaces.md §6.8): deleteTerminalBefore (housekeeping) is not implemented in Phase 1.
}

/** §8.2 AssignmentStore. */
export interface AssignmentStore {
  assign(a: RoleAssignment, now: Timestamp): Promise<'created' | 'unchanged' | 'updated'>;
  unassign(subjectId: Id, roleName: string, scope: RoleAssignment['scope']): Promise<boolean>;
  listActive(subjectId: Id, now: Timestamp): Promise<readonly RoleAssignment[]>;
  listSubjectsByRole(roleName: string, page: PageReq, now: Timestamp): Promise<Page<Id>>;
  removeAllForSubject(subjectId: Id): Promise<number>;
}

/** §8.1 RoleCatalogStore (mirror only; the evaluated catalog is immutable code/config). */
export interface RoleCatalogStore {
  sync(
    snapshot: { version: string; roles: readonly string[]; permissions: readonly string[] },
    now: Timestamp,
  ): Promise<void>;
  getCatalogVersion(): Promise<string | null>;
  // TODO(spec/storage/interfaces.md §8.1): dynamic role methods are out of Phase 1 scope.
}

// ---------------------------------------------------------------- signing-key store (tokens.md §6)

export type StoredKeyType = 'RSA' | 'HMAC';
export type StoredKeyStatus = 'pending' | 'active' | 'retired';

/** Public members of an RSA JWK. Never contains private members (d, p, q, dp, dq, qi). */
export interface PublicJwkMaterial {
  readonly kty: 'RSA';
  readonly n: string;
  readonly e: string;
}

/** What `createKey` persists. `privateMaterial` is a sealed envelope (see keySealing.ts). */
export interface KeyStoreMaterial {
  readonly kid: string;
  readonly type: StoredKeyType;
  /** RSA: the public JWK members, published by JWKS. HMAC: null — a secret is never public. */
  readonly publicMaterial: PublicJwkMaterial | null;
  /** Opaque sealed bytes. Encrypted when a master key is configured; the store never inspects it. */
  readonly privateMaterial: Uint8Array;
}

export interface StoredKey extends KeyStoreMaterial {
  readonly status: StoredKeyStatus;
  readonly createdAt: Timestamp;
  readonly activatedAt: Timestamp | null;
  readonly retiredAt: Timestamp | null;
  readonly metadata: Readonly<Record<string, Json>>;
}

/**
 * Durable signing keys. Lifecycle (never reversed): pending → active → retired, or pending → retired.
 *
 * - `createKey` always creates a PENDING key. A kid is registered forever: reusing one — even after
 *   `remove` — is CONFLICT, so an old token can never be re-validated by a different key.
 * - `activate` is atomic: the kid becomes the single active key and the previous active key is
 *   retired at the same instant. Activating the already-active kid is a no-op; a retired kid can
 *   never be activated again (PRECONDITION_FAILED). `now` earlier than the key's createdAt or the
 *   current key's activatedAt (clock skew between instances) is VALIDATION_FAILED, changing nothing.
 * - `markPending` exists only to assert that a key is (still) pending; no key can RETURN to pending,
 *   because a retired key that could be re-staged could be re-activated after a compromise.
 * - `retire` sets `retiredAt` once; repeating it is a no-op that returns false.
 * - `remove` refuses the active key; `prune` deletes retired keys retired before `olderThan`.
 * - `atomically` runs `fn` holding the keyring lock, with every call inside it applied atomically
 *   (one database transaction, or serialized in-process). Startup generation uses it so concurrent
 *   instances on an empty store create exactly one key.
 * Every mutation above is individually atomic; at most one key is active at any instant.
 */
export interface KeyStore {
  /** Which adapter this is; the configuration must name the same one. */
  readonly kind: 'postgres' | 'file' | 'memory';
  createKey(
    material: KeyStoreMaterial,
    meta: { readonly createdAt: Timestamp; readonly metadata?: Record<string, Json> },
  ): Promise<StoredKey>;
  getActiveKey(): Promise<StoredKey | null>;
  getKeyById(kid: string): Promise<StoredKey | null>;
  /** Ordered by createdAt, then kid. */
  listKeys(): Promise<readonly StoredKey[]>;
  markPending(kid: string): Promise<void>;
  activate(
    kid: string,
    now: Timestamp,
  ): Promise<{ readonly activated: string; readonly retired: string | null }>;
  retire(kid: string, retiredAt: Timestamp): Promise<boolean>;
  remove(kid: string): Promise<void>;
  prune(olderThan: Timestamp): Promise<number>;
  atomically<T>(fn: () => Promise<T>): Promise<T>;
}

/** All stores bound together (one transaction handle or the non-transactional set). */
export interface StoreSet {
  readonly users: UserStore;
  readonly identifiers: IdentifierStore;
  readonly credentials: CredentialStore;
  readonly sessions: SessionStore;
  readonly refreshTokens: RefreshTokenStore;
  readonly assignments: AssignmentStore;
  readonly roles: RoleCatalogStore;
}

/** §11 UnitOfWork. `fn` MUST be free of external side effects. */
export interface UnitOfWork {
  run<T>(fn: (tx: StoreSet) => Promise<T>): Promise<T>;
}

/** Storage bundle returned by an adapter. */
export interface Storage extends StoreSet {
  readonly uow: UnitOfWork;
}

export type { DeviceInfo };
