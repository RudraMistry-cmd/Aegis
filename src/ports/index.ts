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
  issue(input: AccessTokenInput, now: Timestamp): IssuedAccessToken;
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
