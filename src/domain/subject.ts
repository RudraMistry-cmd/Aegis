// Implements spec/auth/principal.md §1-§2: Subject and Principal contracts.
import { authError } from '../errors/index.js';
import {
  deepFreeze,
  isValidId,
  isValidSubjectType,
  type Id,
  type Json,
  type Timestamp,
} from './types.js';

/** The only representation of "who" that authorization may consume (principal.md §1). */
export interface Subject {
  readonly id: Id;
  readonly type: string;
  readonly tenantId?: Id;
  readonly attributes?: Readonly<Record<string, Json>>;
}

/** A Subject authenticated for the current operation (principal.md §2). */
export interface Principal extends Subject {
  readonly authMethod: string;
  readonly authenticatedAt: Timestamp;
  readonly sessionId?: Id;
  readonly amr?: readonly string[];
  readonly claims?: Readonly<Record<string, Json>>;
}

const ATTR_KEY_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const MAX_ATTRIBUTES_BYTES = 8 * 1024;

function violation(field: string, rule: string): never {
  throw authError('VALIDATION_FAILED', { details: { field, rule } });
}

/**
 * Validates and freezes a Subject (principal.md §1.1). Throws VALIDATION_FAILED.
 * The result is an immutable deep copy.
 */
export function createSubject(input: {
  id: Id;
  type: string;
  tenantId?: Id;
  attributes?: Record<string, Json>;
}): Subject {
  if (!isValidId(input.id)) violation('id', 'subject.id');
  if (!isValidSubjectType(input.type)) violation('type', 'subject.type');
  if (input.tenantId !== undefined && !isValidId(input.tenantId))
    violation('tenantId', 'subject.tenant');
  let attributes: Record<string, Json> | undefined;
  if (input.attributes !== undefined) {
    for (const k of Object.keys(input.attributes)) {
      if (!ATTR_KEY_RE.test(k)) violation('attributes', 'subject.attribute_key');
    }
    const copy = JSON.parse(JSON.stringify(input.attributes)) as Record<string, Json>;
    if (Buffer.byteLength(JSON.stringify(copy), 'utf8') > MAX_ATTRIBUTES_BYTES) {
      violation('attributes', 'subject.attributes_size');
    }
    attributes = copy;
  }
  return deepFreeze({
    id: input.id,
    type: input.type,
    ...(input.tenantId !== undefined ? { tenantId: input.tenantId } : {}),
    ...(attributes !== undefined ? { attributes } : {}),
  });
}

/**
 * Non-throwing structural check used by the authorization engine (Stage 0.1).
 * Returns the projected Subject, or null when invalid (decision: deny invalid_subject).
 */
export function projectSubject(input: unknown): Subject | null {
  if (input === null || typeof input !== 'object') return null;
  const s = input as Partial<Subject>;
  if (!isValidId(s.id) || !isValidSubjectType(s.type)) return null;
  if (s.tenantId !== undefined && !isValidId(s.tenantId)) return null;
  try {
    return createSubject({
      id: s.id,
      type: s.type,
      ...(s.tenantId !== undefined ? { tenantId: s.tenantId } : {}),
      ...(s.attributes !== undefined ? { attributes: s.attributes as Record<string, Json> } : {}),
    });
  } catch {
    return null;
  }
}

/** Principal -> Subject projection (principal.md §2.2): drops all authentication fields. */
export function toSubject(p: Subject): Subject {
  return projectSubject(p) ?? createSubject({ id: p.id, type: p.type });
}
