// Implements spec/auth/principal.md §0: primitive types and shared validators.

/** Opaque identifier (spec/auth/principal.md §0). */
export type Id = string;
/** Instant as milliseconds since the Unix epoch (UTC). */
export type Timestamp = number;
/** Non-negative integer number of milliseconds. */
export type Duration = number;
/** JSON value restricted per spec/auth/principal.md §0. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

const ID_RE = /^[A-Za-z0-9_\-.:~]{1,128}$/;
const SUBJECT_TYPE_RE = /^[a-z][a-z0-9_-]{0,31}$/;

/** True when `v` is a syntactically valid Id. */
export function isValidId(v: unknown): v is Id {
  return typeof v === 'string' && ID_RE.test(v);
}

/** True when `v` is a valid SubjectType (spec/auth/principal.md §1). */
export function isValidSubjectType(v: unknown): v is string {
  return typeof v === 'string' && SUBJECT_TYPE_RE.test(v);
}

/** Length counted in Unicode scalar values, not UTF-16 units or bytes. */
export function scalarLength(s: string): number {
  let n = 0;
  for (const _ of s) n++;
  return n;
}

/** Recursively freezes a value (used for immutable Subjects/Principals/catalogs). */
export function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const v of Object.values(value as Record<string, unknown>)) deepFreeze(v);
  }
  return value;
}
