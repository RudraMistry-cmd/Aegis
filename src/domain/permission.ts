// Implements spec/rbac/permissions.md §1-§5: permission/pattern grammar, matching, coverage.

const SEGMENT_RE = /^[a-z][a-z0-9_-]{0,47}$/;

/** A parsed permission or pattern. `*` segments appear only in patterns. */
export interface ParsedPermission {
  readonly resource: string;
  readonly action: string;
}

/** True when `s` is a valid grammar Segment (permissions.md §1). */
export function isSegment(s: unknown): s is string {
  return typeof s === 'string' && SEGMENT_RE.test(s);
}

function parse(s: unknown, allowWildcard: boolean): ParsedPermission | null {
  if (typeof s !== 'string' || s.length > 97) return null;
  const parts = s.split(':');
  if (parts.length !== 2) return null;
  const [resource, action] = parts as [string, string];
  const ok = (seg: string): boolean => isSegment(seg) || (allowWildcard && seg === '*');
  return ok(resource) && ok(action) ? { resource, action } : null;
}

/** Parses a concrete permission (no wildcards). Returns null when invalid. No normalization. */
export function parsePermission(s: unknown): ParsedPermission | null {
  return parse(s, false);
}

/** Parses a pattern (a `*` may be an entire segment). Returns null when invalid. */
export function parsePattern(s: unknown): ParsedPermission | null {
  return parse(s, true);
}

/** True for patterns that contain at least one `*` segment. */
export function isWildcard(pattern: string): boolean {
  return pattern.includes('*');
}

/** Builds `resource:action`, or null if either part is not a valid Segment (permissions.md §5). */
export function makePermission(resourceType: unknown, action: unknown): string | null {
  return isSegment(resourceType) && isSegment(action) ? `${resourceType}:${action}` : null;
}

/** Matching semantics of permissions.md §4: whole-segment, pure. `permission` must be concrete. */
export function matches(pattern: string, permission: string): boolean {
  const pat = parsePattern(pattern);
  const perm = parsePermission(permission);
  if (!pat || !perm) return false;
  return (
    (pat.resource === '*' || pat.resource === perm.resource) &&
    (pat.action === '*' || pat.action === perm.action)
  );
}

/** True when any pattern in `set` allows the concrete permission. */
export function anyMatches(set: Iterable<string>, permission: string): boolean {
  for (const p of set) if (matches(p, permission)) return true;
  return false;
}

/** `a` covers `b` iff every concrete permission matched by `b` is matched by `a` (permissions.md §4.4). */
export function covers(a: string, b: string): boolean {
  const pa = parsePattern(a);
  const pb = parsePattern(b);
  if (!pa || !pb) return false;
  const res = pa.resource === '*' || pa.resource === pb.resource;
  const act = pa.action === '*' || pa.action === pb.action;
  return res && act;
}
