// Aegis core public API (Phase 1 reference implementation of spec/).
//
// Layering: domain (pure types) <- rbac/policy/auth (services) <- ports (interfaces)
// <- storage/memory (one adapter). Nothing here depends on a framework, database or HTTP.
export * from './domain/index.js';
export * from './errors/index.js';
export * from './ports/index.js';
export * from './ports/defaults.js';
export * from './rbac/index.js';
export * from './policy/index.js';
export * from './auth/index.js';
export { createMemoryStorage, type MemoryStorage } from './storage/memory/index.js';
export { InMemoryKeyStore } from './storage/memory/keyStore.js';
export { FileKeyStore } from './storage/file/keyStore.js';
export * from './observability/metrics.js';
