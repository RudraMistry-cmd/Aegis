# Durable signing keys and the JWKS endpoint

Phase 3.5 makes signing keys survive restarts and agree across instances, and publishes the public
halves for external verifiers. Nothing about verification changed: a token is accepted only if its
signature verifies **and** its session, checked in the session store on every request, is still
valid (`tokens.md` §2.5). Publishing a key never makes a revoked session usable again.

## 1. Wiring

```ts
import { openJwtAccessTokens, CryptoIdGenerator, SystemClock } from 'aegis-core';
import { createPostgresStorage } from 'aegis-core/postgres';

const storage = createPostgresStorage({ connectionString: process.env.DATABASE_URL! });
await storage.migrate(); // includes 003_create_keys_table

const { accessTokens, keys, jwks } = await openJwtAccessTokens(
  {
    tokens: { algorithm: 'RS256', issuer: 'https://auth.example.com', audience: 'api', ttl: 900_000 },
    keys: {
      rotationEnabled: true,
      storage: 'postgres',
      generateIfMissing: true,          // first start only: creates a key if the store is EMPTY
      masterKeyEnvVar: 'AEGIS_MASTER_KEY', // the default
      jwks: { path: '/.well-known/jwks.json', cacheTtlSec: 300 },
      refreshIntervalMs: 30_000,        // how often each instance reloads the keyring
    },
  },
  { keyStore: storage.keys, clock: new SystemClock(), ids: new CryptoIdGenerator() },
);

// Any HTTP framework: serve jwks.handle() at jwks.path.
app.get(jwks!.path, (_req, res) => {
  const r = jwks!.handle();
  res.status(r.status).set(r.headers).send(r.body);
});
```

`accessTokens` is passed to `createAuth` exactly like the Phase 3 provider. On shutdown call
`keys.close()` (it stops the refresh timer, which is `unref`'d and never keeps the process alive).

### Startup rules (fail closed)

Startup fails with `CONFIG_INVALID`, listing every violation at once, when:

- the store holds no active key, unless `generateIfMissing` is true **and** the store is completely
  empty (a store with only retired or pending keys is an operator problem, not a first start);
- any stored key cannot be decrypted, parsed, or does not match its algorithm, or its stored public
  half does not match its private half;
- `storage: 'postgres'` and the master key variable is unset (the schema also refuses plaintext);
- the master key is malformed (it must be 32 bytes: 64 hex characters or base64/base64url) or
  obviously weak;
- `jwks` is configured for HS256, or the JWKS path or TTL is invalid.

With the `file` or `memory` store and no master key, Aegis starts but logs once that private keys are
stored **unencrypted**, which is acceptable for local development only.

## 2. What the endpoint publishes

```json
{ "keys": [ { "kty": "RSA", "kid": "rs256-20261002-3f9a…", "alg": "RS256", "use": "sig", "n": "…", "e": "AQAB" } ] }
```

- Exactly the keys this server would accept right now: the active key, every **pending** key, and
  every retired key still inside its verification window (`retiredAt + ttl + leeway`). A removed key
  disappears at once.
- Members are whitelisted: `kty kid alg use n e`. The document is built from public `KeyObject`s
  only; private members (`d p q dp dq qi`) cannot appear, and tests check this against a key whose
  private encoding is known.
- Headers: `content-type: application/jwk-set+json; charset=utf-8`,
  `cache-control: public, max-age=<cacheTtlSec>` (default 300, range 0–86400),
  `x-content-type-options: nosniff`.
- **HS256 is never published.** An HMAC secret verifies *and* signs, so it cannot be shared with
  third parties. Configuring `jwks` with HS256 is `CONFIG_INVALID`.

Pending keys are published deliberately: a verifier that caches the document for `cacheTtlSec`
must already hold a key before the first token signed with it reaches them.

## 3. Guidance for verifiers

1. Fetch the document over HTTPS from a configured URL. Never follow `jku`, `x5u` or `jwk` from a
   token header (Aegis itself rejects such tokens).
2. Cache it for the `max-age` it is served with.
3. On an unknown `kid`, refetch **at most once per short interval** (e.g. once every 30–60 s), then
   reject. Unthrottled refetching lets anyone with a random `kid` turn your verifier into a load
   generator against the issuer.
4. Pin `alg` to `RS256` in your verifier; never take it from the token.
5. A signature check only proves Aegis issued the token and it is unexpired. Only Aegis knows whether
   the session was revoked. Services that need strict revocation must call Aegis (`resolve` /
   `authenticate`) rather than trust a bare JWT; the JWKS exists for services that accept
   revocation latency of one access-token TTL, by their own documented choice.

## 4. Multiple instances

All instances share one key store. Each keeps an in-memory copy, reloaded every
`refreshIntervalMs` and also on demand (at most once per second) when it sees a token with a `kid` it
does not know. A token signed by an instance that rotated a moment ago is therefore verifiable
everywhere at once.

Rotations are serialised by the keyring lock (PostgreSQL advisory lock); the schema admits at most
one active key regardless. Concurrent rotations from several instances end with exactly one active
key and every other key retired; concurrent first starts create exactly one key.

**Staleness bound.** An instance learns of a new active key within `refreshIntervalMs`. Until then
it keeps signing with the key just retired; tokens it issues after the retirement instant are
rejected by up-to-date instances (a retired key never vouches for tokens issued after it retired).
Keep `refreshIntervalMs` small, rotate with the two-phase rollout below, or allow a `leewayMs` that
covers the refresh interval. Aegis does not offer "retire in the future", because a key that keeps
signing after it is declared retired would weaken the guarantee above.

A failed periodic refresh keeps the previous keyring and logs a warning. Session checks still run on
every request; if the database is unreachable those fail closed (`STORAGE_UNAVAILABLE`) anyway.

## 5. Planned rotation (zero downtime)

1. **Stage**: `await keys.stage()` on one instance. The key is pending: verify-only, and published.
2. **Wait** at least `max(cacheTtlSec, refreshIntervalMs)` so every instance and every external
   verifier has it.
3. **Activate**: `await keys.activate(kid)` on one instance (a single leader, a one-off job, or an
   admin endpoint). The previous key is retired at that instant.
4. **Check** the JWKS: new kid present, old kid still present.
5. After `ttl + leeway`, the old key is no longer published; `await keys.prune()` deletes it.

Single-process deployments can call `keys.rotate()`, which does steps 1 and 3 atomically.

## 6. Compromise of a signing key

1. `await keys.rotate()` — a fresh key becomes active; the compromised one is retired.
2. `await keys.remove(compromisedKid)` — it stops verifying at once on the instance that removed it
   and on every other instance at its next refresh (within `refreshIntervalMs`), and leaves the JWKS.
   Its kid is never reusable. For an immediate cluster-wide cut-off, call `keys.refresh()` on every
   instance or restart them.
3. Every token it signed is now rejected. Users re-authenticate with their refresh tokens, which are
   opaque and not signed by this key.
4. If the attacker may also have obtained session or refresh-token data, revoke those sessions
   (`revoke` / revoke-all-for-user, or bump the user's `securityVersion`). Revocation is enforced on
   every request whatever happened to the keys.
5. If the **master key** leaked, every stored private key must be treated as compromised: rotate the
   master key (deploy the new value, then rotate *every* signing key so new ones are sealed under it,
   and remove the old ones once their windows have passed or at once if they are compromised).

## 7. Where the master key and private keys live

The master key is read from one named environment variable (`AEGIS_MASTER_KEY` by default) and from
nowhere else. Private keys are sealed with AES-256-GCM under it (envelope `AEK1 | nonce | tag |
ciphertext`, bound to the kid as additional data, so a ciphertext cannot be moved to another row).

**Distributing the master key across instances is out of scope for Aegis** and is not implemented.
Options, in rough order of preference:

- A cloud secret manager (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) injecting the
  variable at deploy time, with access limited to the auth service's identity.
- Kubernetes Secrets mounted as environment variables, with encryption at rest for etcd enabled.
- HashiCorp Vault (agent injector or `envconsul`).

Never commit the master key, never put it in the same database as the keys, and never log it.

### HSMs and KMS

Full HSM connectors are out of scope. The seam for one is the `KeyProvider` interface
(`src/auth/jwt/keyProvider.ts`): `getActiveKey()` returns the signing key, `getKeyById()` the
verification key. An HSM-backed provider keeps the private key inside the device and signs through
it, persisting only public halves and metadata (kid, status, timestamps) in the `KeyStore`. Best
practice: non-exportable RSA keys generated in the HSM, one key per kid, signing permission granted
only to the auth service, and rotation driven through the same stage → activate lifecycle.
