# Staging runbook

The staging stack (`docker-compose.yml`) runs Aegis exactly as production would — PostgreSQL
storage, durable RS256 signing keys sealed under `AEGIS_MASTER_KEY`, the Express adapter — plus
Prometheus and Grafana. The server is [`examples/staging/server.ts`](../examples/staging/server.ts).

| Service | URL (host) | Notes |
|---|---|---|
| app | http://127.0.0.1:3000 | `/login` `/refresh` `/logout` `/me`, `/.well-known/jwks.json` |
| app metrics | `app:9464/metrics` | compose network only; scraped by Prometheus |
| prometheus | http://127.0.0.1:9090 | scrapes every 15 s |
| grafana | http://127.0.0.1:3001 | `admin` / `admin` unless `GRAFANA_ADMIN_PASSWORD` is set; change it on first login |
| db | 127.0.0.1:5432 | PostgreSQL 15, data in the `pgdata` volume |

## 1. Prerequisites

- Docker with Compose v2 (`docker compose version`)
- Node 22+ (only for running tests or the key CLI outside the containers)
- `openssl` (or Node) to generate a key

## 2. Secrets for this shell

Never put these in a committed file. A local `.env` next to `docker-compose.yml` also works; it is
git-ignored.

```bash
export AEGIS_MASTER_KEY="$(openssl rand -hex 32)"     # 64 hex chars; or: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
export AEGIS_IDENTIFIER_DIGEST_KEY="$(openssl rand -hex 32)"   # keys the HMAC of login identifiers in logs and rate limits
export PG_USER=aegis PG_DB=aegis
export PG_PASS="$(openssl rand -hex 16)"
export STAGING_SEED_EMAIL=smoke@example.com
export STAGING_SEED_PASSWORD="$(openssl rand -hex 12)"
```

Keep `AEGIS_MASTER_KEY` for as long as the database volume exists: it is the only way to unseal
the stored signing keys. A new key against an old volume makes the app refuse to start
(`CONFIG_INVALID`, rule `keys.decrypt`) — by design. See [SECRETS.md](SECRETS.md).

## 3. Build and start

```bash
docker compose up --build -d
docker compose ps
```

Start-up order is enforced: `db` healthy → `migrate` applies `migrations/*.sql` and exits 0 →
`app` starts, creates the first signing key if the key store is empty, and seeds the smoke user.

**Migrations** run automatically through the `migrate` service. To run them by hand:

```bash
docker compose run --rm migrate                                   # inside the stack
DATABASE_URL="postgres://$PG_USER:$PG_PASS@127.0.0.1:5432/$PG_DB" npm run build && npm run migrate   # from the host
```

Both are idempotent (`schema up to date` when nothing is pending).

Logs: `docker compose logs -f app`. A startup failure prints the Aegis error code and exits;
`restart: unless-stopped` retries it.

## 4. Smoke tests

```bash
BASE=http://127.0.0.1:3000

# JWKS: 200, public RSA members only (kty kid alg use n e), Cache-Control: public, max-age=300
curl -si $BASE/.well-known/jwks.json

# Login
TOKENS=$(curl -s -X POST $BASE/login -H 'content-type: application/json' \
  -d "{\"identifier\":\"$STAGING_SEED_EMAIL\",\"password\":\"$STAGING_SEED_PASSWORD\"}")
AT=$(echo "$TOKENS" | node -pe 'JSON.parse(require("fs").readFileSync(0)).accessToken')
RT=$(echo "$TOKENS" | node -pe 'JSON.parse(require("fs").readFileSync(0)).refreshToken')

# Me: 200 with id, type, authMethod
curl -s $BASE/me -H "authorization: Bearer $AT"

# Refresh: 200 with new tokens. (Reusing the old refresh token afterwards → 401 TOKEN_INVALID AND
# the whole session is revoked: reuse detection. Skip that here, or the logout below returns 401.)
NEW=$(curl -s -X POST $BASE/refresh -H 'content-type: application/json' -d "{\"refreshToken\":\"$RT\"}")
AT=$(echo "$NEW" | node -pe 'JSON.parse(require("fs").readFileSync(0)).accessToken')

# Logout: 204; the same access token is then rejected (401) — strict revocation
curl -si -X POST $BASE/logout -H "authorization: Bearer $AT" | head -1
curl -si $BASE/me -H "authorization: Bearer $AT" | head -1

# Metrics (from inside the network): auth_requests_total, refresh_success_total, key_rotations_total
docker compose exec app node -e "fetch('http://127.0.0.1:9464/metrics').then(r=>r.text()).then(console.log)"
# Prometheus target health: "health":"up"
curl -s 'http://127.0.0.1:9090/api/v1/targets?state=active' | grep -o '"health":"[a-z]*"'
```

## 5. Rotate a signing key (planned)

Key operations use the same image and secrets as the app (`examples/staging/keys.ts`):

```bash
KEYS="docker compose run --rm --no-deps app node dist/examples/staging/keys.js"

$KEYS list                     # current keys: one active
$KEYS stage                    # 1. new PENDING key: verify-only; each instance publishes it in
                               #    its JWKS at its next key refresh (≤ 30 s)
# 2. wait ≥ max(JWKS cache 300 s, app key refresh 30 s) so every verifier has the new public key
$KEYS activate <new-kid>       # 3. new key signs; the previous key is RETIRED at this instant
curl -s $BASE/.well-known/jwks.json   # 4. both kids present: the retired one verifies old tokens
# 5. after ttl + leeway (15 min here) the retired key stops verifying and leaves the JWKS
$KEYS prune                    #    then delete it
```

Running app instances pick up each change within 30 s; `key_rotations_total` increases when an
instance sees a new active key. There is no "retire in the future": activation retires the old key.

## 6. Emergency: a signing key is compromised

```bash
$KEYS rotate                   # 1. fresh key becomes active immediately; compromised one retired
$KEYS remove <compromised-kid> # 2. running instances stop accepting it within 30 s
docker compose restart app     # 3. optional: cut-off now instead of within the refresh interval
```

Every token signed by the removed key is rejected; users refresh with their (opaque) refresh tokens
or sign in again. The kid can never be reused.

If session data may also have leaked, revoke sessions as well — strict revocation applies on every
request regardless of keys: revoke the affected sessions or users through the admin API
(`auth.authn.revokeSession` / `invalidateCredentials`), or, for a total reset in staging, end all
sessions in the database:

```bash
docker compose exec db psql -U "$PG_USER" -d "$PG_DB" -c \
  "UPDATE aegis.sessions SET revoked_at_ms = (extract(epoch from now())*1000)::bigint, revoked_reason = 'admin' WHERE revoked_at_ms IS NULL;"
```

If the **master key** leaked: follow the master-key rotation in [SECRETS.md](SECRETS.md#4-key-keepers-do-rotation-runbook).

## 7. Tear down

```bash
docker compose down            # keeps the database and Grafana volumes
docker compose down -v         # also deletes them (and with them every signing key)
```
