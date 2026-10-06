# infra: CI, staging stack, metrics and runbooks

## What

Infrastructure, CI and observability only. **No domain, auth, JWT, storage, key-lifecycle or
Express-adapter behaviour changed**; the one adapter edit is an optional `/metrics` route that is
off unless a metrics object is passed.

| Area | Files |
|---|---|
| CI | `.github/workflows/ci.yml`: build → lint → unit/conformance/Express tests → demo; PostgreSQL suite on **15 and 17** (service containers, health checks) after an explicit `npm run migrate`; staging image build; test logs uploaded as artifacts on failure; required-secrets check |
| Staging stack | `docker-compose.yml` (db postgres:15 + volume, one-shot `migrate`, app, Prometheus, Grafana), `Dockerfile` (multi-stage, runtime = compiled output + express + pg, non-root), `.dockerignore`, `grafana/provisioning/datasources/prometheus.yml` |
| Staging server and tools | `examples/staging/server.ts` (PostgreSQL storage, durable RS256 keys, metrics on internal port 9464), `examples/staging/keys.ts` (list/stage/activate/rotate/remove/prune via `PersistentKeyProvider`), `scripts/migrate.mjs` |
| Metrics | `src/observability/metrics.ts`: `auth_requests_total{result}`, `refresh_success_total`, `key_rotations_total`, `metricsHandler`; fed by `instrumentAuth` (wraps the public `Auth` facade) and `watchKeyRotations`; `prometheus/prometheus.yml` scrapes `app:9464` every 15 s; `test/unit/metrics.test.ts` (5 tests) |
| Docs | `docs/STAGING.md` (runbook: secrets, migrations, smoke tests, planned and emergency rotation), `docs/SECRETS.md` (master key storage, GitHub Secrets / Vault / KMS, rotation runbook) |
| Scripts | `test:postgres`, `migrate`, `keys`; `.env` git-ignored |

## Why

- CI previously ran PostgreSQL 17 only, with credentials in the workflow; staging uses 15. Both
  now run, with credentials from repository secrets.
- There was no way to run Aegis as deployed (PostgreSQL + sealed keys) locally or to observe it.
- Operators had no tested procedure for key rotation or a compromised key.

## Design notes

- **No new runtime dependency.** The Prometheus text format is written directly (~60 lines).
- **Bounded labels.** `result` is `success` or an Aegis error code (fixed catalog), never a user,
  session or kid.
- **Metrics stay internal.** Port 9464 is not published by compose; the main port has no `/metrics`.
- **Fail fast on missing secrets.** Compose uses `${VAR:?…}`; CI checks secrets before running;
  the app refuses to start without `AEGIS_MASTER_KEY` (existing `CONFIG_INVALID` behaviour).
- **Ports bind to 127.0.0.1.** Grafana defaults to admin/admin for local staging only (documented).

## Verification (local, Windows + Docker 29)

| Check | Result |
|---|---|
| `npm ci`, `npm run build`, `npm run lint` | pass |
| `npm test` (unit + conformance + Express + metrics) | **234 / 234** |
| — of which Express adapter | 21 / 21 |
| `npm run test:postgres`, embedded PostgreSQL 17 | **127 / 127** |
| PostgreSQL suite on a `postgres:15` container | **127 / 127** |
| `npm run migrate` twice | `applied: 001_init, 002_indexes, 003_create_keys_table`, then `schema up to date` |
| `docker compose up --build -d` | all services up; `migrate` exited 0 |
| JWKS | 200, `application/jwk-set+json`, `max-age=300`, members `alg,e,kid,kty,n,use` |
| login → /me → refresh → logout → /me | 200 → 200 → 200 → 204 → 401 |
| refresh-token reuse | 401 and session revoked |
| /metrics (internal) | 200 `text/plain; version=0.0.4`; counters match the traffic |
| Prometheus target / Grafana datasource | `up` / provisioned |
| Rotation stage → activate | new kid signs, retired kid still published, `key_rotations_total 1` |
| Emergency rotate → remove | removed kid's token → 401; kid stays reserved |
| Secret scan of the branch and image env | no secret values found |

## Before merging

Repository secrets are required for the PostgreSQL job (see `docs/SECRETS.md` §3):
`AEGIS_MASTER_KEY`, `PG_USER`, `PG_PASS`, `PG_DB`. Pull requests from forks get no secrets, so that
job fails at "Check required secrets" for them.

No release tag is created by this PR.
