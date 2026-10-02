# Secrets: `AEGIS_MASTER_KEY` and database credentials

## 1. What the master key protects

Aegis stores JWT signing keys in PostgreSQL (`aegis.signing_keys`). The private half of every key is
sealed with AES-256-GCM under `AEGIS_MASTER_KEY` before it reaches the database; the schema itself
refuses plaintext. Anyone holding **both** a database copy and the master key can mint access
tokens for any user. Anyone holding only one of them cannot.

Format: 32 random bytes, as 64 hex characters (base64 is also accepted). Aegis refuses to start
with a malformed or obviously weak value (`CONFIG_INVALID`, rule `keys.master_key`), and refuses to
use the PostgreSQL key store without one (`keys.master_key_required`).

```bash
openssl rand -hex 32
```

## 2. Never next to the data

- **Not in the database, not in its backups, not in the same backup job.** The whole point of the
  seal is that a leaked dump is useless. A dump that carries the key (a `config` table, a `.env` in
  the same archive, a VM snapshot holding both) defeats it.
- Not in the repository, a Docker image, a compose file, a CI log, an issue or a chat. The compose
  file and the CI workflow only *reference* it (`${AEGIS_MASTER_KEY:?…}`, `${{ secrets.… }}`).
- Not in application logs. Aegis never logs it; do not print the environment in your own startup
  code either.
- Read from exactly one environment variable (configurable name, default `AEGIS_MASTER_KEY`), so
  the injection point is single and auditable.

Losing the key is an outage, not a breach: no stored signing key can be unsealed, so the app
refuses to start. Recovery = new master key + new signing keys (§4 step 5); every existing access
token becomes invalid, sessions and refresh tokens are unaffected.

## 3. Injecting it

### GitHub Actions

Repository → *Settings → Secrets and variables → Actions → New repository secret*:

| Secret | Used by | Value |
|---|---|---|
| `AEGIS_MASTER_KEY` | CI jobs (`.github/workflows/ci.yml`) | `openssl rand -hex 32` — a CI-only key, never the staging or production one |
| `PG_USER`, `PG_PASS`, `PG_DB` | the PostgreSQL service container in CI | throwaway values; `PG_PASS` URL-safe (letters, digits, `-`, `_`) |

```bash
gh secret set AEGIS_MASTER_KEY --body "$(openssl rand -hex 32)"
gh secret set PG_USER --body aegis
gh secret set PG_PASS --body "$(openssl rand -hex 16)"
gh secret set PG_DB --body aegis
```

GitHub masks secret values in logs. Pull requests from forks receive no secrets; the PostgreSQL
job then fails at "Check required secrets" with a clear message.

### HashiCorp Vault

```bash
vault kv put secret/aegis/staging master_key="$(openssl rand -hex 32)"
# at deploy time, in the process supervisor's environment only:
export AEGIS_MASTER_KEY="$(vault kv get -field=master_key secret/aegis/staging)"
```

On Kubernetes, prefer the Vault Agent injector or the Secrets Store CSI driver and map the value to
the `AEGIS_MASTER_KEY` environment variable; grant read only to the auth service's identity.

### Cloud secret managers and KMS

AWS Secrets Manager, GCP Secret Manager or Azure Key Vault: store the 64-hex value, grant
`get` to the service's role only, inject it as an environment variable through the platform (ECS
task `secrets`, Cloud Run `--set-secrets`, App Service Key Vault references). A KMS can hold a
key-encryption key that wraps the master key at rest; Aegis only ever needs the unwrapped value in
its environment. Full HSM signing (private keys never leave the device) is a different integration;
see [JWKS.md §7](JWKS.md).

## 4. Key Keepers Do: rotation runbook

**Signing keys** rotate routinely (stage → wait → activate → prune, [STAGING.md §5](STAGING.md)).
That needs no master-key change.

**Master key** rotation (scheduled yearly, or immediately when it may have leaked). Stored keys are
sealed under the old value and Aegis reads one master key, so rotation means *new signing keys
under the new master key*:

1. Generate the new value and store it in the secret manager as a **new version**; keep the old one.
2. Schedule a short window: access tokens issued before the switch will stop verifying when their
   key is unreadable, so users refresh (refresh tokens are unaffected).
3. Stop all app instances (they must not run with mixed master keys).
4. With the **old** master key, list keys (`npm run keys list`) and note every kid.
5. With the **new** master key and an empty key table, start one instance with
   `AEGIS_GENERATE_KEY=true`: delete the old rows first
   (`DELETE FROM aegis.signing_keys;` — the kid registry keeps the old kids reserved forever), so the
   instance generates and seals a fresh active key.
6. Start the remaining instances with the new value. Verify `/.well-known/jwks.json` shows only the
   new kid and a login → `/me` smoke test passes.
7. Destroy the old master-key version in the secret manager once nothing reads it; record who did
   what and when.

**If the old master key leaked**, also treat every token signed before the switch as forged:
step 5 already invalidates them; additionally revoke sessions if session data may have leaked
([STAGING.md §6](STAGING.md#6-emergency-a-signing-key-is-compromised)).

**Database credentials** rotate independently: create the new role/password, update the secret,
roll the instances, drop the old credential.

Checklist for every rotation: two people (one acts, one verifies), the old value never pasted into
a ticket or chat, the secret manager's audit log reviewed afterwards.
