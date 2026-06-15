# Runbook — Production key & secret rotation

Authoritative, command-oriented procedure for rotating every cryptographic key
and secret the WeldForge IAM platform holds. Read the whole entry for a given
secret before you touch anything — several of these are **hard cutovers** with
cross-system blast radius.

> Verify infra facts before acting — names and state drift. The values below
> were correct when written.

## Environment facts (verified)

| Fact | Value |
|---|---|
| GCP project | `weldforge` |
| Region | `africa-south1` |
| GKE cluster | `weldforge-gke` (Autopilot) |
| kube context | `gke_weldforge_africa-south1_weldforge-gke` (pass explicitly with `--context=`) |
| Namespace | `sso` |
| API deployment | `sso-api` (container `sso-api`) |
| Cloud SQL | instance `weldforge-db`, db `weldforge`, connection `weldforge:africa-south1:weldforge-db` |
| Secret store | Google Secret Manager: `wf-db-password`, `wf-jwt-secret`, `wf-app-crypto-secret`, `wf-sendgrid-api-key` |
| Deploy path | push to `main` → `.github/workflows/deploy-gcp.yml` reads the GSM secrets and `helm upgrade --install`s them via `--set-string` |
| Access-token TTL | 5 min (`JWT_EXPIRATION_MS=300000`) |
| Refresh-token TTL | 7 days (`REFRESH_TOKEN_EXPIRATION_MS=604800000`) |

**One-time setup for every procedure below**

```bash
gcloud config set project weldforge
gcloud container clusters get-credentials weldforge-gke \
    --region africa-south1 --project weldforge
KCTX=gke_weldforge_africa-south1_weldforge-gke
```

Secrets are injected at deploy time from GSM into the pods' env (see
`deploy-gcp.yml` lines ~84-122 and `infrastructure/helm/weldforge/values.yaml`
`api.secrets.*`). They are **not** stored as long-lived k8s Secrets you can edit
in place — the source of truth is GSM, and the way to push a rotated secret into
the running pods is to **add a new GSM version and re-run the deploy** (or run
`helm upgrade` manually, see `infrastructure/README.md`).

`SecretHygieneValidator` refuses to boot the app if a secret is too short
(`JWT_SECRET` < 64 bytes for HS512, `APP_CRYPTO_SECRET` < 16 chars — enforced in
every profile) or, when `APP_REQUIRE_SECURE_SECRETS=true` (set in prod values),
is still a known dev/placeholder default — so generate strong values. See
[../security/configuration-reference.md](../security/configuration-reference.md).

---

## Summary table

| Secret | GCP Secret Manager name | Backs | Blast radius | Grace / overlap mechanism | Suggested cadence |
|---|---|---|---|---|---|
| Platform HMAC `app.jwt.secret` | `wf-jwt-secret` | HS512 platform tokens (legacy `/api/auth/*`) | **All 4 systems**: weldforge-auth + Safe Space + Krusty + Commons | **None** — hard cutover, invalidates every live token simultaneously | Annual or on compromise (coordinated) |
| At-rest key `app.crypto.secret` | `wf-app-crypto-secret` | AES-GCM encryption of tenant RSA private keys, OAuth2 client secrets, Stripe/Twilio/CRM/LDAP creds | All encrypted DB columns become undecryptable on a naive swap | **None built-in** — requires a custom re-encryption migration | Rarely / on compromise (with re-encryption job) |
| Per-tenant OIDC/SAML signing keys | `tenant_signing_keys` table (in DB, encrypted by `app.crypto.secret`) | RS256 OIDC token signing + SAML assertion signing | One tenant's RP/SP relying parties | **Yes** — overlapping `kid`s, old key stays in JWKS; `KeyRotationScheduler` (prod-enabled, 90d) | 90 days (automatic) |
| Internal PKI CA | `tenant_certificate_authorities` table (key encrypted by `app.crypto.secret`) | Per-tenant client-auth / S/MIME certs | One tenant's issued client certs | CRL-based revocation; cert renewal notifier | 10-year CA; rotate on compromise |
| DB password | `wf-db-password` | Cloud SQL login for `wfuser` | weldforge-auth ↔ DB connection only | Cloud SQL allows changing the user's password live | Annual or on compromise |
| SendGrid API key | `wf-sendgrid-api-key` | Outbound transactional email (SMTP) | Email delivery only (password reset, verification) | SendGrid supports multiple active keys | Annual or on compromise |

---

## 1. Platform HMAC `app.jwt.secret` (`wf-jwt-secret`) — CRITICAL, coordinated

### Why this is the dangerous one

`JwtService` signs the legacy platform access tokens with a single HMAC secret
(`Keys.hmacShaKeyFor(secret)`, see `weldforge-auth/.../service/JwtService.java`).
That same secret is **shared verbatim** with three external consumers — Safe
Space, Krusty, and the Commons microservice — each of which verifies tokens with
its own `WELDFORGE_JWT_SECRET` env, mirrored from `wf-jwt-secret` (see
`CLAUDE.md` → Tech Metropolis trio).

There is **no key-id / key-ring / grace mechanism** today: `JwtService` has one
secret in, one secret out. The moment the secret changes, every token signed
under the old secret fails verification — in weldforge-auth **and** in all three
consumers — *simultaneously*. This is a hard cutover. You cannot stage it.

Bounded impact: access-token TTL is **5 minutes**, so worst case any logged-in
user across the four systems gets one failed request and must re-authenticate
(or the consumer silently re-fetches). Refresh tokens are 7 days but are stored
server-side and re-minted, so the practical user-visible window is minutes, not
days — provided all four systems flip together.

> Cross-reference: the planned **HMAC key-ring** (publish a `kid`, accept both
> old and new keys during an overlap window) removes this lockstep requirement.
> It is tracked in `docs/security/hardening-backlog.md` (create/append there if
> it does not yet exist). Until that ships, follow the coordinated procedure.

### Pre-checks

```bash
# Confirm current secret length is sane (must be >= 64 bytes for HS512 / hygiene)
gcloud secrets versions access latest --secret=wf-jwt-secret | tr -d '\n' | wc -c

# Confirm the pods are currently healthy before you change anything
kubectl --context=$KCTX -n sso get pods -l app=sso-api
kubectl --context=$KCTX -n sso exec deploy/sso-api -c sso-api -- \
    curl -s http://localhost:8076/actuator/health
```

### Procedure (coordinated maintenance window)

1. **Notify the three consumer owners** (Safe Space, Krusty, Commons). All four
   systems must redeploy inside the same window. Do not start until owners have
   confirmed they can deploy on your signal.
2. **Schedule a window.** Off-peak. Expect a few minutes of forced
   re-authentication.
3. **Generate a new secret** (64+ bytes of base64 entropy):

   ```bash
   NEW_JWT=$(openssl rand -base64 64 | tr -d '\n')
   ```

4. **Add it as a new GSM version** (do NOT disable the old version yet — keep it
   as rollback):

   ```bash
   printf '%s' "$NEW_JWT" | gcloud secrets versions add wf-jwt-secret --data-file=-
   ```

5. **Distribute to the three consumers.** Each consumer reads its
   `WELDFORGE_JWT_SECRET` from its own GSM mirror of `wf-jwt-secret`. Update the
   value in each consumer's secret store to the same `$NEW_JWT`. Have each owner
   stage (but not yet apply) their redeploy.
6. **Cut over together.** On the signal, redeploy **all four simultaneously**:
   - weldforge-auth — re-run the deploy so pods pick up the new GSM version:

     ```bash
     # Preferred: trigger the GHA deploy (no-op commit to main or re-run the
     # latest deploy-gcp.yml run). Or manually:
     helm upgrade --install weldforge infrastructure/helm/weldforge \
       --namespace sso \
       -f infrastructure/helm/weldforge/values-prod.yaml \
       --set-string api.secrets.JWT_SECRET="$(gcloud secrets versions access latest --secret=wf-jwt-secret)" \
       --set api.image.tag=$CURRENT_TAG --set frontend.image.tag=$CURRENT_TAG
     # then force a fresh rollout so all replicas restart with the new env:
     kubectl --context=$KCTX -n sso rollout restart deploy/sso-api
     ```
   - Safe Space / Krusty / Commons — each owner redeploys with the new env.

### Verification

```bash
# 1. Pods rolled out cleanly
kubectl --context=$KCTX -n sso rollout status deploy/sso-api

# 2. A fresh login mints a token that verifies (login against a live tenant)
TOKEN=$(curl -s -X POST https://sso.weldforge.org/api/auth/login \
  -H 'Content-Type: application/json' -H 'X-Tenant-Slug: leap' \
  -d '{"identifier":"<test-user>","password":"<pw>"}' | jq -r .accessToken)
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null   # eyeball the claims

# 3. Each consumer owner confirms their service accepts a freshly-issued token
#    and that old tokens are now rejected (expected).
```

### Rollback

The old GSM version is still present. Re-point all four systems back to it and
redeploy:

```bash
# Find the previous version number, then redeploy reading that specific version,
# or disable the new version so `latest` resolves to the old one:
gcloud secrets versions list wf-jwt-secret
gcloud secrets versions disable <NEW_VERSION> --secret=wf-jwt-secret
kubectl --context=$KCTX -n sso rollout restart deploy/sso-api
# Consumers revert their WELDFORGE_JWT_SECRET to the old value and redeploy.
```

Rollback is itself a coordinated flip — all four together — because the same
lockstep applies in reverse.

---

## 2. At-rest encryption key `app.crypto.secret` (`wf-app-crypto-secret`)

### Why a naive swap destroys data

`EncryptedStringConverter` (`config/crypto/EncryptedStringConverter.java`)
derives an AES-256 key as `SHA-256(app.crypto.secret)` and uses AES-GCM to
encrypt string columns at rest. Columns protected by it (search for `@Convert`
referencing the converter) include:

- **Tenant OIDC/SAML RSA private keys** (`tenant_signing_keys.privateKeyPem`)
- **Per-tenant PKI CA private keys** (`tenant_certificate_authorities`)
- **OAuth2 client secrets** (`oidc_clients`)
- **Twilio / CRM / LDAP / payment-gateway (Stripe) provider credentials**
  (`tenant_twilio_providers`, `tenant_crm_providers`, `tenant_ldap_providers`,
  `payment_gateway`)

The IV is stored inline (`[12-byte IV][ciphertext+tag]`, base64). **There is no
key id stored with the ciphertext** — decryption always uses the one key derived
from the current `app.crypto.secret`. If you change the secret without
re-encrypting, every existing ciphertext becomes permanently undecryptable:
JWKS/SAML signing breaks, OAuth2 client auth breaks, outbound provider calls
break. This is **not** recoverable without the old secret.

There is **no built-in re-encryption job.** Rotating this secret is therefore a
*build-a-migration* task, not a config flip.

### Procedure — envelope re-encryption (decrypt-old, re-encrypt-new)

1. **Write a one-shot re-encryption script/job** that, for every encrypted
   column listed above:
   - reads the row ciphertext,
   - decrypts it with the **old** `app.crypto.secret` (old AES key),
   - re-encrypts it with the **new** `app.crypto.secret` (new AES key),
   - writes it back, ideally inside a transaction per batch.

   The cleanest place is a standalone Spring Boot run profile or a Flyway
   Java migration that is given **both** secrets (e.g. `APP_CRYPTO_SECRET_OLD`
   and `APP_CRYPTO_SECRET`) so it can hold two `SecretKeySpec`s at once. Reuse
   the exact IV/tag framing from `EncryptedStringConverter`
   (`AES/GCM/NoPadding`, 12-byte IV prefix, 128-bit tag) so output is
   byte-compatible with the converter.

2. **Pre-checks**

   ```bash
   # Snapshot the DB FIRST — this is destructive if the script is wrong.
   gcloud sql backups create --instance=weldforge-db
   # Inventory of rows to re-encrypt (rough sanity counts)
   #   tenant_signing_keys, tenant_certificate_authorities, oidc_clients,
   #   tenant_twilio_providers, tenant_crm_providers, tenant_ldap_providers,
   #   payment_gateway
   ```

3. **Generate the new secret** and add it as a GSM version (keep the old):

   ```bash
   NEW_CRYPTO=$(openssl rand -base64 48 | tr -d '\n')
   printf '%s' "$NEW_CRYPTO" | gcloud secrets versions add wf-app-crypto-secret --data-file=-
   ```

4. **Run the re-encryption job** in a maintenance window (ideally with the API
   scaled to 0 or in a read-only posture so nothing writes new ciphertext under
   the old key mid-run):

   ```bash
   kubectl --context=$KCTX -n sso scale deploy/sso-api --replicas=0
   # run the job with APP_CRYPTO_SECRET_OLD=<old> APP_CRYPTO_SECRET=<new>
   ```

5. **Redeploy the API with the new secret** and scale back up:

   ```bash
   kubectl --context=$KCTX -n sso rollout restart deploy/sso-api
   kubectl --context=$KCTX -n sso scale deploy/sso-api --replicas=2
   ```

### Verification

```bash
# Tenant JWKS + SAML metadata must still load (proves private keys decrypt)
curl -s https://sso.weldforge.org/t/leap/oauth2/jwks | jq .
curl -s https://sso.weldforge.org/t/leap/saml2/idp/metadata | head
curl -s https://sso.weldforge.org/t/leap/.well-known/openid-configuration | jq .issuer
# Exercise one OAuth2 client_secret flow and one outbound provider (e.g. a test
# password-reset email if Twilio/SendGrid creds were among the re-encrypted set).
```

### Rollback

Restore the pre-run DB backup **and** re-point `wf-app-crypto-secret` to the old
version (disable the new GSM version so `latest` is the old one), then redeploy.
Because the job rewrites ciphertext in place, the DB snapshot is the only safe
rollback for partially-migrated data — do not attempt to re-run the job in
reverse against half-migrated rows.

---

## 3. Per-tenant OIDC/SAML signing keys (`tenant_signing_keys`)

### Mechanism (grace built in)

`TenantSigningKeyService` (`service/oidc/TenantSigningKeyService.java`) mints a
2048-bit RSA key per tenant with a stable `kid` (`wf-<uuid>`). Rotation is
**non-destructive**: `rotate()` marks the current active key `active=false` /
sets `rotatedAt`, then generates a fresh active key. Crucially `jwks()` returns
**every** key for the tenant — active *and* rotated — so relying parties that
cached a token signed by the old `kid` can still find the matching public key in
JWKS during the propagation window. This is the overlap/grace mechanism the HMAC
secret lacks.

`KeyRotationScheduler` (`@ConditionalOnProperty app.key-rotation.enabled=true`,
**enabled in prod**, `APP_KEY_ROTATION_MAX_AGE_DAYS=90`, daily interval) rotates
any tenant whose active key is older than 90 days automatically. So in normal
operation you do nothing.

`V41__regenerate_default_tenant_signing_key.sql` is the worked example of a
**manual** regen — it deleted the `default` tenant's key rows so the service
lazily re-minted a clean key (used there to recover from a key that no longer
decrypted under the current crypto secret).

### Manual rotation of a single tenant

Two options:

- **Admin API (preferred):** call the tenant signing-key rotate endpoint via the
  admin portal / REST surface. This calls `TenantSigningKeyService.rotate()`,
  which preserves the old key in JWKS (best for relying-party grace).
- **SQL regen (recovery only, e.g. an undecryptable key like V41):** delete the
  tenant's `tenant_signing_keys` rows; the service re-mints on next JWKS/sign
  request. This drops the old public key from JWKS immediately, so only use it
  when the old key is already unusable.

```sql
-- Recovery-style regen for tenant slug 'sometenant' (mirrors V41):
DELETE FROM tenant_signing_keys
 WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'sometenant');
-- service lazily re-mints a fresh RS256 key on next request.
```

### Verification

```bash
SLUG=sometenant
curl -s https://sso.weldforge.org/t/$SLUG/oauth2/jwks | jq '.keys[].kid'
curl -s https://sso.weldforge.org/t/$SLUG/.well-known/openid-configuration | jq .issuer
curl -s https://sso.weldforge.org/t/$SLUG/saml2/idp/metadata | head
```

Confirm the new `kid` appears, and (for a graceful rotate) that the old `kid` is
still present until the propagation window closes.

### Rollback

A graceful `rotate()` is additive — the new key just stops being used if you mark
it inactive. For an SQL regen, restore from a DB backup if a relying party
pinned the deleted `kid` and broke. Generally, re-issuing tokens (5-min TTL)
plus a JWKS refetch resolves consumer-side caching within minutes.

---

## 4. Internal PKI CA (`tenant_certificate_authorities`)

`CertificateAuthorityService` (`service/pki/CertificateAuthorityService.java`)
mints a per-tenant **RSA-4096 self-signed root CA** valid for 10 years (default),
its private key encrypted at rest via `app.crypto.secret`. End-entity certs are
RSA-2048, default 365 days; their private keys are single-reveal and never
stored. `CertificateRenewalNotifier` watches for expiry.

Rotation considerations (low-frequency, do on compromise or near CA expiry):

- **There is no in-place CA re-key.** The model enforces one CA per tenant
  (`createRootCa` throws if one exists). Rotating the CA means: stand up a new CA
  (delete the old row or extend the model to support a successor CA), re-issue
  end-entity certs under the new CA, and distribute the new CA cert to every
  relying verifier. Treat as a planned migration, not a routine task.
- **Revocation, not rotation, is the day-to-day tool.** Use
  `revokeCertificate(serial, reason)` and publish a fresh CRL via
  `generateCrlPem(tenantId)` (24-hour `nextUpdate`, CRL number auto-bumps per
  RFC 5280 §5.2.3). On CA compromise, revoke with reason `CA_COMPROMISE`.
- The CA private key is protected by `app.crypto.secret`, so a §2 crypto-secret
  rotation must re-encrypt these rows too (it is in the §2 column list).

CRL/OCSP note: relying parties cache the CRL up to its 24h `nextUpdate`. After a
revocation, that is the worst-case window before a revoked cert is universally
rejected — communicate it when revoking for compromise.

---

## 5. DB password (`wf-db-password`) and SendGrid key (`wf-sendgrid-api-key`)

Both are plain credential rotations with no cryptographic blast radius beyond the
single integration.

### DB password (`wf-db-password`)

```bash
# 1. Generate + add a new GSM version
NEW_DB=$(openssl rand -base64 36 | tr -d '\n')
printf '%s' "$NEW_DB" | gcloud secrets versions add wf-db-password --data-file=-

# 2. Change the Cloud SQL user's password to match (user is wfuser)
gcloud sql users set-password wfuser \
    --instance=weldforge-db --password="$NEW_DB"

# 3. Redeploy so SPRING_DATASOURCE_PASSWORD picks up the new version
kubectl --context=$KCTX -n sso rollout restart deploy/sso-api
kubectl --context=$KCTX -n sso rollout status deploy/sso-api
```

Verify: readiness probe goes green (it includes `db`):

```bash
kubectl --context=$KCTX -n sso exec deploy/sso-api -c sso-api -- \
    curl -s http://localhost:8076/actuator/health/readiness
```

Rollback: set the Cloud SQL password back to the previous value and disable the
new GSM version. Sequence matters — change Cloud SQL and the deployed secret as
close together as possible to minimise auth-failure window (Cloud SQL Auth Proxy
sidecar reconnects use the env-supplied password).

### SendGrid API key (`wf-sendgrid-api-key`)

SendGrid supports multiple active keys, so this is zero-downtime:

```bash
# 1. Create a new API key in the SendGrid dashboard (Mail Send scope).
# 2. Add it as a new GSM version
printf '%s' "$NEW_SENDGRID_KEY" | gcloud secrets versions add wf-sendgrid-api-key --data-file=-
# 3. Redeploy so mail.password is re-rendered (SMTP password = the API key)
kubectl --context=$KCTX -n sso rollout restart deploy/sso-api
# 4. Smoke-test, THEN delete the old key in the SendGrid dashboard.
curl -X POST https://sso.weldforge.org/api/auth/forgot-password \
     -H 'Content-Type: application/json' -H 'X-Tenant-Slug: leap' \
     -d '{"email":"<throwaway-test@example.com>"}'
# confirm "Delivered" in the SendGrid Activity Feed.
```

> Note: `SmtpMailService` logs a delivery failure but the triggering security
> operation still returns success — so the smoke test is mandatory; a broken key
> is otherwise silent. (See the SendGrid operational-deadline note in
> `CLAUDE.md`.)

Rollback: re-point `wf-sendgrid-api-key` to the old version (still valid in
SendGrid until you delete it) and redeploy.

---

## General rollback principles

- **Never disable/destroy the old GSM version until verification passes.** Add a
  new version, deploy, verify, *then* disable the old one.
- **For `app.crypto.secret` only**, a DB backup is the real rollback because the
  re-encryption job rewrites ciphertext in place — take one before you start.
- **Re-run the deploy to push a secret into pods.** Editing GSM alone does not
  restart the pods; `kubectl rollout restart deploy/sso-api` (or a fresh GHA
  deploy) is what makes the new value live.
