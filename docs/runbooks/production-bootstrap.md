# Runbook — Production bootstrap (first stand-up in a non-dev environment)

**Audience:** an operator bringing WeldForge up in staging / production for the
**first time**. The README quickstart (`docker compose up`) is **dev-only**: it
boots on source-committed insecure defaults and does **not** enforce secret
hygiene. This runbook covers the things that quickstart deliberately skips.

> **The one thing to know before you start:** the app **fails fast at boot** on
> bad secrets. `SecretHygieneValidator`
> (`weldforge-auth/.../config/security/SecretHygieneValidator.java`) runs in a
> `@PostConstruct` and throws `IllegalStateException` — the container will
> crash-loop, not start degraded — if a required secret is too short, or (when
> `APP_REQUIRE_SECURE_SECRETS=true`) is left at a known dev/placeholder default.
> See the [Common boot failures](#6-common-boot-failures) table for the exact
> messages and fixes.

For the **full** list of configuration flags, see
[`docs/security/configuration-reference.md`](../security/configuration-reference.md).

---

## 1. Pre-flight checklist — required secrets

Generate every secret fresh per environment. Never reuse a dev value, never
commit a real value. In GKE these live in **Google Secret Manager** and are
injected at deploy time (see [§4](#4-gke-deploy)).

| Secret | Env var | GSM secret | Generate with | Hard rule |
|---|---|---|---|---|
| JWT signing key | `JWT_SECRET` | `wf-jwt-secret` | `openssl rand -base64 64` | **≥ 64 bytes** (HS512 / `Keys.hmacShaKeyFor`) |
| At-rest encryption key | `APP_CRYPTO_SECRET` | `wf-app-crypto-secret` | `openssl rand -base64 32` | **≥ 16 chars** |
| DB password | `SPRING_DATASOURCE_PASSWORD` | `wf-db-password` | (your Cloud SQL user password) | must match the Cloud SQL user |
| SendGrid API key *(optional)* | `mail.password` | `wf-sendgrid-api-key` | (from SendGrid dashboard) | omit to leave email dormant |

### `JWT_SECRET` — SHARED, treat rotation as a coordinated event

```bash
openssl rand -base64 64
```

The minimum is **64 raw UTF-8 bytes** because the value is consumed directly by
`Keys.hmacShaKeyFor` for HS512. `openssl rand -base64 64` yields ~88 printable
chars, comfortably over the bar.

This key is **shared with external token consumers** (Safe Space, Krusty,
Commons — they verify WeldForge-issued tokens with the same HMAC). A fresh value
must be **distributed to every consumer at the same time** or their token
verification breaks. For a brand-new environment with no consumers yet, just
generate and store it. To change it later, follow the coordinated procedure in
[`docs/runbooks/key-rotation.md`](./key-rotation.md).

### `APP_CRYPTO_SECRET` — set once, do not rotate casually

```bash
openssl rand -base64 32
```

Minimum **16 characters**. This is the at-rest encryption key for secrets stored
in the DB (`EncryptedStringConverter` columns: tenant signing keys, OAuth client
secrets, SMTP creds, etc.). **Once data has been written under it, changing it
requires re-encrypting every stored secret** — there is no automatic migration.
Pick it at bootstrap and leave it alone.

### `SPRING_DATASOURCE_PASSWORD`

The Cloud SQL `wfuser` password. In prod the datasource points at the Cloud SQL
Auth Proxy sidecar (`jdbc:postgresql://127.0.0.1:5432/weldforge`, see
`values.yaml`). Store the password as GSM `wf-db-password`.

### SendGrid API key (optional)

Outbound email (password reset, email verification, identity-proofing
challenges) is **dormant until `mail.password` is supplied**. Create GSM
`wf-sendgrid-api-key` and `--set-string mail.password=...` to activate. With no
key, `LoggingMailService` is used and no `SPRING_MAIL_*` env is rendered — safe
to deploy without it. See `docs/email-deliverability.md`.

---

## 2. Turn on secret-hygiene enforcement

**Set `APP_REQUIRE_SECURE_SECRETS=true` in every non-dev deploy.** It is already
baked into Helm `infrastructure/helm/weldforge/values.yaml` (`api.env`), so a
standard GKE deploy gets it for free. If you deploy outside that chart, set it
yourself.

What the flag changes:

| State | Behaviour |
|---|---|
| Flag **unset / false** (dev) | Length checks still run, but a known dev/placeholder default is accepted — only a `WARN` is logged. **Risk: a real deploy that forgot to inject secrets silently runs on the insecure committed defaults.** |
| Flag **true**, secret missing | The env falls through to the `application.yml` dev default, which is on the known-insecure list → **boot fails** with a `Refusing to start` error naming the missing env (see table in §6). This is the desired behaviour: a missed injection becomes a crash, not a silent weak key. |
| Flag **true**, secrets good | `Secret hygiene checks passed (secure-secrets enforcement ON).` logged; boot continues. |

The two enforcement layers, from the validator:
1. **Always (every profile):** `JWT_SECRET` ≥ 64 bytes, `APP_CRYPTO_SECRET` ≥ 16 chars.
2. **Only when `APP_REQUIRE_SECURE_SECRETS=true`:** neither value may equal a
   known dev/placeholder default (the `application.yml` dev defaults **and** the
   Helm `changeme-...` placeholders).

---

## 3. WebAuthn / passkeys — override the RP ID and origins

The defaults are `localhost`-only and **will break passkey registration and
login in prod** (the browser binds a credential to the RP ID, which must match
the site host). Override both:

| Env var | Default (dev) | Production value |
|---|---|---|
| `APP_MFA_WEBAUTHN_RP_ID` | `localhost` | the registrable host users see, e.g. `sso.weldforge.org` |
| `APP_MFA_WEBAUTHN_ORIGINS` | `http://localhost:4200,http://localhost:8076` | the real HTTPS origin(s), comma-separated, e.g. `https://sso.weldforge.org` |
| `APP_MFA_WEBAUTHN_RP_NAME` | `WeldForge` | display name (optional) |

- **RP ID** must be a domain suffix of every origin. With per-tenant subdomains
  (`*.sso.weldforge.org`), set RP ID to the **apex** `sso.weldforge.org` so a
  passkey works across tenant subdomains, and include each origin you serve in
  `APP_MFA_WEBAUTHN_ORIGINS`.
- It must be `https` (except `localhost`). A mismatch surfaces as
  registration/assertion verification failures, not a boot error.

---

## 4. GKE deploy

The canonical path is a push to `main` → `.github/workflows/deploy-gcp.yml`.
For a manual / first-time deploy, use the helm command documented in
[`infrastructure/README.md`](../../infrastructure/README.md#deploying) — do not
re-type it here; that file is the source of truth. It:

- runs against project **`weldforge`**, region **`africa-south1`**, cluster
  **`weldforge-gke`**, namespace **`sso`**;
- injects the three GSM secrets via
  `--set-string api.secrets.{SPRING_DATASOURCE_PASSWORD,JWT_SECRET,APP_CRYPTO_SECRET}=$(gcloud secrets versions access latest --secret=...)`;
- uses `-f values-prod.yaml`, which carries `APP_REQUIRE_SECURE_SECRETS=true`
  from the base `values.yaml`.

Before deploying, confirm the three secrets exist:

```bash
for s in wf-db-password wf-jwt-secret wf-app-crypto-secret; do
  gcloud secrets describe "$s" --project weldforge >/dev/null \
    && echo "OK   $s" || echo "MISSING $s"
done
```

Get cluster creds (note: the dev-machine default kube context can revert — pass
the context explicitly on every `kubectl`):

```bash
gcloud container clusters get-credentials weldforge-gke \
  --region africa-south1 --project weldforge
CTX=gke_weldforge_africa-south1_weldforge-gke
```

If you are also standing up per-tenant subdomain auth URLs, the wildcard DNS +
TLS is a separate prerequisite — see
[`docs/runbooks/wildcard-tls-setup.md`](./wildcard-tls-setup.md).

---

## 5. Post-deploy verification

### a. App booted (no SecretHygiene failure)

```bash
kubectl --context=$CTX -n sso rollout status deploy/sso-api --timeout=300s
# Expect the success line; the WARN/ERROR forms are in §6.
kubectl --context=$CTX -n sso logs deploy/sso-api -c sso-api | grep -i "secret hygiene"
# Want: "Secret hygiene checks passed (secure-secrets enforcement ON)."
```

A crash-loop (`CrashLoopBackOff`) almost always means a SecretHygiene throw —
read the logs and match against §6.

### b. Health

`/actuator/**` is **not** exposed through the public ingress, so check it from
inside the pod:

```bash
kubectl --context=$CTX -n sso exec deploy/sso-api -c sso-api -- \
  curl -s http://localhost:8076/actuator/health
# {"status":"UP"}
```

### c. A live tenant's OIDC discovery returns 200 (outside-in)

Use the **`leap`** tenant (the canonical "prove it's live" tenant — public, no
auth). For your own domain, substitute your host:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  https://sso.weldforge.org/t/leap/.well-known/openid-configuration   # 200
curl -s -o /dev/null -w '%{http_code}\n' \
  https://sso.weldforge.org/t/leap/oauth2/jwks                        # 200
curl -s -o /dev/null -w '%{http_code}\n' \
  https://sso.weldforge.org/t/leap/saml2/idp/metadata                 # 200
```

> Do not use `/actuator/health` or a `demo` tenant as an outside-in check —
> `/actuator/**` falls through to the marketing SPA (returns HTML) and there is
> no `demo` tenant.

### d. Content-Type guard (415)

Confirms the request hardening is live:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' -d 'a=b' \
  https://sso.weldforge.org/api/auth/login                            # 415
```

---

## 6. Common boot failures

All of these are thrown by `SecretHygieneValidator` at startup → the pod
crash-loops. Fix the secret, redeploy.

| Log message (substring) | Cause | Fix |
|---|---|---|
| `app.jwt.secret must be at least 64 bytes (got N)` | `JWT_SECRET` unset or too short. `got 0` = env never reached the pod. | Set `JWT_SECRET` to `openssl rand -base64 64`; store as `wf-jwt-secret` and re-inject via `--set-string api.secrets.JWT_SECRET=...`. |
| `app.crypto.secret must be at least 16 characters` | `APP_CRYPTO_SECRET` unset or too short. | Set to `openssl rand -base64 32`; store as `wf-app-crypto-secret` and re-inject. |
| `app.jwt.secret is a known insecure default but app.security.require-secure-secrets=true ... JWT_SECRET ... was not injected` | Enforcement on, but the value is a dev/placeholder default → the `--set-string ... JWT_SECRET` override was missed. | Verify GSM `wf-jwt-secret` exists and is passed in the helm `--set-string`. Confirm the rendered env: `kubectl ... exec ... -- printenv JWT_SECRET` (should not be a `changeme-`/`dev-only-` value). |
| `app.crypto.secret is a known insecure default but app.security.require-secure-secrets=true ... APP_CRYPTO_SECRET ... was not injected` | Same as above, for the crypto key. | Verify GSM `wf-app-crypto-secret` and its `--set-string`. |
| `Running with dev-only default secrets ... MUST NOT happen on a real deployment` (a **WARN**, app still starts) | `APP_REQUIRE_SECURE_SECRETS` was **not** set, so a dev default was accepted. | This is the silent-weak-key trap. Set `APP_REQUIRE_SECURE_SECRETS=true` (it ships in `values.yaml`) and inject real secrets, then redeploy. |

Quick triage:

```bash
kubectl --context=$CTX -n sso describe pod -l app=sso-api | grep -A3 -i "last state\|reason"
kubectl --context=$CTX -n sso logs deploy/sso-api -c sso-api --previous | tail -n 40
```

---

## Related docs

- [`docs/security/configuration-reference.md`](../security/configuration-reference.md) — full flag reference.
- [`docs/runbooks/key-rotation.md`](./key-rotation.md) — coordinated `JWT_SECRET` rotation across token consumers.
- [`docs/runbooks/wildcard-tls-setup.md`](./wildcard-tls-setup.md) — per-tenant subdomain DNS + TLS.
- [`infrastructure/README.md`](../../infrastructure/README.md) — canonical helm deploy command and live-environment reference.
- [`docs/email-deliverability.md`](../email-deliverability.md) — activating SendGrid SMTP.
