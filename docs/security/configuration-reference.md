# WeldForge — Security Configuration Reference

> **Single source of truth for every security-relevant configuration flag.**
> Rows are derived directly from the live source:
> - `weldforge-auth/src/main/resources/application.yml`
> - `infrastructure/helm/weldforge/values.yaml` and `values-prod.yaml`
> - `weldforge-auth/src/main/java/tech/cwvermaak/weldforge/config/security/SecretHygieneValidator.java`
>
> If you change a security default in any of those files, update this doc in the same PR.

---

## 1. How configuration is layered

WeldForge reads configuration through Spring's property resolution, layered
lowest-to-highest precedence:

1. **`application.yml` defaults** — every property uses the
   `${ENV_VAR:default}` form, so the file always boots with a working dev
   default and no env vars set. The defaults are deliberately weak/dev-only for
   the security secrets (see §2).
2. **Environment variables** — override the YAML defaults. This is the only
   mechanism used in containers; nothing security-relevant is baked into the
   image.
3. **Helm values** — `infrastructure/helm/weldforge/values.yaml` (base) merged
   with `values-prod.yaml` (prod overrides). `api.env.*` becomes plain
   `env:` entries on the pod; `api.secrets.*` becomes secret-backed env entries.
4. **GCP Secret Manager injection** — the real production secret *values* are
   never in the chart. The deploy workflow sources them from GCP Secret Manager
   (project **`weldforge`**, region **`africa-south1`**) and injects them via
   `--set-string` / `secretRef` into the Kubernetes Secret that backs the
   `api.secrets.*` env vars. The placeholder strings committed in `values.yaml`
   (`changeme-…`) are tripwires: if one reaches runtime, the injection was
   missed and the app refuses to boot (see §2/§3).

Deployment target: GKE Autopilot cluster, namespace **`sso`**, deployment
`sso-api`.

---

## 2. Required production secrets

All three MUST be supplied at deploy time from GCP Secret Manager. The
application **fails to start** (throws at `@PostConstruct`,
`SecretHygieneValidator`) if any is blank, too short, or — when
`APP_REQUIRE_SECURE_SECRETS=true` — still equal to a known dev/placeholder
default.

| Secret (env var) | GSM secret name | Minimum | Purpose & rotation notes |
|---|---|---|---|
| `JWT_SECRET` (`app.jwt.secret`) | `wf-jwt-secret` | **≥ 64 bytes** (UTF-8). HS512 consumes it as a raw key via `Keys.hmacShaKeyFor`. | HMAC signing secret for legacy platform tokens. **Shared with external token consumers** (Safe Space / Krusty / Commons), which verify with the same key. **Rotation requires a coordinated roll across every consumer at the same time** — see [`docs/runbooks/key-rotation.md`](../runbooks/key-rotation.md). |
| `APP_CRYPTO_SECRET` (`app.crypto.secret`) | `wf-app-crypto-secret` | **≥ 16 chars** | Derives the AES-GCM key that encrypts per-tenant OAuth2 client secrets and RSA private keys **at rest** (`EncryptedStringConverter`). **Rotating it requires re-encrypting all existing at-rest data** — it is not a drop-in swap. Source from a KMS/HSM (PRD SEC-09). |
| `SPRING_DATASOURCE_PASSWORD` (`spring.datasource.password`) | `wf-db-password` | non-blank | Cloud SQL (`weldforge-db`) database password for user `wfuser`. Connects via the Cloud SQL Auth Proxy sidecar on `127.0.0.1:5432`. |

**Fail-fast behaviour (`SecretHygieneValidator`):**

- **Layer 1 — length, enforced in *every* profile** (including local dev):
  `app.jwt.secret` < 64 bytes → boot fails; `app.crypto.secret` < 16 chars →
  boot fails.
- **Layer 2 — known-default rejection, only when
  `APP_REQUIRE_SECURE_SECRETS=true`:** if either secret still equals one of the
  committed dev/placeholder defaults, boot fails. The rejected values are:
  - `dev-only-insecure-jwt-secret-do-not-use-in-production-change-me-now-0123456789`
  - `dev-only-change-me-weldforge-tenant-secret-key`
  - `changeme-generate-a-256-bit-secret-key-here` (Helm placeholder)
  - `changeme-source-from-kms-or-hsm` (Helm placeholder)

When enforcement is **off** and a dev default is detected, the app boots but
logs a `WARN` ("Running with dev-only default secrets … MUST NOT happen on a
real deployment").

---

## 3. `APP_REQUIRE_SECURE_SECRETS`

| | |
|---|---|
| **YAML path** | `app.security.require-secure-secrets` |
| **Default** | `false` (local dev — convenient dev defaults boot out of the box) |
| **Production** | `"true"` — set in `infrastructure/helm/weldforge/values.yaml` under `api.env` on **every cluster deploy** |

What it enforces: turns the Layer-2 known-default check on. With it set, a
missing `JWT_SECRET` or `APP_CRYPTO_SECRET` env (which would otherwise silently
fall through to the insecure `application.yml` default) becomes a **hard boot
failure** instead. This is the guardrail that guarantees a real deployment can
never run on a source-committed secret. The length checks (Layer 1) apply
regardless of this flag.

---

## 4. Full security-relevant flag reference

> "Recommended prod" = the value to run with in production. Where the Helm
> values already set it, that is noted; where the YAML default is already the
> right prod value, it is marked *(default OK)*.

### Password policy

| Env var | YAML path | Default | Recommended prod | Effect |
|---|---|---|---|---|
| `APP_PASSWORD_MIN_LENGTH` | `app.security.password.min-length` | `10` | `10`+ *(default OK)* | Minimum password length. |
| `APP_PASSWORD_MAX_LENGTH` | `app.security.password.max-length` | `72` | `72` *(default OK)* | Maximum length (72 = BCrypt byte ceiling). |
| `APP_PASSWORD_REQUIRE_UPPERCASE` | `app.security.password.require-uppercase` | `true` | `true` *(default OK)* | Require an uppercase letter. |
| `APP_PASSWORD_REQUIRE_LOWERCASE` | `app.security.password.require-lowercase` | `true` | `true` *(default OK)* | Require a lowercase letter. |
| `APP_PASSWORD_REQUIRE_DIGIT` | `app.security.password.require-digit` | `true` | `true` *(default OK)* | Require a digit. |
| `APP_PASSWORD_REQUIRE_SYMBOL` | `app.security.password.require-symbol` | `true` | `true` *(default OK)* | Require a symbol. |

### Account lockout

| Env var | YAML path | Default | Recommended prod | Effect |
|---|---|---|---|---|
| `APP_LOCKOUT_MAX_ATTEMPTS` | `app.security.lockout.max-attempts` | `5` | `5` *(default OK)* | Failed-login attempts before the account locks. |
| `APP_LOCKOUT_MINUTES` | `app.security.lockout.lock-minutes` | `15` | `15` *(default OK)* | Lockout duration in minutes. |

### Rate limiting (token-bucket per identifier)

| Env var | YAML path | Default | Recommended prod | Effect |
|---|---|---|---|---|
| `APP_RATE_LIMIT_ENABLED` | `app.security.rate-limit.enabled` | `true` | `true` *(default OK)* | Master switch. Disable only for load tests. |
| `APP_RATE_LIMIT_LOGIN_CAPACITY` | `app.security.rate-limit.login-capacity` | `10` | `10` *(default OK)* | Login bucket capacity. |
| `APP_RATE_LIMIT_LOGIN_REFILL_MINUTES` | `app.security.rate-limit.login-refill-minutes` | `15` | `15` *(default OK)* | Login bucket refill window. (Default: 10 logins / 15 min.) |
| `APP_RATE_LIMIT_MFA_CAPACITY` | `app.security.rate-limit.mfa-verify-capacity` | `15` | `15` *(default OK)* | MFA-verify bucket capacity. |
| `APP_RATE_LIMIT_MFA_REFILL_MINUTES` | `app.security.rate-limit.mfa-verify-refill-minutes` | `15` | `15` *(default OK)* | MFA-verify bucket refill window. |
| `APP_RATE_LIMIT_REGISTER_CAPACITY` | `app.security.rate-limit.register-capacity` | `5` | `5` *(default OK)* | Registration bucket capacity. |
| `APP_RATE_LIMIT_REGISTER_REFILL_MINUTES` | `app.security.rate-limit.register-refill-minutes` | `60` | `60` *(default OK)* | Registration bucket refill window. (Default: 5 registrations / 60 min.) |

### Token TTLs

| Env var | YAML path | Default | Recommended prod | Effect |
|---|---|---|---|---|
| `JWT_EXPIRATION_MS` | `app.jwt.access-token-expiration-ms` | `300000` (**5 min**) | `300000` (set in Helm `api.env`) | Access-token lifetime. Short by design. |
| `REFRESH_TOKEN_EXPIRATION_MS` | `app.jwt.refresh-token-expiration-ms` | `604800000` (**7 days**) | `604800000` (set in Helm `api.env`) | Refresh-token JWT expiry. |
| `APP_REFRESH_TOKEN_LIFETIME_DAYS` | `app.security.refresh-token.lifetime-days` | `30` | `30` *(default OK)* | Server-side refresh-token record lifetime (absolute cap on a refresh chain). |

### Key rotation (per-tenant signing keys)

| Env var | YAML path | Default | Recommended prod | Effect |
|---|---|---|---|---|
| `APP_KEY_ROTATION_ENABLED` | `app.key-rotation.enabled` | `false` | `"true"` (set in Helm `api.env` + `values-prod.yaml`) | Enable the scheduled signing-key rotation job. |
| `APP_KEY_ROTATION_INTERVAL_MS` | `app.key-rotation.interval-ms` | `86400000` (24 h) | `86400000` *(default OK)* | How often the rotation job runs. |
| `APP_KEY_ROTATION_MAX_AGE_DAYS` | `app.key-rotation.max-age-days` | `90` | `90` (set in Helm `api.env` + `values-prod.yaml`) | Age at which a signing key is rotated out. |

### MFA — WebAuthn & TOTP

| Env var | YAML path | Default | Recommended prod | Effect |
|---|---|---|---|---|
| `APP_MFA_WEBAUTHN_RP_ID` | `app.mfa.webauthn.rp-id` | `localhost` | **`sso.weldforge.org`** | WebAuthn Relying Party ID — the bare host (no scheme, no port). **⚠️ MUST be overridden to the production host. If left as `localhost`, WebAuthn origin binding fails and every passkey/security-key ceremony breaks in prod.** Not currently set in the committed Helm values — set it. |
| `APP_MFA_WEBAUTHN_RP_NAME` | `app.mfa.webauthn.rp-name` | `WeldForge` | `WeldForge` *(default OK)* | Display name shown in the authenticator prompt. |
| `APP_MFA_WEBAUTHN_ORIGINS` | `app.mfa.webauthn.origins` | `http://localhost:4200,http://localhost:8076` | **`https://sso.weldforge.org`** (and any per-tenant `*.sso.weldforge.org` origins in use) | Comma-separated list of origins the WebAuthn library will accept. **Must include the real prod origin(s)** or assertions are rejected. |
| `APP_MFA_TOTP_ISSUER` | `app.mfa.totp.issuer` | `WeldForge` | `WeldForge` *(default OK)* | Issuer label embedded in TOTP enrolment URIs (shown in authenticator apps). |

### CORS

| Env var | YAML path | Default | Recommended prod | Effect |
|---|---|---|---|---|
| `APP_CORS_ALLOWED_ORIGINS` | `app.cors.allowed-origins` | `http://localhost:4200,https://www.weldforge.org` | `https://sso.weldforge.org,https://*.sso.weldforge.org,https://app.wellspring.org.za` (rendered from Helm `cors.allowedOrigins`) | Allowed CORS origins. Wildcard-aware via the `*` suffix, so one `*.sso.weldforge.org` entry covers every tenant subdomain. `values-prod.yaml` narrows the list (drops the wildcard tenant entry; confirm against the current file before relying on it). |

### Public host / tenant resolution

| Env var | YAML path | Default | Recommended prod | Effect |
|---|---|---|---|---|
| `APP_PUBLIC_BASE_DOMAIN` | `wf.public.base-domain` | `sso.weldforge.org` | `sso.weldforge.org` (set in Helm `api.env`) | Drives Host-header tenant resolution (`TenantResolverFilter`) and outbound URL construction (password-reset email links, OIDC login redirects). |
| `APP_PUBLIC_SCHEME` | `wf.public.scheme` | `https` | `https` (set in Helm `api.env`) | Scheme used when constructing outbound absolute URLs. |
| `APP_PUBLIC_RESERVED_LABELS` | `wf.public.reserved-labels` | `www,api,admin,app,mail,static` | same (set in Helm `api.env`) | Subdomain labels that never resolve to a tenant (prevents tenant slugs from shadowing infra hostnames). |
| `APP_PUBLIC_SLUG_HOLDBACK_DAYS` | `wf.public.slug-holdback-days` | `90` | `90` (set in Helm `api.env`) | Days a deleted tenant's slug stays unavailable for reuse — closes the identity-confusion window after a tenant delete. **`0` disables the holdback — testing only, not safe in production.** |

### SCIM

| Env var | YAML path | Default | Recommended prod | Effect |
|---|---|---|---|---|
| `APP_SCIM_BULK_MAX_OPERATIONS` | `app.scim.bulk.max-operations` | `100` | `100` *(default OK)* | Max operations accepted in a single SCIM Bulk request (DoS guard). |

---

## 5. Hardening defaults already on

These ship secure by default — no action needed to enable them, but know they
are load-bearing:

- **Rate limiting is ON by default** (`app.security.rate-limit.enabled=true`):
  login 10/15min, MFA-verify 15/15min, register 5/60min.
- **Account lockout: 5 attempts / 15 min** (`app.security.lockout.*`).
- **BCrypt cost factor 12** for password hashing — real logins are
  intentionally ~hundreds of ms; do not lower it.
- **JWT clock-skew tolerance 60s** on token validation.
- **`spring.jpa.hibernate.ddl-auto=validate`** — schema changes go through
  Flyway only; the app never mutates the schema at runtime.
- **`server.forward-headers-strategy=native`** + Tomcat `RemoteIpValve` so
  generated absolute URLs (OIDC issuer, redirect URIs) carry the original
  `https` scheme behind the GCP HTTPS load balancer.
- **`/actuator/**` exposes only** `health,prometheus,circuitbreakers`, with
  `health.show-details=when-authorized`. Actuator is **not** routed through the
  public ingress.

### Cross-links

- [`docs/security/hardening-backlog.md`](./hardening-backlog.md) — open
  hardening items not yet shipped.
- [`docs/threat-model.md`](../threat-model.md) — the threat model these
  controls map to.
- [`docs/runbooks/key-rotation.md`](../runbooks/key-rotation.md) — coordinated
  `JWT_SECRET` rotation across external consumers.
- [`docs/auth-url-spec.md`](../auth-url-spec.md) — per-tenant subdomain auth
  URL contract (drives the public-host flags above).
