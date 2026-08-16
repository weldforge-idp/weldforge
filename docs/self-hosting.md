# Self-hosting WeldForge

Run your own WeldForge instance. This is the supported path for the free
**Community** tier and for self-hosted paid tiers.

## License & free-tier limits

WeldForge is **source-available** under the **Business Source License 1.1**
([`LICENSE`](../LICENSE)). You may run it in production **for free** up to the
**Community** limits — **1 tenant and 25 users** — and use it at any scale for
non-production (dev/test/eval). Beyond that, or for paid features (SAML, SCIM,
advanced MFA, multi-tenant), you need a commercial subscription or a license key.
See [weldforge.org](https://www.weldforge.org).

## Prerequisites

- Docker + Docker Compose (the quickest path), **or** a Kubernetes cluster.
- A Postgres 14+ database (the compose bundles one).
- For a real deployment: a domain + TLS (a reverse proxy or your ingress).

You do **not** need a JDK or Node toolchain. The compose stack pulls prebuilt
images from GitHub Container Registry:

| Image | Architectures |
|---|---|
| `ghcr.io/weldforge-idp/weldforge-auth` | linux/amd64, linux/arm64 |
| `ghcr.io/weldforge-idp/weldforge-admin-portal` | linux/amd64, linux/arm64 |

arm64 is built natively rather than emulated, so a Raspberry Pi, an Ampere VPS
or Apple Silicon pulls the same tag as everyone else.

**Pin a version in production.** `latest` moves only on tagged releases (never
on a `main` build), but pinning is still the right habit:

```bash
echo 'WF_VERSION=v1.2.3' >> .env
```

Contributors who want to build from source instead of pulling can add `--build`
to any `up` command — `build:` is retained in the compose file for exactly that.

## Quick start (Docker Compose — full stack)

This brings up the **API + Postgres + admin portal** from source.

```bash
git clone https://github.com/weldforge-idp/weldforge
cd weldforge

# 1. Configure
cp .env.selfhost.example .env

# 2. Generate strong secrets into .env (the app refuses to boot without them)
#    JWT_SECRET >= 64 bytes, APP_CRYPTO_SECRET >= 16 chars, a DB password:
#      openssl rand -base64 64   # -> JWT_SECRET
#      openssl rand -base64 32   # -> APP_CRYPTO_SECRET
#      openssl rand -base64 24   # -> DB_PASSWORD
#    Also set WF_BOOTSTRAP_ADMIN_EMAIL to the email you'll register as admin.

# 3. Launch (pulls prebuilt images; add --build to compile from source instead)
docker compose -f docker-compose.selfhost.yml up -d
```

- **Admin portal:** http://localhost:8080
- **Backend API:** http://localhost:8076
- **Health:** http://localhost:8080/health → `{"status":"UP"}`

> The `weldforge-auth/docker-compose.yml` file is a **backend-only dev** stack
> (API + Postgres, no portal). Use `docker-compose.selfhost.yml` (repo root) for
> the full self-host stack.

## Create the first super-admin

A fresh install has no admins, and admin/tenant creation is **not** reachable
from self-registration (by design). Mint the first super-admin via infrastructure
control:

1. Register your user in the app (the admin portal sign-up, or `POST
   /api/auth/register`).
2. Set `WF_BOOTSTRAP_ADMIN_EMAIL` in `.env` to that email and restart
   (`docker compose -f docker-compose.selfhost.yml up -d`). On boot the user is
   promoted to super-admin.
3. **Unset it again** afterwards (hygiene). Full detail:
   [`runbooks/production-bootstrap.md` §7](runbooks/production-bootstrap.md#7-establish-the-first-super-admin).

## Customising the login & password-reset forms (branding)

Each tenant's auth screens are themeable. Set branding either in the admin portal
(**Tenants → Branding**) or via the API:

```
PUT /api/admin/tenants/{id}    body: { "branding": { ... }, "displayName": "..." }
```

Supported `branding` keys include `logoUrl`, `primaryColor`, `primaryDarkColor`,
`accentColor`, `bgColor`, `bg2Color`, `textColor`, `displayFont`, `sansFont`,
`tagline`, `eyebrow`, `headline`, `ctaLabel`. Per-tenant toggles:
`registrationEnabled`, `passwordRecoveryEnabled`, `emailVerificationRequired`,
`returnToCallerEnabled`. See [`tenant-branding.md`](tenant-branding.md).

## Hosting shapes: single-host vs per-tenant subdomains

WeldForge builds each tenant's login URL as `https://{slug}.<base-domain>/login`.

- **Single-host eval (localhost / one domain):** the apex/`default`-tenant
  fallback serves auth at the base host — fine for evaluation and small setups.
- **Per-tenant subdomains (recommended for multi-tenant):** point
  `APP_PUBLIC_BASE_DOMAIN` at your domain and provision **wildcard DNS
  (`*.example.com`) + wildcard TLS**, so every tenant gets its own branded,
  cookie-isolated origin. WebAuthn requires a single registrable RP-ID across
  those subdomains — set `WF_WEBAUTHN_RP_ID` to the apex.

## Production hardening checklist

- **Put it behind TLS** (a reverse proxy / load balancer terminating HTTPS) and
  set `WF_SCHEME=https`, `WF_BASE_DOMAIN=your.domain`.
- **`APP_REQUIRE_SECURE_SECRETS=true`** (default in the self-host compose) — boot
  fails on placeholder secrets.
- **WebAuthn:** set `WF_WEBAUTHN_RP_ID` / `WF_WEBAUTHN_ORIGINS` to your real host,
  or passkeys break.
- **Email:** outbound mail (verification, password reset) is dormant until SMTP
  is configured — see [`email-deliverability.md`](email-deliverability.md).
- Full flag reference: [`security/configuration-reference.md`](security/configuration-reference.md).

## Upgrades

Pull the new code and rebuild; **Flyway** applies schema migrations automatically
at boot. Back up the database first. `APP_CRYPTO_SECRET` must not change between
runs (it encrypts stored secrets).

## Kubernetes (non-GKE)

The chart in `infrastructure/helm/weldforge` currently assumes GKE (gce ingress,
Google ManagedCertificate, Cloud SQL proxy, Workload Identity). A portable
`values-selfhost.yaml` (configurable `ingressClassName` + cert-manager, an
in-cluster Postgres, direct datasource, parameterised images) is on the roadmap.
Until then, Docker Compose above is the supported self-host path.

## Related

- [`runbooks/production-bootstrap.md`](runbooks/production-bootstrap.md) — secrets, first-admin, hardening.
- [`security/configuration-reference.md`](security/configuration-reference.md) — every config flag.
- [`auth-url-spec.md`](auth-url-spec.md) — the per-tenant auth URL contract.
