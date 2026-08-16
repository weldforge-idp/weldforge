<div align="center">

<img src="weldforge-www/public/weldforge-logo.svg" alt="WeldForge" width="96">

# WeldForge

### Multi-tenant federated identity platform — one binary, every protocol.

OIDC issuer • SAML 2.0 SP + IdP • SCIM 2.0 • MFA (TOTP / WebAuthn / SMS) • Internal per-tenant PKI • HMAC-signed audit webhooks • M2M API keys with path/method scopes • Multi-tenant from the database up

[![Website](https://img.shields.io/badge/website-weldforge.org-4A8FF5)](https://www.weldforge.org)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.8-6DB33F)](https://spring.io/projects/spring-boot)
[![Java](https://img.shields.io/badge/Java-25-ED8B00)](https://openjdk.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14+-336791)](https://www.postgresql.org/)
[![Security audit](https://img.shields.io/badge/security%20audit-April%202026-brightgreen)](SECURITY_AUDIT_2026-04-15.md)

[**Documentation**](https://www.weldforge.org) ·
[**Pricing**](https://www.weldforge.org/pricing.html) ·
[**Compare**](https://www.weldforge.org/compare/) ·
[**Tutorials**](https://www.weldforge.org/tutorials.html) ·
[**For AI agents**](https://www.weldforge.org/agents.html)

</div>

---

## What it is

WeldForge is a single Spring Boot jar that speaks every identity protocol your
applications already know how to talk to:

- **OAuth 2.0 + OpenID Connect** — per-tenant issuer with its own signing key
- **SAML 2.0** — both as a Service Provider (federate upstream IdPs) and as an
  Identity Provider (issue assertions to downstream SPs)
- **SCIM 2.0** — inbound + outbound, Users and Groups
- **LDAP / Active Directory** — bind-on-login with break-glass fallback
- **MFA** — TOTP, WebAuthn, SMS OTP, backup codes, per-tenant policy enforcement
- **X.509 PKI** — per-tenant CA, CRL, OCSP responder, mTLS client certs
- **HMAC-signed audit webhooks** — every authentication, admin action, lifecycle
  event; retry queue + dead-letter
- **Scoped API keys** — `{path, methods}`-restricted, hashed at rest
- **Service-account tokens** — M2M identity with admin role

Every query is tenant-scoped from the database up. One installation serves many
customers (or many environments of a single customer) with strict isolation.

## 5-minute quickstart

```bash
git clone https://github.com/weldforge-idp/weldforge
cd weldforge/weldforge-auth
docker compose up -d postgres
./mvnw spring-boot:run
# ──
# The API is now on http://localhost:8076. Nothing seeds a user, so there are
# no credentials to log in with yet — create the first one, then promote it:
#
#   curl -X POST http://localhost:8076/api/auth/register \
#     -H "X-Tenant-Slug: default" -H "Content-Type: application/json" \
#     -d '{"name":"You","email":"you@example.com","password":"CorrectHorse-9!"}'
#
#   APP_ADMIN_BOOTSTRAP_SUPER_ADMIN_EMAIL=you@example.com ./mvnw spring-boot:run
#
# That promotes the account to SUPER_ADMIN on start-up; sign in again
# afterwards, because the promotion invalidates earlier tokens. Swagger UI is
# at http://localhost:8076/swagger-ui/index.html and needs an
# x-app-authorization key — see the tutorials page.
```

Full walkthrough: [weldforge.org/tutorials](https://www.weldforge.org/tutorials.html)

## Why another identity platform?

Because the existing options all make you pay somewhere:

- **Auth0** — feature-complete but Enterprise pricing bites hard at 25k+ MAU,
  and SAML IdP / SCIM / audit webhooks are gated behind custom-priced tiers.
  [→ WeldForge vs Auth0](https://www.weldforge.org/compare/auth0.html)
- **Keycloak** — free to self-host, but you absorb the operational cost and
  write SPIs for anything beyond the core. No first-party managed cloud.
  [→ WeldForge vs Keycloak](https://www.weldforge.org/compare/keycloak.html)
- **FusionAuth** — genuinely cheaper flat-rate pricing at scale; we credit
  that openly. WeldForge wins on POPIA-native residency, SAML IdP emphasis,
  built-in PKI, scoped API keys.
  [→ WeldForge vs FusionAuth](https://www.weldforge.org/compare/fusionauth.html)
- **Clerk** — unmatched React DX under 10k MAU. Falls off when enterprise
  buyers ask for SAML SSO or SCIM provisioning.
  [→ WeldForge vs Clerk](https://www.weldforge.org/compare/clerk.html)

WeldForge's bet: a **source-available** backend with **per-tenant OIDC + SAML
IdP**, **built-in PKI**, **HMAC audit webhooks**, and a hosted option in
**Cape Town** (POPIA-native) — priced transparently from $29/mo with a free
self-host tier.

## Architecture

```
              ┌──────────────────────────────────────────────────┐
              │                  WeldForge                        │
              │                                                   │
Browser ───►  │  ┌─ Spring Boot 3.5.8 (Java 25) ───────────────┐ │
              │  │    REST + OIDC + SAML + SCIM + PKI          │ │
App ────────► │  │    Resilience4j circuit breakers             │ │
              │  │    Prometheus metrics + health probes        │ │
SP ─────────► │  └──────────────────────────────────────────────┘ │
              │                                                   │
              │  ┌─ Postgres 14+ ──────────────────────────────┐ │
              │  │    Flyway-managed schema (V44 migrations)    │ │
              │  │    Tenant-scoped queries enforced at DAO     │ │
              │  └──────────────────────────────────────────────┘ │
              │                                                   │
              │  ┌─ Angular 21 admin portal (separate pod) ────┐ │
              │  └──────────────────────────────────────────────┘ │
              └──────────────────────────────────────────────────┘
```

Runs as one jar + one database. Scales horizontally behind a load balancer
— no per-pod state beyond Postgres connection pools.

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Spring Boot 3.5.8, Java 25, JPA/Hibernate 6 |
| Database | PostgreSQL 14+, Flyway migrations |
| SAML | OpenSAML 4 + Spring Security SAML |
| OAuth2 / OIDC | Hand-rolled issuer (JJWT-signed; no Spring Authorization Server) |
| MFA | Custom TOTP, Yubico WebAuthn, Twilio SMS |
| PKI | Bouncy Castle (CA / CRL / OCSP / client certs) |
| Payments | Stripe (first gateway; abstraction supports Paddle / PayFast / Yoco / Peach) |
| Admin portal | Angular 21, TypeScript, served by nginx |
| Container | Docker / Kubernetes manifests under `infrastructure/` |
| Test | JUnit 5 + Cucumber (153 BDD scenarios, 684 steps) |
| Observability | Prometheus, Resilience4j, Spring Actuator |

## Deployment options

Six supported topologies, [documented in full here](https://www.weldforge.org/deployment.html):

| Model | Who runs it | Starting price |
|---|---|---|
| Self-host OSS (Developer tier) | You | **Free, unlimited** |
| Self-host + support | You | $249/mo |
| Cloud shared | WeldForge | $29/mo (free under 500 MAU) |
| Cloud dedicated | WeldForge | From $4 999/mo |
| On-prem managed | You, we operate | From $9 999/mo |
| Air-gapped appliance | You, offline | Custom |

## Repository layout

```
weldforge/
├── weldforge-auth/              # Spring Boot backend (Java 25)
│   ├── src/main/java/.../            # Production code
│   ├── src/main/resources/           # application.yml + Flyway migrations
│   └── src/test/java/.../bdd/        # Cucumber BDD coverage
├── weldforge-admin-portal/      # Angular 21 admin console
├── weldforge-www/               # Marketing site (github.com/weldforge-idp -> weldforge.org)
├── infrastructure/
│   └── helm/weldforge/             # Helm chart deployed to GKE Autopilot (weldforge-gke, africa-south1)
├── SECURITY_AUDIT_2026-04-15.md  # Internal security review — Phase 1 (passive)
└── VALIDATION_REPORT_2026-04-17.md  # Follow-up validation pass
```

## Security

WeldForge underwent an internal security review in April 2026 (Phase 1, passive
analysis) covering OWASP Top 10, authentication, authorisation, data protection,
cryptographic primitives and dependency SCA, followed by a validation pass. See
[SECURITY_AUDIT_2026-04-15.md](SECURITY_AUDIT_2026-04-15.md) and
[VALIDATION_REPORT_2026-04-17.md](VALIDATION_REPORT_2026-04-17.md). A full
independent third-party penetration test has **not** yet been completed; the
hardening backlog is tracked in
[docs/security/hardening-backlog.md](docs/security/hardening-backlog.md), with a
consolidated [threat model](docs/threat-model.md).

**Recent hardening (June 2026).** Secret-hygiene boot validation (fail-fast on
weak/default secrets); OAuth2 consent CSRF token, deny-path open-redirect fix and
scope enforcement; constant-time client-secret checks and JWT clock-skew
tolerance; MFA TOTP anti-replay and single-use challenge tokens; tenant-scoped
admin-role assignment; SAML inbound XXE-hardened parsing and per-SP AuthnRequest
signature verification. See the backlog (F1–F12) for details.

**Operating WeldForge:**
[Configuration reference](docs/security/configuration-reference.md) ·
[Production bootstrap](docs/runbooks/production-bootstrap.md) ·
[Key rotation](docs/runbooks/key-rotation.md) ·
[Incident response](docs/runbooks/incident-response.md) ·
[Relying-party onboarding](docs/integrations/relying-party-onboarding.md).

To report a security issue, email **security@weldforge.org**. Do not open a
public GitHub issue. We acknowledge within 48 hours and publish a CVE with
credit where warranted.

## Documentation

- **Product overview** — https://www.weldforge.org
- **Tutorials** (curl recipes for every flow) — https://www.weldforge.org/tutorials.html
- **For AI agents** — https://www.weldforge.org/agents.html (includes machine-readable `ai-manifest.json`)
- **Deployment models** — https://www.weldforge.org/deployment.html
- **Pricing** — https://www.weldforge.org/pricing.html
- **Cost calculator** — https://www.weldforge.org/calculator.html

## Contributing

Issues and pull requests are welcome for:

- Bug fixes
- Documentation improvements
- New gateway Strategy implementations (Paddle / PayFast / Yoco / Peach)
- Additional migration converters (from Auth0 / Okta / Keycloak / FusionAuth / Clerk)
- Additional LDAP dialects or CRM connectors

Substantial feature additions should be discussed in an issue first so we
can align on scope and API shape. See `weldforge-auth/src/test/resources/features/`
for the BDD conventions — new features ship with Gherkin scenarios.

## License

Source-available under a commercial licence. Free for self-host evaluation,
development and non-commercial production use. Paid licensing required for
commercial production use above the free tier thresholds — see
[pricing.html](https://www.weldforge.org/pricing.html).

The full LICENSE document ships separately to paying customers.

## Contact

- **Website**: https://www.weldforge.org
- **Sales**: sales@weldforge.org
- **Support**: support@weldforge.org
- **Security**: security@weldforge.org
- **GitHub issues**: https://github.com/weldforge-idp/weldforge/issues

---

<div align="center">
<sub>Built by <a href="https://www.weldforge.org">WeldForge</a> · Made in Cape Town, South Africa · POPIA-native by design</sub>
</div>
