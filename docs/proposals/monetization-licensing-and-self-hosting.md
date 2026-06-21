# Proposal — WeldForge Monetization, Licensing, Vouchers & Self-Hosting

> **Status: DRAFT for review.** Nothing here is implemented yet. Decisions you
> confirmed are marked ✅; open decisions for you are in §10. Prices are
> illustrative placeholders — **`[confirm]`**.
> Author: identity/security review, 2026-06-21.

## 1. Goal

Turn WeldForge into a **passive, recurring-revenue** product that is **free/low-cost
for SMMEs** and **more attractive than Keycloak and Entra/Okta/Auth0** — without
losing the self-hostable, own-your-data character.

## 2. Positioning (how we beat the incumbents)

| Competitor | Their weakness | WeldForge wedge |
|---|---|---|
| **Keycloak** (free OSS) | Can't beat $0 on price — but high TCO: you run Java/infra, do upgrades, multi-realm tenancy is clunky | **Managed cloud + radically simpler ops + first-class multi-tenancy + POPIA/SA data residency.** Sell "we run it / it's easier," not "cheaper." |
| **Entra / Okta / Auth0** | Per-user/per-MAU pricing punishes growth; opaque tiers; vendor lock-in | **Transparent flat low pricing, no per-seat gouging, own-your-data, self-host escape valve** (anti-lock-in is itself a selling point) |

**Revenue wedge (proven — WorkOS model):** core auth (OIDC/OAuth2 + basic MFA)
**free** for SMMEs; charge for the **enterprise connectors** (SAML, SCIM/directory
sync), **scale** (more users/tenants), and **managed cloud**. Enterprises happily
pay for SSO/SCIM; SMMEs ride the free core and convert as they grow (product-led
growth → low-touch → passive).

## 3. Tiers ✅ (open-core, per-tenant cap)

| Tier | Price `[confirm]` | Tenants | Users / tenant | Features |
|---|---|---|---|---|
| **Community** (free, self-host) | $0 | 1 | **25** | OIDC/OAuth2, TOTP MFA, custom branding, community support |
| **Starter** | ~$19/mo `[confirm]` | 1 | ~100 | + email support, password policies, longer audit |
| **Business** | ~$99/mo `[confirm]` | up to ~5 | ~500 | + **SAML**, **SCIM/dir-sync**, **WebAuthn/SMS MFA**, extended audit retention |
| **Enterprise / Cloud** | custom | many / unlimited | high/unlimited | + SLA, priority support, data residency, SSO connectors at scale |

- **Pricing shape:** flat per-tier monthly (predictable, SMME-friendly) — **not
  per-seat.** Optional per-extra-tenant add-on for partners/MSPs running many
  client orgs (this monetizes our multi-tenant strength directly).
- **Free cap ✅** = 1 tenant, ~25 users in it. Multi-tenant and enterprise
  connectors are the paid lines.

## 4. Licensing architecture ✅ — signed offline license keys

- A **license** is an **Ed25519-signed** compact token encoding:
  `{ licenseId, licensee, tier, maxTenants, maxUsersPerTenant, features[],
  issuedAt, expiresAt, grace }`.
- The app embeds **only the WeldForge public key** and verifies the license at
  boot; the **private signing key stays offline with you** (the issuer) — never in
  the app or repo. This is the GitLab/Sentry/Metabase pattern.
- **No license installed → built-in Community entitlement** (1 tenant / 25 users /
  core features). So a fresh self-host "just works" for free, capped.
- **Self-host = honor-backed** (license law; fine for the SMME/business market).
  **Managed cloud = absolute** (we run it).
- **No phone-home** — good for POPIA / air-gapped. (Cloud can additionally verify
  server-side.)
- **Graceful expiry (recommended):** on expiry, **don't lock existing users out** —
  revert to Community limits: keep existing users working, **block new creation
  past the free cap** and disable paid features, with loud admin warnings during a
  grace window. (Hard-locking paying customers out on a lapsed card is hostile and
  a support nightmare.)

## 5. Enforcement points

A central `EntitlementService` is consulted at:
- **User creation** — `register`, admin invite, SCIM provisioning, federated JIT →
  count active users in the tenant; past `maxUsersPerTenant` → **block with a clear
  upgrade message** (HTTP 402/403 + machine code `entitlement_user_limit`).
- **Tenant creation** — past `maxTenants` → blocked.
- **Feature use** — SAML/SCIM/WebAuthn/SMS/audit-retention/branding gated by
  `features[]` (`EntitlementService.requireFeature(...)`).
- **Grandfathering** — an install already over a (newly lowered) cap is **warned,
  not retroactively locked**; only *growth* is blocked.

> These are the **same code paths the sign-up approval gate touches** — so we build
> the entitlement check and the approval gate together to avoid editing
> `register`/invite/SCIM/JIT twice.

## 6. Vouchers / coupons (marketing) — NEW

Two complementary mechanisms:

**(a) Pre-signed grant licenses (self-host).** A "voucher" can simply *be* a
time-boxed signed license you generate and hand out (conference codes, design
partners, "free Business for 6 months"). Redemption = paste the key. No server
needed — works for self-hosters.

**(b) Redeemable voucher codes (cloud / order funnel).** A short human code
(`WELDFORGE-SMME-AB12`) the user redeems in the portal/checkout. On redemption the
system issues the matching entitlement (or applies a discount to a paid plan).
Needs a small voucher store + redemption endpoint with single-use / usage-limit /
expiry tracking — and gives you **campaign analytics** (which code drove signups).

**Voucher model:**
`code, campaign, type (FREE_TIER_GRANT | PERCENT_DISCOUNT | FIXED_DISCOUNT),
grantsTier, durationDays, maxRedemptions, perAccountLimit, validFrom, validUntil,
status` + a `voucher_redemptions` record (code, tenant/account, timestamp).

- **Discount vouchers** plug into the existing **order funnel** (`PendingOrder` /
  `Subscription` / payment gateways) — apply % or fixed off at checkout.
- **Grant vouchers** issue a `Subscription` + license **without payment**.
- Admin UI: create/disable codes, set caps/expiry, see redemption counts.

This is your marketing lever: seed SMMEs and communities cheaply, track what
converts, upsell when the voucher lapses.

## 7. Self-hosting fixes (prerequisite for a credible "free install")

The self-install review found the free-install story is **not real yet**. Top gaps:

1. **🔴 No `LICENSE` file in the repo at all.** README says "source-available,
   free for self-host eval/dev/non-commercial," but by default copyright **a clone
   grants no right to run/modify** — which contradicts the advertised free tier and
   the whole monetization plan. **This must be fixed first.** Recommended:
   **Business Source License (BSL 1.1)** — free for self-host/dev/non-production and
   small-scale use, paid for production-at-scale, auto-converts to an OSS license
   after N years. It's purpose-built for exactly this "free for SMMEs, pay at scale,
   still source-available" model (used by HashiCorp, Sentry, CockroachDB). Alternatives:
   SSPL (stricter, anti-cloud-competitor) or a custom source-available grant.
2. **No self-hosting doc / portable artifacts.** The Helm chart is GKE-only
   (gce ingress, GKE ManagedCertificate, Cloud SQL proxy, Workload Identity, the
   maintainer's Artifact Registry); `postgres.enabled: true` is a dead toggle (no
   StatefulSet template). Add `docs/self-hosting.md` + a self-contained
   `docker-compose.selfhost.yml` (app + db + **admin-portal**, with secret
   generation) and a `values-selfhost.yaml` (configurable `ingressClassName`,
   cert-manager, real in-cluster Postgres, direct datasource, parameterized images).
3. **README quickstart inaccuracies** (`db` vs `postgres` service; `:8076` is the
   API not the portal; version drift) — erodes trust on first read.
4. **Marketing vs repo mismatch** — `deployment.html` / the blog promise generic
   K8s manifests + a compose that won't run against the real image. Reconcile.

## 8. Sign-up approval gate (already designed, in flight)

The per-tenant approval gate (✅ decided: **local + federated**, **domain-allowlist +
manual**, **after email verification**) is ready to build and shares §5's
enforcement points. Proposed as a **Business-tier** feature (gated org onboarding is
an enterprise need) — or keep it free; your call (§10).

## 9. Phased implementation plan

| Phase | Scope | Revenue-relevant? |
|---|---|---|
| **0 — Legal/docs (unblocks free install)** | `LICENSE` (BSL 1.1), `docs/self-hosting.md`, self-contained compose, README fixes | Prerequisite |
| **1 — Entitlement core** | `EntitlementService`, Ed25519 license verify, Community default, enforce caps at user/tenant creation, admin "License" view | ✅ enables paid |
| **2 — Open-core feature gates** | gate SAML/SCIM/WebAuthn/SMS/audit/branding by `features[]` | ✅ |
| **3 — Vouchers/coupons** | voucher model + redemption + discounts in order funnel + campaign tracking | ✅ marketing |
| **4 — Sign-up approval gate** | the designed gate (local+federated, domain allowlist, post-verification) | feature |
| **5 — Cloud billing polish** | self-serve upgrade, Stripe → subscription → license issuance, license/voucher admin portal | ✅ |

Each phase ships independently with TDD/BDD, on its own branch/PR.

## 10. Open decisions for you

1. **License text:** BSL 1.1 (recommended) / SSPL / custom source-available?
2. **Prices** per tier (the `[confirm]` cells in §3)?
3. **Free cap:** exactly **25 users / 1 tenant**? (1 tenant free ✅; confirm the 25.)
4. **Expiry behaviour:** graceful degrade-to-Community (recommended) vs hard cap?
5. **Vouchers:** both pre-signed grant licenses *and* cloud redeemable codes (recommended), or just one?
6. **Approval gate:** Business-tier feature, or free for all tiers?
7. **Phase order:** start with Phase 0 (legal/docs) — agreed? It unblocks everything else and is low-risk.
