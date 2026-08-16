# Proposal — WeldForge Monetization, Licensing, Vouchers, Hosting & Self-Hosting

> **Status: DRAFT for review.** Nothing here is implemented yet. Decisions you
> confirmed are marked ✅; open decisions for you are in §11. Prices are
> illustrative placeholders — **`[confirm]`**.
> Author: identity/security review, 2026-06-21.

## 1. Goal

Turn WeldForge into a **passive, recurring-revenue** product that is **free/low-cost
for SMMEs** and a genuinely **more attractive alternative to Keycloak** (and to
Entra/Okta/Auth0) — without losing the self-hostable, own-your-data character.

## 2. Positioning (how we beat the incumbents)

| Competitor | Their weakness | WeldForge wedge |
|---|---|---|
| **Keycloak** (free OSS) | Can't beat $0 on price — but high TCO: you run Java/infra, do upgrades, multi-realm tenancy is clunky, and it offers **one topology only: self-host** | **A whole spectrum of hosting models (§4) + managed cloud + radically simpler ops + first-class multi-tenancy + POPIA/SA data residency.** Sell "we run it / it's easier / you choose," not "cheaper." |
| **Entra / Okta / Auth0** | Per-user/per-MAU pricing punishes growth; opaque tiers; vendor lock-in | **Transparent flat low pricing, no per-seat gouging, own-your-data, and the freedom to move between self-host and cloud** (anti-lock-in is itself the pitch) |

**Revenue wedge (proven — WorkOS model):** core auth (OIDC/OAuth2 + basic MFA)
**free** for SMMEs; charge for **enterprise connectors** (SAML, SCIM/dir-sync),
**scale** (more users/tenants), **hosting convenience** (§4), and **support**.
Enterprises pay for SSO/SCIM; SMMEs ride the free core and convert as they grow
(product-led growth → low-touch → passive).

**The Keycloak-killer angle:** Keycloak makes you choose between "free but you
operate it" and nothing else. WeldForge lets the *same* customer pick — and later
change — between self-hosting it free, having us run it, running it in their own
cloud, or reselling it — all on the **same OIDC/SAML/SCIM contract**, so moving
between models never means re-integrating their apps.

## 3. Tiers ✅ (open-core, per-tenant cap)

| Tier | Price `[confirm]` | Tenants | Users / tenant | Features |
|---|---|---|---|---|
| **Community** (free, self-host) | $0 | 1 | **25** | OIDC/OAuth2, TOTP MFA, custom branding, community support |
| **Starter** | ~$19/mo `[confirm]` | 1 | ~100 | + email support, password policies, longer audit |
| **Business** | ~$99/mo `[confirm]` | up to ~5 | ~500 | + **SAML**, **SCIM/dir-sync**, **WebAuthn/SMS MFA**, extended audit retention |
| **Enterprise / Cloud** | custom | many / unlimited | high/unlimited | + SLA, priority support, data residency, SSO connectors at scale |

- **Pricing shape:** flat per-tier monthly (predictable, SMME-friendly) — **not
  per-seat.** Optional per-extra-tenant add-on for partners/MSPs (§4.5).
- **Free cap ✅** = 1 tenant, ~25 users in it. Multi-tenant and enterprise
  connectors are the paid lines.
- Tiers are orthogonal to the hosting model (§4): e.g. you can run **Business**
  self-hosted (license key) *or* on our cloud (subscription).

## 4. Deployment & hosting models — the full spectrum

This is the core of the Keycloak-alternative story. Every model speaks the **same
OIDC/OAuth2/SAML/SCIM contract**, so a customer can start anywhere and migrate
without re-integrating their apps.

| # | Model | Who operates | Who holds the data | Enforcement | Pricing motion | Best for |
|---|---|---|---|---|---|---|
| 4.1 | **Self-hosted (customer-operated)** | Customer | Customer | Signed license key (honor-based) | Free Community / paid license key | Teams who want full control; the direct **Keycloak replacement** |
| 4.2 | **Managed shared cloud (multi-tenant SaaS)** | **Us** | Us (SA region) | Absolute (we run it) | Monthly subscription | SMMEs wanting zero ops — **primary passive-income engine** |
| 4.3 | **Managed dedicated instance** | **Us** | Us, isolated per customer | Absolute | Premium subscription + setup | Customers needing isolation/compliance but not ops |
| 4.4 | **BYOC — bring your own cloud** | **Us (managed)** | **Customer's cloud account** | Absolute (we operate) | Enterprise + management fee | Data-sovereignty / regulated customers |
| 4.5 | **Partner / MSP / white-label** | Partner | Partner (for their clients) | Per-tenant license to partner | Wholesale per-tenant; partner marks up | Agencies/MSPs serving many client orgs — **channel + monetizes multi-tenancy** |
| 4.6 | **Air-gapped / on-prem enterprise** | Customer | Customer (offline) | Signed **offline** license (no phone-home) | Enterprise license + support | Banks, government, defense |
| 4.7 | **Embedded / OEM** *(optional, later)* | Product vendor | Their product | OEM license (per-deployment / per-MAU) | OEM contract | SaaS vendors embedding auth |

**Why this beats Keycloak directly:**
- Keycloak ≈ **4.1 only** (Red Hat adds support). It has **no managed cloud, no
  managed-BYOC, no clean white-label multi-tenant** offering.
- WeldForge's **4.2 managed cloud** removes Keycloak's biggest real cost (you
  operating it) — that alone wins most SMMEs.
- **4.4 BYOC** is a premium enterprise differentiator (managed ops *and* data stays
  in the customer's cloud) that Keycloak/Entra don't offer cleanly.
- **4.5 MSP/white-label** turns our multi-tenant engine into a **reseller channel** —
  partners onboard their own clients as tenants and we earn wholesale per-tenant.
  This is a growth multiplier Keycloak structurally lacks.

**Portability promise (the anti-lock-in pitch):** because the protocol surface and
the schema (Flyway) are identical across models, a customer can **export/migrate**
between self-host ⇄ cloud ⇄ BYOC. Document a supported migration path (DB dump +
re-issue signing keys, or a tenant-export tool) so "you're never trapped" is a real,
demonstrable claim — the exact opposite of Entra/Okta lock-in.

## 5. Licensing architecture ✅ — signed offline license keys

- A **license** is an **Ed25519-signed** compact token encoding:
  `{ licenseId, licensee, tier, hostingModel, maxTenants, maxUsersPerTenant,
  features[], issuedAt, expiresAt, grace }`.
- The app embeds **only the WeldForge public key** and verifies the license at
  boot; the **private signing key stays offline with you** (the issuer) — never in
  the app or repo. GitLab/Sentry/Metabase pattern.
- **No license installed → built-in Community entitlement** (1 tenant / 25 users /
  core features). A fresh self-host "just works" for free, capped.
- **Enforcement differs by hosting model (§4):** self-host (4.1) & air-gap (4.6) =
  **honor-based** signed key (license law; fine for the SMME/business market);
  managed cloud / dedicated / BYOC (4.2–4.4) = **absolute** (we operate it). No
  phone-home anywhere (POPIA / air-gap friendly); cloud may *additionally* verify
  server-side.
- **Graceful expiry (recommended):** on expiry, **don't lock existing users out** —
  revert to Community limits (existing users keep working, **new creation past the
  free cap blocked**, paid features disabled) with loud admin warnings during a
  grace window.

## 6. Enforcement points

A central `EntitlementService` is consulted at:
- **User creation** — `register`, admin invite, SCIM provisioning, federated JIT →
  count active users in the tenant; past `maxUsersPerTenant` → **block with a clear
  upgrade message** (HTTP 402/403 + machine code `entitlement_user_limit`).
- **Tenant creation** — past `maxTenants` → blocked.
- **Feature use** — SAML/SCIM/WebAuthn/SMS/audit-retention/branding gated by
  `features[]` (`EntitlementService.requireFeature(...)`).
- **Grandfathering** — an install already over a (newly lowered) cap is **warned,
  not retroactively locked**; only *growth* is blocked.

> These are the **same code paths the sign-up approval gate (§9) touches** — so we
> build the entitlement check and the approval gate together to avoid editing
> `register`/invite/SCIM/JIT twice.

## 7. Vouchers / coupons (marketing)

Two complementary mechanisms:

**(a) Pre-signed grant licenses (self-host).** A "voucher" can simply *be* a
time-boxed signed license you generate and hand out (conference codes, design
partners, "free Business for 6 months"). Redemption = paste the key. No server
needed — works for self-hosters (4.1/4.6).

**(b) Redeemable voucher codes (cloud / order funnel).** A short human code
(`WELDFORGE-SMME-AB12`) the user redeems in the portal/checkout. On redemption the
system issues the matching entitlement (or applies a discount). Needs a small
voucher store + redemption endpoint with single-use / usage-limit / expiry
tracking — and gives you **campaign analytics**.

**Voucher model:**
`code, campaign, type (FREE_TIER_GRANT | PERCENT_DISCOUNT | FIXED_DISCOUNT),
grantsTier, durationDays, maxRedemptions, perAccountLimit, validFrom, validUntil,
status` + a `voucher_redemptions` record. Discount vouchers plug into the existing
order funnel (`PendingOrder`/`Subscription`/gateways); grant vouchers issue a
`Subscription` + license without payment. Admin UI to create/disable codes and see
redemption counts. **This is the marketing lever** — seed SMMEs/communities, track
conversions, upsell when the voucher lapses.

## 8. Self-hosting fixes (prerequisite for a credible "free install")

The self-install review found the free-install story is **not real yet**. Top gaps:

1. **🔴 No `LICENSE` file in the repo at all.** README advertises "free for
   self-host eval/dev/non-commercial," but by default copyright **a clone grants no
   right to run/modify** — contradicting the free tier and the whole plan.
   **Fix first.** Recommended: **Business Source License (BSL 1.1)** — free for
   self-host/dev/small-scale, paid for production-at-scale, auto-converts to OSS
   after N years (HashiCorp/Sentry/CockroachDB use it). Alternatives: SSPL (stricter)
   or custom source-available.
2. **No self-hosting doc / portable artifacts.** The Helm chart is GKE-only
   (gce ingress, GKE ManagedCertificate, Cloud SQL proxy, Workload Identity, the
   maintainer's Artifact Registry); `postgres.enabled: true` is a dead toggle (no
   StatefulSet template). Add `docs/self-hosting.md`, a self-contained
   `docker-compose.selfhost.yml` (app + db + **admin-portal**, with secret
   generation), and `values-selfhost.yaml` (configurable `ingressClassName`,
   cert-manager, real in-cluster Postgres, direct datasource, parameterized images).
3. **README quickstart inaccuracies** (`db` vs `postgres` service; `:8076` is the
   API not the portal; version drift) — erodes trust on first read.
4. **Marketing vs repo mismatch** — `deployment.html` / the blog promise generic
   K8s manifests + a compose that won't run against the real image. Reconcile.

## 9. Sign-up approval gate (already designed, in flight)

The per-tenant approval gate (✅ decided: **local + federated**, **domain-allowlist +
manual**, **after email verification**) is ready to build and shares §6's
enforcement points. Proposed as a **Business-tier** feature (gated org onboarding is
an enterprise need) — or keep it free; your call (§11).

## 10. Phased implementation plan

| Phase | Scope | Revenue-relevant? |
|---|---|---|
| **0 — Legal/docs (unblocks free install)** | `LICENSE` (BSL 1.1), `docs/self-hosting.md`, self-contained compose, README fixes | Prerequisite |
| **1 — Entitlement core** | `EntitlementService`, Ed25519 license verify, Community default, enforce caps at user/tenant creation, admin "License" view | ✅ enables paid |
| **2 — Open-core feature gates** | gate SAML/SCIM/WebAuthn/SMS/audit/branding by `features[]` | ✅ |
| **3 — Vouchers/coupons** | voucher model + redemption + discounts in order funnel + campaign tracking | ✅ marketing |
| **4 — Sign-up approval gate** | the designed gate (local+federated, domain allowlist, post-verification) | feature |
| **5 — Hosting enablement** | `values-selfhost.yaml` + portable Helm (4.1), cloud self-serve onboarding (4.2), BYOC install playbook (4.4), MSP/white-label tenant model + wholesale licensing (4.5) | ✅ hosting revenue |
| **6 — Cloud billing polish** | self-serve upgrade, Stripe → subscription → license issuance, license/voucher admin portal, migration/export tool (portability) | ✅ |

Each phase ships independently with TDD/BDD, on its own branch/PR.

## 11. Open decisions for you

1. **License text:** BSL 1.1 (recommended) / SSPL / custom source-available?
2. **Prices** per tier (the `[confirm]` cells in §3)?
3. **Free cap:** exactly **25 users / 1 tenant**? (1 tenant free ✅; confirm the 25.)
4. **Expiry behaviour:** graceful degrade-to-Community (recommended) vs hard cap?
5. **Vouchers:** both pre-signed grant licenses *and* cloud redeemable codes (recommended), or one?
6. **Approval gate:** Business-tier feature, or free for all tiers?
7. **Hosting models (§4):** which to offer at launch? Recommended first wave:
   **4.1 self-host + 4.2 managed cloud** (covers the Keycloak-alternative core),
   then **4.5 MSP/white-label** (channel growth) and **4.4 BYOC** (enterprise).
   Defer **4.7 OEM**. Confirm or adjust.
8. **BYOC clouds:** GCP first (we're already there), then AWS/Azure? Or GCP-only initially?
9. **White-label depth (4.5):** full re-brand (partner's logo/domain/emails) or co-branded?
10. **Phase order:** start with **Phase 0** (legal/docs)? It unblocks everything and is low-risk.
</content>
