# Free-tier self-serve onboarding — implementation plan

**Status:** Phase 2 in progress on `feat/tenant-seat-limits`; Phases 1, 3–5 not started.
**Goal:** let a prospective customer sign themselves up for a free tenant
(max 25 users) from the marketing site, without an operator in the loop.

> Written 2026-07-31. Re-verify file/line references before acting — they
> drift. Companion docs: `docs/security/hardening-backlog.md`,
> `docs/auth-url-spec.md` (identity-proofing V2b/V2c/V2d).

---

## What already exists

`POST /api/public/orders` (`PublicOrderController.java:27`) is already an
anonymous, CORS-allowed-from-the-marketing-site signup endpoint, and
`CreateOrderRequest` already collects organisation, contact name, contact
email, slug (regex-validated), tier, billing details and terms acceptance.
The funnel exists — it is the *paid* one.

`TenantProvisioningService` already creates the tenant, mints a bootstrap
`TENANT_ADMIN` service account, creates the subscription row and audits
`tenant.provisioned`.

## What does not exist

1. **No free tier.** `TierPricing.java:18-26` has seven tiers, cheapest
   `cloud-starter` at $29/mo, and `PublicOrderController.java:29` rejects
   anything absent from that map.
2. **No user limit anywhere.** No `max_users` column, no seat concept, no
   count query on `UserRepository`.
3. **Provisioning is welded to payment.** `TenantProvisioningService.provision()`
   throws unless the order is `PAID` (`:66-69`), and is only ever called from
   the payment webhook and its retry scheduler. A free signup produces no
   payment event, so nothing would trigger it.

(3) is the substantive work: it is a second path into provisioning, not a
new row in a price map.

---

## Phase 0 — decisions

| Decision | Recommendation |
|---|---|
| Does a free tenant get a `subscriptions` row? | Yes — `tier='free'`, `amount_cents=0`, null gateway, so reporting stays uniform. Verify `subscriptions.gateway_id` is nullable in `V31__payment_billing.sql` first. |
| Does the seat count include deactivated users? | No — count active users only. See Phase 2. |
| Email the bootstrap token, or a one-time setup link? | Setup link. See Phase 3. |

## Phase 1 — free tier + a non-payment path to provisioning

**Keep free signups in `pending_orders`.** A separate table is tempting, but
slug uniqueness is enforced by the partial unique index
`pending_orders_active_slug_reservation`; a separate table would let a free
signup and a paid order claim the same slug concurrently. Reusing the table
inherits that safety.

- **New `OrderStatus` values**: `AWAITING_EMAIL_VERIFICATION` and
  `VERIFIED_FREE`. Add both to `ACTIVE` so the slug reservation holds. The
  enum javadoc states the DB check constraint mirrors it — the migration must
  extend that constraint too.
- **New `PublicFreeSignupController`** → `POST /api/public/signup/free`.
  Deliberately *not* routed through `OrderService.createOrder`, which
  unconditionally calls `TierPricing.amountCents()` and then selects a
  gateway. Free never touches a gateway.
- **Order creation** stays on `OrderService` — its javadoc claims sole
  ownership of `pending_orders` mutations; honour that. Creates the order at
  `AWAITING_EMAIL_VERIFICATION` and issues a verification token to
  `contactEmail`.
- **Verification callback** transitions → `VERIFIED_FREE`, then provisions.
- **`TenantProvisioningService.provision()`** — extend the status gate at
  `:66-69` to accept `VERIFIED_FREE`; skip `createSubscription()` when
  `selectedGateway` is null (or create the free row per decision 1). Set
  `max_users = 25` on the new tenant.
- **Slug reservation TTL**: paid uses 10 minutes
  (`app.payment.slug-reservation-minutes`), sized for a checkout window. Free
  needs an email round-trip — add a separate property at 24–48h. Do not
  reuse the paid one.
- **`OrderService.expireStaleCheckouts()`** (`:207`) must also sweep
  `AWAITING_EMAIL_VERIFICATION`, or abandoned free signups hold slugs
  forever.

Nullable-column changes this forces on `pending_orders`:
`selected_gateway_id`, `currency`, `billing_country`.

## Phase 2 — the seat cap

**In progress.** There are six user-creation paths, not three:

| Path | Site |
|---|---|
| Self-registration | `AuthService.java:85` |
| Admin creates user | `AdminService.java:313` |
| SCIM provisioning | `ScimUserService.java:109` |
| Social login JIT | `CustomOAuth2UserService.java:59` |
| LDAP/AD upstream JIT | `LdapUpstreamService.java:94` |
| SAML JIT | `SamlUserProvisioningSuccessHandler.java:109` |

The last three create users *during login*, via the same
`findBy…().orElseGet(User.builder()…)` → `save()` shape. Two consequences:
the guard must fire only when the user is genuinely new (`getId() == null`),
and when it does fire the result is a failed *sign-in* for somebody who has
no idea a quota exists — so it needs a comprehensible error, not a 500.

- **Schema (V45)**: `tenants.max_users INTEGER NULL`. Null means unlimited,
  so every existing tenant is unaffected and no backfill is needed.
- **`UserRepository.countByTenantIdAndActiveTrue(Long)`** — note the field is
  `User.active`, not `enabled`.
- **`TenantSeatService.assertCapacity(Tenant)`** throwing a typed
  `SeatLimitExceededException`, called from all six sites. Explicit and
  greppable; a JPA `@PrePersist` hook would be invisible and awkward to
  error-handle.
- **Error mapping**: 409 for registration and admin create; SCIM needs its
  own error envelope; the three JIT paths need a user-facing "this
  organisation is full" outcome.
- **Counting rule**: active users only. If deactivated users burned seats
  permanently, ordinary staff churn would fill a 25-seat tenant and generate
  support tickets. Side benefit: a tenant at its cap can deactivate someone
  to free a seat without contacting us.
- **Optional backstop**: a Postgres trigger on `users`. Six call sites is
  already easy to miss one, and a seventh will be added eventually.
- **80% warning** in the admin portal — needs the seat count exposed on the
  tenant admin API response.

## Phase 3 — welcome email

`TenantProvisioningService.sendWelcome()` (`:158-167`) logs a structured line
and sends nothing. The bootstrap `TENANT_ADMIN` token exists *only* in that
log line. Smaller than it looks: `service/mail/MailService.java` is already a
clean seam with an SMTP implementation behind it.

Note the tension: `MailService`'s contract explicitly requires delivery
failure to be non-fatal. Correct for password resets — but if the welcome
mail is the sole carrier of the admin token, a silent failure means a
permanently locked-out customer.

- **Recommended**: do not email a long-lived `TENANT_ADMIN` token at all.
  Email a one-time setup link that lets them set an admin password on
  arrival. Same infrastructure, and it keeps a durable credential out of an
  inbox.
- **Minimum viable**: inject `MailService`, send the token, and add a
  "resend welcome" admin action that *rotates* the service-account token —
  never re-sends the old one.
- Either way, emit a failure metric. The `sso.mail.send` counter from the
  hardening backlog is still unbuilt and would earn its keep here.

## Phase 4 — abuse controls

- **Rate-limit the new endpoint**: add it to `RateLimitingFilter.ROUTES`
  (`:32`). That is a `Map.of(...)`, which caps at 10 pairs and is already
  close — adding an entry may force `Map.ofEntries(...)`.
- **Free tenants stay unverified.** `Tenant.verifiedAt` already defaults null
  and the public branding endpoint derives a `verified` boolean the auth
  shell renders as a warning badge. Do not auto-verify free signups — that
  badge's value depends on it.
- **Ship identity-proofing V2c** (watchword slugs — `bank`, `pay`, `secure`).
  Spec'd in `docs/auth-url-spec.md`, unbuilt. Theoretical while signup is
  manual; live once it is free and self-serve.
- Optionally reject disposable-email domains on `contactEmail`.

## Phase 5 — the form

Marketing site (`weldforge-www`). Four fields: organisation, contact email,
slug, terms checkbox — plus contact name if wanted. **No optional fields.**
Branding, OIDC clients and MFA policy all belong in the admin portal after
provisioning, where the operator can see what each setting does.

The slug is the one irreversible choice: it is baked into
`https://sso.weldforge.org/t/{slug}`, which becomes a literal environment
variable in the customer's own deployment. Validate availability live and
state plainly that it cannot be changed.

Supporting endpoint: `GET /api/public/signup/slug-available?slug=`.
Rate-limit it. It is a mild enumeration oracle, which is acceptable — the
slug namespace is already public via
`/t/{slug}/.well-known/openid-configuration`.

## Testing

- **Unit**: seat cap boundary (24 → 25 → 26); deactivated users excluded;
  `maxUsers == null` unlimited.
- **Integration** (Testcontainers, `-Dtests.integration=true`, CI-only): full
  free signup → email verify → provision → first login.
- **Concurrency**: two signups racing the same slug; exactly one wins via the
  unique index.
- **Regression**: the paid funnel is untouched.

## Sequencing

Phase 2 first, as its own PR — the seat cap is self-contained, useful
regardless of how signup works, and touches six files better not changed at
the same time as a new state machine. Then Phases 1 + 3 together
(provisioning is useless without the email), then 4 and 5.
