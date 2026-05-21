# Auth URL Specification

Status: **active** — implementation on `feat/per-tenant-auth-urls`. Supersedes
the older `?tenant=<slug>` query-param form, which is removed.

## Goal

Each tenant's user-facing auth pages must live on a **distinct origin** so
password managers — both browser-builtins (Chrome, Firefox, Safari) and
third-party (Bitwarden, 1Password, Dashlane) — treat each tenant as a
separate site. Browser autofill matches on `scheme + host + port` and
**ignores the path entirely**, so a path-prefix (`/t/<slug>/login`) is not
enough. Query strings are also ignored. Only the host can carry the tenant
identity for the user-facing forms.

## Host pattern

```
https://{slug}.sso.weldforge.org/{path}
```

- `{slug}` matches `^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$` — same regex enforced
  everywhere else for tenant slugs.
- The base domain (`sso.weldforge.org`) is configurable via the
  `wf.public.base-domain` property / `APP_PUBLIC_BASE_DOMAIN` env var.
- The scheme is configurable via `wf.public.scheme` / `APP_PUBLIC_SCHEME`
  (defaults to `https`; only `http` is honoured in dev / tests).

## Reserved root labels

A list of subdomain labels is reserved for non-tenant uses and may
**not** be used as tenant slugs. The list is enforced at **two points**:

1. **Resolution time** — `TenantResolverFilter` refuses a reserved
   label as a slug. The request falls back to the default tenant.
2. **Slug-creation time** — `TenantService.requireSlug` rejects the
   creation request entirely. Without this, an admin could create a
   tenant with a reserved slug and the tenant would be permanently
   unreachable via its subdomain.

The current list (configurable via `wf.public.reserved-labels`):

- **Infrastructure / well-known:** `www`, `api`, `admin`, `app`,
  `mail`, `static`, `cdn`, `assets`, `health`, `actuator`, `metrics`,
  `prometheus`, `grafana`, `swagger`, `api-docs`.
- **Environment markers:** `dev`, `staging`, `stage`, `test`, `prod`,
  `production`.
- **Identity / federation (phishing-prone):** `auth`, `oauth`,
  `oauth2`, `oidc`, `saml`, `scim`, `sso`, `account`, `accounts`,
  `login`, `logout`, `signin`, `signup`, `register`, `verify`,
  `reset`, `password`, `mfa`, `totp`.
- **Marketing / catch-all:** `blog`, `docs`, `support`, `help`,
  `status`, `billing`.

The identity-and-federation labels are deliberately broad: a slug like
`oauth` on a wildcard cert would look authoritative to a user even
though the operator could be anyone with a credit card. Treat new
additions to this list as a security action and audit it on every
release.

## Public end-user routes

These are the only routes a password manager will ever see, and the only
ones that move to per-tenant subdomains:

| Path | Purpose |
| --- | --- |
| `/login` | Sign-in form |
| `/login/forgot` and `/forgot-password` | Request a password reset |
| `/login/reset` and `/reset-password` | Choose a new password from a reset link |
| `/register` | Create an account (where the tenant has registration enabled) |
| `/verify-email` | Confirm a verification token |

The Spring `LoginController` serves `/login`, `/login/forgot`, `/login/reset`
as plain HTML (the legacy hosted form used by the OIDC redirect loop). The
Angular admin portal serves the same paths plus `/forgot-password`,
`/reset-password`, `/register`, `/verify-email` as SPA routes. Both
implementations resolve the tenant **from the Host header** — no query
string, no path prefix.

## Tenant resolution (server-side)

`TenantResolverFilter` resolves the request's tenant in this order. The
first hit wins:

1. **`X-Tenant-Slug` request header.** For machine clients (Angular
   interceptor, server-to-server callers). Highest priority because it is
   the most explicit and is required for the super-admin tenant picker.
2. **`/t/{slug}/...` path prefix.** Used by the OIDC/SAML deep-link
   endpoints (`/t/<slug>/oauth2/authorize`, `/t/<slug>/saml2/idp/sso`,
   `/t/<slug>/.well-known/openid-configuration`, …). These are
   machine-to-machine URLs; password-manager distinctness does not apply.
3. **Host header subdomain.** First label of the host, taken modulo a
   trailing port. The label must:
   - match the slug regex,
   - **not** be the configured base domain itself (so `sso.weldforge.org`
     stays the admin portal),
   - **not** appear in `wf.public.reserved-labels`,
   - and the remaining suffix must equal `wf.public.base-domain`.
4. **Fallback to `default`.** Single-tenant deployments and unit tests
   without any host/path context still work.

The `tenant=<slug>` query parameter is **no longer consulted**. URLs that
still carry it ignore the query and resolve via the rules above; if no rule
matches and the request hits a tenant-required path, the request is
rejected with the same error that an unknown tenant would produce today.

## Access-token `iss` claim

Every access JWT carries

```
iss = https://<base-domain>/t/<tenant-slug>
```

— the canonical apex issuer that matches the `issuer` field of
`https://<base-domain>/t/<tenant-slug>/.well-known/openid-configuration`.
RPs that validate `iss` strictly against discovery (the Spring Security
OAuth2 resource-server default, Auth0 SDKs, etc.) will accept the token.
The issuer is **not** the host the user signed in on — it is always the
apex, even when the access cookie was set on a tenant subdomain. This
preserves a stable issuer identity across the auth-URL refactor and
across any future move of `/login` to a different host shape.

## Tenant deletion revokes all sessions

`TenantService.deleteTenant` performs three steps in one transaction
before the row goes away:

1. Bump `token_version` on every user in the tenant — every outstanding
   access JWT for that tenant carries an older version and stops
   authenticating at `JwtAuthenticationFilter`.
2. Mark every live `refresh_token` family in the tenant as revoked
   (`revoked_reason='tenant_deleted'`). A refresh attempt against the
   apex `/api/auth/refresh` after delete will fail.
3. Hard-delete the `tenants` row.

Without step 1, a stolen-pre-deletion JWT would silently keep working
as a stale identity if the slug were ever reused. Step 4 closes the
slug-reuse side of the same risk — see "Slug-reuse holdback" below.

## Slug-reuse holdback

When a tenant is deleted, its slug is written to the
`tenant_slug_holdback` table (V37 migration) with the release timestamp.
`TenantService.requireSlug` refuses any slug whose most recent release
sits within `wf.public.slug-holdback-days` (default **90 days**) — the
window in which a stolen pre-deletion session could plausibly still be
in someone's password manager or browser cache and confuse the user.

Operational notes:

- The same slug may appear in the holdback table multiple times over
  its lifetime — each delete writes a fresh row. `requireSlug` looks
  only at the most recent release, so the slug becomes reusable when
  *that* release ages past the window.
- `wf.public.slug-holdback-days = 0` disables the check. Acceptable
  for ephemeral test deployments; not safe in production.
- The holdback rows live forever by design — they double as a delete
  audit trail. A future cleanup job can purge entries older than,
  say, 2× the window.
- The `released_by_user_id` FK is `ON DELETE SET NULL` so removing an
  admin doesn't break the holdback ledger.

## Cookies — defence-in-depth

The four mitigations covered above (JWT binding, JWT `iss`,
`SameSite=Lax`+JSON-only, reserved-slug allowlist) leave one residual
concern: a developer adding a new `/api/auth/*` mutating endpoint
might forget the JSON-only invariant and write a form-encoded
handler. A form-encoded POST does not trigger a CORS preflight, so a
hostile sibling subdomain (which shares the base-domain cookie) could
fire one as a classic CSRF. To convert the implicit invariant into a
hard check, `AuthJsonContentTypeFilter` returns **415 Unsupported
Media Type** for any `/api/auth/**` mutating request whose body is
not `application/json` (or one of its `+json` variants). The hosted
`/login/**` HTML auth-form path is deliberately not covered — it
accepts form encoding because it's a normal &lt;form&gt; element,
and an attacker forging a sign-in submits credentials they don't
have.

## OIDC / SAML endpoints stay on the apex host

OIDC and SAML use **path-prefixed** URLs under the apex host, not
subdomains:

- Authorize:  `https://sso.weldforge.org/t/{slug}/oauth2/authorize?…`
- Token:      `https://sso.weldforge.org/t/{slug}/oauth2/token`
- UserInfo:   `https://sso.weldforge.org/t/{slug}/oauth2/userinfo`
- Discovery:  `https://sso.weldforge.org/t/{slug}/.well-known/openid-configuration`
- SAML SSO:   `https://sso.weldforge.org/t/{slug}/saml2/idp/sso`
- SAML meta:  `https://sso.weldforge.org/t/{slug}/saml2/idp/metadata`

Rationale: these are *machine-to-machine* endpoints driven by relying-party
configuration. Password managers never see them and don't need to
distinguish them. Issuer stability matters more than UX distinctness —
moving the path under a per-tenant subdomain would force every existing RP
to re-register.

When the apex host's `OidcAuthorizationController` decides the caller is
unauthenticated, it redirects to the **tenant subdomain's** login page:

```
302 Location: https://{slug}.sso.weldforge.org/login?oidcReturnTo=<base64-url>
```

The login form submission lands on the tenant subdomain (which the
resolver maps to the correct tenant), `AuthService.login` sets the
session cookie scoped to that host, and the user is bounced back to the
apex `/t/{slug}/oauth2/authorize` URL where the consent screen now sees a
signed-in principal.

## Cookies

Both `wf_session` (access JWT) and `refresh_token` cookies are written
with `Domain=<base-domain>` (e.g. `sso.weldforge.org`). The browser
therefore sends them on every `*.sso.weldforge.org` host, **not** just
the tenant subdomain that set them.

**Why this is needed.** The OIDC unauthenticated-redirect from
`https://sso.weldforge.org/t/<slug>/oauth2/authorize` sends the user to
`https://<slug>.sso.weldforge.org/login`. After sign-in, the user is
302'd back to the apex `/t/<slug>/oauth2/authorize` URL — a
**different host** from the one that just set the session cookie. A
host-only cookie would not be sent, the apex would see an
unauthenticated user, and the OIDC consent step would loop forever. The
parent-domain scope is the trade-off that keeps the apex OIDC flow
working without giving up password-manager distinctness (which is
host-based and independent of cookie scope).

**The four mitigations that make this safe:**

1. **JWT tenant binding (load-bearing).** `JwtAuthenticationFilter`
   compares the JWT's `tenant_id` claim against the request's
   **implicit** tenant (Host subdomain or `/t/<slug>/` path prefix —
   NOT the `X-Tenant-Slug` header, which is the explicit
   cross-tenant channel reserved for super-admins). A mismatch is
   refused: the JWT is treated as if absent and the request runs
   anonymous. Without this check, a tenant-A session would silently
   authenticate the user against tenant B's UI and API on B's
   subdomain.
2. **JWT `iss` claim.** Every access token carries
   `iss=https://<base-domain>/t/<slug>` so a downstream resource
   server (or our own consent screen) can reject a token minted for
   the wrong tenant even without a request-time host check.
3. **`SameSite=Lax` + JSON-only auth POST endpoints.** A malicious
   `evil.sso.weldforge.org` is *same-site* with
   `acme.sso.weldforge.org` per the SameSite spec, so the cookie
   would be sent on a top-level navigation. Our `/api/auth/*` POST
   endpoints accept `application/json` only, which browsers don't
   send cross-origin via simple forms, so a classical form-CSRF
   doesn't fire. The JWT check above closes the rest.
4. **Reserved-slug allowlist.** Subdomain labels like `oauth`,
   `login`, `accounts`, `auth` are reserved at both
   resolution-time AND slug-creation-time (see "Reserved root
   labels" below). A phishing-prone slug never reaches the
   `tenants` table.

**Consequences for operators:**

- A super-admin signed into `sso.weldforge.org` (the apex admin
  portal) carries that session into tenant subdomains for the
  branding/social-providers public GETs. Their JWT identifies them as
  super-admin and the tenant-binding check exempts them.
- A regular tenant-A user landing on `acme.sso.weldforge.org` while
  carrying a JWT for `contoso` will appear logged-out. They see the
  acme login form. This is intended.
- `SameSite=Lax` remains so top-level browser navigation (the OIDC
  bounce back to apex) still carries the cookie.

## Cross-tenant trust model

The base-domain cookie scope means a malicious tenant — one whose
operator the platform trusts as much as the next-cheapest plan tier
allows — has cross-origin read of the *cookie name and Set-Cookie
behaviour* of its siblings (not the cookie's value, which is
`HttpOnly`). It cannot use a stolen cookie thanks to (1) above, but a
hostile tenant operator can still:

- **Phish** by spinning up a plausibly-named tenant
  (`acme-bank-secure.sso.weldforge.org` with acme's logo). Defences
  outside this spec: tenant identity-proofing at onboarding,
  branding-verification badges, abuse reporting.
- **Run XSS in their own subdomain** and pivot to its own users; this
  is contained to that tenant by the JWT binding above, but the
  tenant's users' sessions are still in scope.
- **Initiate same-site GET navigations** (`window.location =
  https://acme.sso.weldforge.org/some-link?…`) that carry the
  victim's cookie. We rely on JSON-only POST endpoints and the JWT
  binding to neutralise this. **A new mutating endpoint MUST NOT
  accept form-encoded POST bodies on `/api/auth/*` without also
  requiring a CSRF token.**

Operators should treat tenant slugs as trust-level identifiers: a
verified-by-WeldForge tenant should not be visually indistinguishable
from a freshly-signed-up tenant in any user-visible context. This is
not a code-level guarantee — it is product policy and is out of scope
for this spec.

## Email links

`PasswordResetService` builds the reset-link URL as:

```
https://{tenant.slug}.{wf.public.base-domain}/reset-password?token=<raw-token>
```

There is no `tenant=` query parameter. Existing 1-hour-expiry tokens
issued before the cut-over die naturally; users who click an old link
land on an URL that no longer matches a tenant and see the generic
"invalid or expired" reset response.

## Frontend tenant identification

Until the user signs in (no JWT yet), the Angular app needs the tenant
slug to load branding and pre-populate the tenant context. It reads the
slug from `window.location.host`:

1. Parse the host's first label.
2. If the host matches `{label}.{wf.public.base-domain}` and `{label}` is
   not reserved, return `{label}`.
3. Otherwise return `null` (apex admin portal — defer to the super-admin
   tenant picker).

The `TenantInterceptor` then stamps `X-Tenant-Slug` onto `/api/*`
requests for the public branding/social-providers GETs, identically to
the picker-driven flow.

## Search-engine indexing — tenant subdomains are noindex

Every response served from a tenant subdomain
(`<slug>.<base-domain>`) carries

```
X-Robots-Tag: noindex, nofollow
```

The apex host (`<base-domain>`) keeps its normal indexability for the
marketing site / admin portal landing. Two layers enforce this:

- `TenantSubdomainNoIndexFilter` — stamps the header on every backend
  response when `PublicHostProperties.slugFromHost(request)` returns
  non-null.
- nginx (`infrastructure/helm/weldforge/templates/frontend-nginx-configmap.yaml`)
  — stamps the same header on SPA and static-asset responses served
  directly by nginx, keyed off `$host` with the apex explicitly
  whitelisted.

Why: a wildcard cert + per-tenant login form would otherwise let
search engines index thousands of tenant-branded sign-in pages —
fragmenting brand reputation, leaking tenant existence, and weakening
phishing-detection heuristics that rely on a single canonical
sign-in URL.

## DNS

A wildcard `A` record (or `CNAME` to an ingress hostname) is required:

```
*.sso.weldforge.org   A   <static ingress IP>
```

The wildcard points at the same GKE ingress that serves `sso.weldforge.org`
today. nginx in the frontend pod serves the Angular SPA for any host that
hits it; the Spring backend reads `Host` to resolve the tenant.

## TLS

Google's `ManagedCertificate` resource does **not** support wildcard SANs.
The wildcard cert is provisioned via Google Certificate Manager
(`certificatemanager.googleapis.com`):

1. Create a `CertificateMap` `sso-frontend-cert-map`.
2. Issue a DNS-authorised wildcard certificate for `*.sso.weldforge.org`
   and a leaf certificate for `sso.weldforge.org`.
3. Attach both to `CertificateMapEntry` resources keyed by hostname.
4. Reference the map from the ingress via the
   `networking.gke.io/v1beta1.FrontendConfig` and
   `networking.gke.io/v1.certificatemap` annotations.

This is a one-time operation outside the Helm chart. The chart no longer
ships a `ManagedCertificate` for the wildcard host; it keeps the existing
one for the apex host as a fallback until the certificate-map migration
lands in prod.

## Migration

There is **no backwards-compatibility shim**. The `?tenant=` query
parameter stops working the day this branch merges. Known consumers to
update:

- TechMetropolis — external system that constructs WeldForge login URLs;
  has been notified.
- `weldforge-admin-portal/src/app/features/tenants/tenants.component.ts`
  — the in-portal explainer text shown to admins (updated in this branch).
- `docs/agent-memory/feedback_auth_form_branding.md` and the matching
  CLAUDE.md section — updated in this branch.

## Test scope

- `TenantResolverFilterTest`: subdomain resolution + reserved-label
  rejection + apex/default fallback + path-prefix / header priority
  unchanged.
- `JwtAuthenticationFilterTest`: JWT `tenant_id` is enforced against
  the implicit tenant (Host subdomain + `/t/<slug>/` path), super-admin
  exemption, apex fallback. Cross-tenant cookie attempt is rejected.
- `TenantServiceReservedSlugTest`: reserved labels (`oauth`, `login`,
  `api`, `ADMIN`) are refused at slug-creation time, regardless of
  case.
- `TenantServiceSlugHoldbackTest`: a slug released within the
  configured window is refused; an expired release is reusable;
  `slug-holdback-days=0` disables the check; never-released slugs
  pass.
- `AuthJsonContentTypeFilterTest`: `/api/auth/**` mutating endpoints
  accept `application/json` (with or without charset parameter) and
  refuse form-encoded, multipart, text/plain, and missing
  Content-Type with a body. GET is unrestricted. `/login/**`
  HTML-form path is unaffected.
- `PasswordResetIntegrationTest`: assert reset URL has the
  `{slug}.<base-domain>` host shape and no `tenant=` query parameter.
- Existing OIDC tests: still pass because OIDC paths stay on the apex
  host.
