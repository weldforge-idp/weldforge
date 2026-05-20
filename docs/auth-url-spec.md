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

A handful of subdomain labels are reserved for non-tenant uses and may
**not** be used as tenant slugs. The resolver rejects them and falls back
as if the host had no recognisable subdomain:

- `www` — marketing redirects
- `api` — direct backend access
- `admin` — admin portal root (if ever split out)
- `app` — generic app root
- `mail` — outbound SMTP / inbound parse
- `static` — CDN assets

Configured via `wf.public.reserved-labels`. Slug-creation should additionally
refuse these names on the admin side.

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
**without a `Domain` attribute**, so the browser scopes them to the exact
host that set them. Consequences:

- A user signed into `acme.sso.weldforge.org` is **not** signed into
  `contoso.sso.weldforge.org` — confirming the per-tenant isolation we
  want.
- A super-admin signed into `sso.weldforge.org` (the apex admin portal)
  does not carry that session into tenant subdomains. They re-authenticate
  if they navigate to a tenant subdomain directly.
- `SameSite=Lax` remains so top-level browser navigation (the OIDC bounce
  back to apex) still carries the cookie.

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
- `PasswordResetIntegrationTest`: assert reset URL has the
  `{slug}.<base-domain>` host shape and no `tenant=` query parameter.
- Existing OIDC tests: still pass because OIDC paths stay on the apex
  host.
