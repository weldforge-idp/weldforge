# Relying-party onboarding — integrating an external app with WeldForge

This guide walks an external application (a "relying party" / RP) through
integrating with the WeldForge IAM platform across all three supported
protocols: **OIDC** (WeldForge as OpenID Provider), **SAML 2.0** (WeldForge as
IdP, and as SP federating an upstream IdP), and **SCIM 2.0** (inbound user/group
provisioning).

Every endpoint and field below is grounded in the live code; anything not yet
verifiable is marked **TODO**.

---

## 1. Overview & the per-tenant subdomain model

WeldForge is multi-tenant. Each tenant has a **slug** (e.g. `acme`, `leap`) and
its own signing keys, branding, OIDC clients, SAML SPs and SCIM scope.

There are two host shapes, and they are deliberately different:

- **Tenant auth UI** lives on the tenant's own subdomain:
  `https://{slug}.sso.weldforge.org/{login,register,forgot-password,reset-password,verify-email}`.
  Per-tenant subdomains mean browsers and third-party password managers treat
  each tenant as a distinct site. See `docs/auth-url-spec.md`.

- **OIDC / SAML protocol endpoints** live on the **apex** host under a
  `/t/{slug}/...` path prefix:
  - OIDC: `https://sso.weldforge.org/t/{slug}/.well-known/openid-configuration`
    and `/t/{slug}/oauth2/*`
  - SAML: `https://sso.weldforge.org/t/{slug}/saml2/idp/*`
  - SCIM: `https://sso.weldforge.org/scim/v2/{slug}/...`

The issuer embedded in OIDC discovery and minted tokens is the per-tenant URL
`{scheme}://{host}/t/{slug}` (`OidcDiscoveryController`,
`OidcDiscoveryControllerHelper.tenantIssuer`). Resolve discovery dynamically
rather than hard-coding endpoint URLs.

A canonical always-live demo tenant exists at slug **`leap`** — useful for
smoke-testing discovery/JWKS/metadata without credentials.

> **Admin APIs** (`/api/admin/...`) are tenant-scoped and require an
> authenticated tenant admin; the request's tenant context is resolved from the
> caller's session/JWT. The public `/api/auth/tenants/*/{branding,...}` reads are
> additionally gated by `AppAuthorizationFilter` (an `x-app-authorization`
> header).

---

## 2. OIDC relying-party onboarding

WeldForge is a hand-rolled OpenID Provider (no Spring Authorization Server).
Supported per the discovery document (`OidcDiscoveryController`):

- `response_types_supported`: `code`
- `grant_types_supported`: `authorization_code`, `client_credentials`
- `id_token_signing_alg_values_supported`: `RS256`
- `token_endpoint_auth_methods_supported`: `client_secret_post`, `none`
- `scopes_supported`: `openid`, `profile`, `email`
- `code_challenge_methods_supported`: `S256` (PKCE)
- `subject_types_supported`: `public`

### 2.1 Discovery & JWKS

| Purpose | URL |
|---|---|
| Discovery | `GET /t/{slug}/.well-known/openid-configuration` |
| JWKS | `GET /t/{slug}/oauth2/jwks` |

Both are **public** (no auth) — RPs hit them before they hold any credentials.
The discovery document advertises the authorization, token, userinfo,
introspection, revocation and end-session endpoints; consume those rather than
constructing them by hand.

### 2.2 Registering a client

Two paths register an OIDC client:

**(a) Admin API** — `OidcAdminController`, base `/api/admin/oidc/clients`
(tenant admin required):

| Method | Path | Action |
|---|---|---|
| `GET` | `/api/admin/oidc/clients` | list (secret never returned) |
| `POST` | `/api/admin/oidc/clients` | create |
| `POST` | `/api/admin/oidc/clients/{id}/rotate-secret` | rotate secret |
| `DELETE` | `/api/admin/oidc/clients/{id}` | delete |

Create body is an `OidcClientDto`. Fields the service honours
(`OidcClientService.create`):

- `redirectUris` (**required**) — list of exact redirect URIs.
- `scopes` (**required**) — the client's registered scope list.
- `grantTypes` (**required**) — e.g. `["authorization_code"]`,
  `["client_credentials"]`.
- `name` — display name (shown on the consent screen).
- `clientId` — optional; auto-generated as `wf_client_<uuid>` if omitted.
- `webOrigins` — CORS origins; each must be a bare `scheme://host[:port]` with
  **no path/query/fragment**. `https` always allowed; plain `http` only for
  loopback (`localhost` / `127.0.0.1` / `::1`).
- `postLogoutRedirectUris`
- `publicClient` (bool) and/or `tokenEndpointAuthMethod`: `none` → public,
  PKCE-only client (no secret). Anything else → confidential
  (`client_secret_post`).
- `requirePkce` — defaults **on** (forced on for public clients).
- `requireMfa`, `maxAuthenticationAgeSeconds` — step-up controls.

Secret handling: client secrets are generated server-side (prefix `wfs_`),
AES-GCM encrypted at rest, and **returned in plaintext exactly once** on create
or rotate. Public clients never receive a secret. Confidential client IDs are
prefixed `wf_client_`.

**(b) Dynamic registration (RFC 7591)** — `OidcRegistrationController`:

```
POST /t/{slug}/oauth2/register      Content-Type: application/json
{
  "redirect_uris": ["https://app.example.com/callback"],
  "client_name": "Example App",
  "grant_types": ["authorization_code"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "client_secret_basic"   // "none" => public/PKCE
}
```

Returns `201` with `client_id`, `client_secret` (omitted for public clients),
`client_id_issued_at`, `client_secret_expires_at: 0` (never expires),
`registration_client_uri`, plus the echoed metadata. The endpoint is public
(rate-limited in production); a registration **access token** for later
management is not yet implemented.

> **Auth-method note:** dynamic registration accepts the RFC value
> `client_secret_basic`, but the token endpoint authenticates confidential
> clients via `client_secret_post` (secret in the form body), and discovery only
> advertises `client_secret_post` / `none`. Send the secret in the POST body.

### 2.3 redirect_uri, PKCE & scope rules

- **redirect_uri is exact-match** against the registered list — checked at both
  `/authorize` and the consent `/decide` step
  (`OidcAuthorizationController`). No wildcards, no prefix matching.
- **PKCE**: only `S256` is supported. PKCE is required whenever the client has
  `requirePkce` on (default), and **always** for public clients
  (`OidcAuthorizationService.issueAuthorizationCode` / `exchangeCode`).
- **Scope restriction**: when a client has a non-empty registered scope list,
  any requested scope outside it is rejected with `invalid_scope`. The standard
  OIDC scopes are **always permitted** regardless of registration:
  `openid`, `profile`, `email`, `address`, `phone`, `offline_access`
  (`STANDARD_OIDC_SCOPES`). Clients registered without a scope list are left
  unconstrained (legacy compatibility).

### 2.4 Authorization-code flow (with consent)

```
GET /t/{slug}/oauth2/authorize
    ?response_type=code
    &client_id=...
    &redirect_uri=...        (exact match)
    &scope=openid profile email
    &state=...               (recommended)
    &nonce=...               (recommended)
    &code_challenge=...&code_challenge_method=S256   (PKCE)
```

State machine (`OidcAuthorizationController.authorize`):

1. **Unauthenticated** → `302` to the tenant's subdomain login page
   (`https://{slug}.sso.weldforge.org/login/?oidcReturnTo=<base64url>`).
2. **Authenticated, no consent** → server-rendered HTML consent screen listing
   the requested scopes, with a CSRF token bound to the user+tenant.
3. **Allow** → mint a single-use authorization code (5-minute TTL, stored
   hashed), `302` back to `redirect_uri` with `code` and `state`.
4. **Deny** → `302` back with `error=access_denied` and `state`
   (RFC 6749 §4.1.2.1).

If the client requires MFA / a max-auth-age and the user's factors don't
satisfy it, the flow raises a step-up challenge instead of issuing a code.

**Token exchange:**

```
POST /t/{slug}/oauth2/token    Content-Type: application/x-www-form-urlencoded
grant_type=authorization_code
&code=...
&redirect_uri=...              (must match the code's redirect_uri)
&client_id=...
&client_secret=...             (confidential clients only)
&code_verifier=...             (PKCE clients)
```

Response: `access_token`, `token_type: Bearer`, `expires_in`, `id_token`,
`scope`. Both access and ID tokens are **RS256-signed** with the tenant key
(`kid` in the JWS header), carry `iss = .../t/{slug}`, `aud = client_id`, and a
`roles` array derived from the user's role + super-admin flag
(`OidcTokenService`). Authorization codes are single-use and tenant+client
bound.

**Client-credentials grant** (machine-to-machine; confidential clients whose
`grantTypes` include `client_credentials`):

```
POST /t/{slug}/oauth2/token    Content-Type: application/x-www-form-urlencoded
grant_type=client_credentials&client_id=...&client_secret=...&scope=...
```

Returns an access token only (`expires_in: 3600`, no ID token). Public clients
are rejected for this grant.

### 2.5 Userinfo, introspection, revocation

| Endpoint | Method | Auth | Notes |
|---|---|---|---|
| `/t/{slug}/oauth2/userinfo` | `GET` | `Authorization: Bearer <access_token>` | Verifies the token against the tenant JWKS and that `iss` ends with `/t/{slug}`; returns `sub`, `email`, optional `name`, `picture`. 401 on any failure (`OidcUserinfoController`). |
| `/t/{slug}/oauth2/introspect` | `POST` (form) | `client_id` + `client_secret` | RFC 7662. Unauthenticated → 401; authenticated with a bad token → `active=false` (not 401) (`OidcIntrospectRevokeController`). |
| `/t/{slug}/oauth2/revoke` | `POST` (form) | `client_id` + `client_secret` | RFC 7009. Always `200`, even for an unknown token. |

### 2.6 Token TTLs

- **Access token**: `app.oidc.access-token-seconds` (default **3600s**), unless
  the tenant sets a per-tenant `accessTtlMs`, which takes precedence
  (`OidcTokenService.resolveAccessTtlSeconds`, PRD SSO-03).
- **ID token**: `app.oidc.id-token-seconds` (default **3600s**), capped at the
  effective access TTL.
- **Authorization code**: **300s** (5 min), single-use
  (`OidcAuthorizationService.CODE_TTL_SECONDS`).
- **Client-credentials access token**: advertised `expires_in: 3600`.

---

## 3. SAML IdP onboarding (WeldForge issues assertions to your SP)

Use this when your application is a SAML **Service Provider** and you want
WeldForge to be its **Identity Provider**.

### 3.1 Where your SP fetches WeldForge's IdP metadata

```
GET /t/{slug}/saml2/idp/metadata        (public, application/samlmetadata+xml)
```

(`SamlIdpController.metadata`.) Point your SP's IdP-metadata configuration here.

### 3.2 Register your SP

Admin API — `SamlIdpAdminController`, base `/api/admin/saml/service-providers`
(tenant admin):

| Method | Path | Action |
|---|---|---|
| `GET` | `/api/admin/saml/service-providers` | list |
| `POST` | `/api/admin/saml/service-providers` | create |
| `PUT` | `/api/admin/saml/service-providers/{id}` | update |
| `DELETE` | `/api/admin/saml/service-providers/{id}` | delete |
| `POST` | `/api/admin/saml/service-providers/import-metadata` | parse SP metadata (XML or URL) into a pre-filled DTO; nothing persisted |

Create/update body is a `SamlServiceProviderDto`:

| Field | Meaning |
|---|---|
| `entityId` | your SP's entity ID (matched against the AuthnRequest `Issuer`) |
| `name` | display name |
| `acsUrl` | Assertion Consumer Service URL — where the signed `SAMLResponse` is POSTed |
| `sloUrl` | Single Logout URL (optional) |
| `spCertificate` | your SP's PEM X.509 cert (needed for signed-request verification and assertion encryption) |
| `nameIdFormat` | NameID format |
| `attributeMappings` | `Map` controlling which user attributes map into assertion attributes |
| `enabled` | toggle |
| `encryptAssertions` | when true **and** `spCertificate` is set, the IdP returns an `EncryptedAssertion` (PRD SAM-04) |
| `wantAuthnRequestSigned` | when true **and** `spCertificate` is set, the IdP verifies the XML signature on inbound AuthnRequest / LogoutRequest messages and rejects unsigned/invalid ones (B-SAML-1) |

### 3.3 SSO endpoints (the runtime flow)

- **SP-initiated SSO**: `POST` or `GET` `/t/{slug}/saml2/idp/sso` with a
  `SAMLRequest` (and optional `RelayState`). The user must already be
  authenticated (else `401`). WeldForge decodes the AuthnRequest (XXE-hardened
  parse), matches the `Issuer` to a registered SP, verifies the request
  signature if required, builds a signed `SAMLResponse`, and returns an
  auto-submitting HTML form POSTing it to the SP's `acsUrl`
  (`SamlIdpController.handleSso`).
- **Single Logout**: IdP-initiated `POST /t/{slug}/saml2/idp/slo`;
  SP-initiated `POST /t/{slug}/saml2/sp-slo` (PRD SAM-06).

### 3.4 Enabling signed AuthnRequests (recommended, XSW-resistant)

To harden against forged / replayed AuthnRequests:

1. Upload your SP's signing certificate in `spCertificate`.
2. Set `wantAuthnRequestSigned: true`.

The IdP then rejects unsigned or invalid-signature AuthnRequests and
LogoutRequests for that SP (`SamlIdpService.verifyAuthnRequestSignature`,
`SamlInboundMessageParser` does an XXE-hardened namespace-aware DOM parse).
Without a cert configured, signature verification is a no-op.

### 3.5 Assertion encryption

Set `encryptAssertions: true` (with `spCertificate`) to have the IdP emit an
`EncryptedAssertion` instead of a cleartext assertion.

---

## 4. SAML SP onboarding (WeldForge federates an upstream IdP)

Use this when a tenant wants its users to log in via an **external/corporate
IdP** (Okta, Azure AD, ADFS, …) — WeldForge acts as the SP.

Admin API lives under the tenant resource (`TenantController`):

| Method | Path | Action |
|---|---|---|
| `GET` | `/api/admin/tenants/{id}/saml-providers` | list upstream IdPs |
| `POST` | `/api/admin/tenants/{id}/saml-providers` | create/upsert |
| `DELETE` | `/api/admin/tenants/{id}/saml-providers/{providerKey}` | delete |
| `POST` | `/api/admin/tenants/{id}/saml-providers/import-metadata` | parse upstream IdP metadata (XML or URL) into a pre-filled DTO |

Body is a `SamlProviderDto`. Key fields: `providerKey` (slug in the registration
id, immutable after creation), `displayName`, `idpEntityId`, `idpSsoUrl`,
`idpSloUrl`, `ssoBinding`, `idpSigningCertificate` (PEM X.509),
`nameIdFormat`, `emailAttribute`, `nameAttribute`, `wantAssertionsSigned`,
`wantAuthnRequestSigned`, `enabled`. The DTO also surfaces convenience read-only
fields: `registrationId`, `loginUrl` (where the login page posts the
SP-initiated auth request), and `spMetadataUrl` (WeldForge's SP metadata to hand
to the upstream IdP admin).

(Base path confirmed: `TenantController` is `@RequestMapping("/api/admin/tenants")`,
so the paths in the table above are exact.)

---

## 5. SCIM 2.0 provisioning (inbound user/group sync)

WeldForge exposes a SCIM 2.0 service for IdPs / HR systems (Okta, Workday, etc.)
to provision users and groups into a tenant.

### 5.1 Base URL & auth

- **Base URL**: `https://sso.weldforge.org/scim/v2/{slug}`
- **Auth**: `Authorization: Bearer <api-key>`. The API key is an
  **`app_clients` API key** scoped to a tenant. The `ScimAuthenticationFilter`
  hashes the presented key, looks it up, and **cross-checks that the key's
  tenant matches the `{slug}` in the URL** — a leaked token cannot be used
  against another tenant. Legacy unhashed keys are treated as revoked.
- **Content type**: `application/scim+json` (the controllers also accept
  `application/json` on writes).

### 5.2 Discovery (RFC 7644 §4) — `ScimDiscoveryController`

| Endpoint | Returns |
|---|---|
| `GET /scim/v2/{slug}/ServiceProviderConfig` | capabilities |
| `GET /scim/v2/{slug}/ResourceTypes` | `User`, `Group` |
| `GET /scim/v2/{slug}/Schemas` | core User / Group schema metadata |

Advertised capabilities: `patch: supported=true`, `filter: supported=true`
(maxResults 1000), `sort/etag/changePassword: supported=false`,
auth scheme `oauthbearertoken`.

> ⚠️ **Caveat — do not rely on the advertised bulk capability.**
> `ServiceProviderConfig` currently advertises `bulk: supported=false`
> (`maxOperations: 0`) **even though** the `/Bulk` endpoint is actually
> implemented (`ScimBulkController`). This mismatch is tracked as **B-TEN-3** in
> `docs/security/hardening-backlog.md`. Until it's reconciled, treat bulk as
> unsupported in your provisioning config — the advertised contract says it's
> off, and the implementation may change to match the advertisement.

### 5.3 Supported resources

- **Users** — `/scim/v2/{slug}/Users`: `GET` (list with `filter`, `startIndex`,
  `count`), `GET /{id}`, `POST`, `PUT /{id}`, `PATCH /{id}`, `DELETE /{id}`
  (`ScimUserController`).
- **Groups** — `/scim/v2/{slug}/Groups`: mirror of Users
  (`ScimGroupController`).
- **Bulk** — `/scim/v2/{slug}/Bulk` exists but is **not** advertised (see
  caveat above).

User deactivation is the SCIM `active` attribute (PRD PRV-03): setting
`active=false` (via `PUT` or `PATCH`) deactivates the account and emits a
`scim.user.deactivate` audit event; `active=true` reactivates
(`ScimUserService`).

---

## 6. Deprovisioning / offboarding

- **Per-user (SCIM)**: set `active=false` (`PUT`/`PATCH`) to deactivate, or
  `DELETE` the user. This flips the deactivation hook (PRV-03) and audits it.
- **Tenant deletion** (`TenantService.deleteTenant`, super-admin only) performs
  a hard sequence:
  1. **Bumps `token_version`** for every user in the tenant
     (`userRepository.bumpTokenVersionForTenant`) — outstanding access JWTs are
     invalidated at the **next** `JwtAuthenticationFilter` check.
  2. **Revokes all refresh-token families** for the tenant
     (`refreshTokenRepository.revokeAllForTenant`, reason `tenant_deleted`),
     closing the refresh side.
  3. Records a **slug holdback** (`TenantSlugHoldback`): the deleted slug cannot
     be reclaimed for `wf.public.slug-holdback-days` (the "90-day holdback";
     confirm the live value via `PublicHostProperties.getSlugHoldbackDays()`).
     This defends against a new tenant grabbing an old slug and inheriting stale
     trust/bookmarks.

> Note: the `token_version`-bump + refresh-revoke described above is the
> **tenant-level** kill switch. Per-user SCIM `active=false` is a softer
> deactivation, not a token_version bump.

---

## 7. Customising the login & password-reset forms

Each tenant's auth screens (login, register, forgot-password, reset-password,
verify-email) are brandable. Set branding via the admin portal
(**Tenants → Branding**) or `PUT /api/admin/tenants/{id}` with a `branding`
JSON object; it's stored on `tenants.branding` (JSONB) and served to the browser
by `GET /api/auth/tenants/{slug}/branding`.

Supported keys (see `docs/tenant-branding.md` for the authoritative, current
list) include CSS-variable keys (`primaryColor`, `primaryDarkColor`,
`accentColor`, `bgColor`, `bg2Color`, `borderColor`, `textColor`, `displayFont`,
`sansFont`, …) and content keys (`logoUrl`, `tagline`, `eyebrow`, `headline`,
`ctaLabel`, plus `displayName`), and the per-tenant feature toggles
(`registrationEnabled`, `passwordRecoveryEnabled`, `emailVerificationRequired`,
`returnToCallerEnabled`).

The tenant slug enters the auth URLs via the **per-tenant subdomain**: each
tenant lives at
`https://{slug}.sso.weldforge.org/{login,register,forgot-password,reset-password,verify-email}`,
its own site so browsers/password managers treat it distinctly. The
`/t/{slug}/...` apex path-prefix is reserved for OIDC/SAML protocol endpoints
(see §1). The legacy `?tenant=<slug>` query-param form has been removed — see
`docs/auth-url-spec.md`.

---

## See also

- `docs/auth-url-spec.md` — URL contract & per-tenant subdomain model
- `docs/tenant-branding.md` — branding keys (authoritative)
- `docs/security/hardening-backlog.md` — B-TEN-3 (SCIM bulk advertisement),
  B-SAML-1 (signed AuthnRequests)
- `docs/integrations/leap.md` — the always-live demo tenant
