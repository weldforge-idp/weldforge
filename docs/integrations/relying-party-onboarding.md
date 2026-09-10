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
What it supports, as published by the live `leap` tenant's discovery document
(`OidcDiscoveryController`, checked 2026-09-10):

- `response_types_supported`: `code` (`response_modes_supported`: `query`)
- `grant_types_supported`: `authorization_code`, `refresh_token`, `client_credentials`
- `token_endpoint_auth_methods_supported`: `client_secret_basic`, `client_secret_post`, `none`
- `id_token_signing_alg_values_supported`: `RS256`
- `code_challenge_methods_supported`: `S256` (PKCE)
- `scopes_supported`: `openid`, `profile`, `email`
- `subject_types_supported`: `public`
- `authorization_response_iss_parameter_supported`: `true` (RFC 9207, see §2.4)
- `claims_supported`: `sub`, `iss`, `aud`, `exp`, `iat`, `auth_time`, `email`,
  `name`, `picture`, `nonce`, `amr`, `roles`

Which standards and profiles this adds up to, and the known deviations, are in
[`../compliance/standards-conformance.md`](../compliance/standards-conformance.md).

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
`registration_client_uri`, `registration_access_token`, plus the echoed
metadata. The endpoint is public (rate-limited in production). When
`token_endpoint_auth_method` is omitted, the client is registered for
`client_secret_basic`.

**Managing the registration (RFC 7592).** Present the registration access token
as a bearer token:

```
GET    /t/{slug}/oauth2/register/{client_id}    Authorization: Bearer <registration_access_token>
DELETE /t/{slug}/oauth2/register/{client_id}    Authorization: Bearer <registration_access_token>
```

Read returns the current registration; delete deregisters the client. **Update
(`PUT`) is not supported** — see
[ADR 0003](../adr/0003-rfc7592-client-registration-management.md); ask a tenant
admin to change a registered client. Any failure — wrong token, unknown client,
another tenant's client — is the same `403 {"error":"invalid_token"}`, so the
endpoint cannot be used to discover which client ids exist.

> **Client authentication.** The token, introspection and revocation endpoints
> accept either `client_secret_basic` (HTTP Basic, with `client_id` and
> `client_secret` each form-urlencoded first, per RFC 6749 §2.3.1) or
> `client_secret_post` (both in the form body). Use one or the other; a request
> carrying both is refused.

### 2.3 redirect_uri, PKCE & scope rules

- **redirect_uri is exact-match** against the registered list — checked at both
  `/authorize` and the consent `/decide` step
  (`OidcAuthorizationController`). No wildcards, no prefix matching.
- **PKCE**: only `S256` is supported. **New clients require PKCE by default**:
  `requirePkce` is on for clients created through the admin API or dynamic
  registration unless an admin explicitly turns it off for a confidential
  client, and it is always on for public clients
  (`OidcAuthorizationService.issueAuthorizationCode` / `exchangeCode`). Send a
  `code_challenge` on every authorization request, confidential client or not.
  Clients registered before this default existed may still run a code flow
  without PKCE. Those flows are counted on the `sso.oidc.pkce.missing` meter
  rather than refused, and will be switched to required once the meter reads
  zero. Do not rely on the exemption.
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
    &max_age=...  &prompt=...                        (optional, see §2.7)
```

State machine (`OidcAuthorizationController.authorize`):

1. **Unauthenticated** → `302` to the tenant's subdomain login page
   (`https://{slug}.sso.weldforge.org/login/?oidcReturnTo=<base64url>`).
2. **Authenticated, consent already given** for these scopes → a code is issued
   straight away. Consent is remembered per user and client; a later request
   for **fewer** scopes is covered, and a request for **more** asks again.
3. **Authenticated, no consent** → server-rendered HTML consent screen listing
   the requested scopes, with a CSRF token bound to the user and tenant.
4. **Allow** → mint a single-use authorization code (5-minute TTL, stored
   hashed), `302` back to `redirect_uri` with `code`, `state` and `iss`.
5. **Deny** → `302` back with `error=access_denied` and `state`
   (RFC 6749 §4.1.2.1).

**Check `iss` (RFC 9207).** Every authorization response, success or error,
carries `iss` = the tenant's issuer (`https://sso.weldforge.org/t/{slug}`).
Every tenant is a separate issuer behind one hostname, so a client integrated
with more than one tenant must compare `iss` with the issuer it sent the user to
before redeeming the code. That is what defeats the mix-up attack
([ADR 0002](../adr/0002-rfc9207-issuer-identification.md)).

If the client requires MFA and the user's factors don't satisfy it, no code is
issued; see §2.7 for how that surfaces.

**Token exchange** (shown with `client_secret_basic`; `client_secret_post`
works too, see §2.2):

```
POST /t/{slug}/oauth2/token    Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(urlencode(client_id) ":" urlencode(client_secret))   (confidential clients)

grant_type=authorization_code
&code=...
&redirect_uri=...              (must match the code's redirect_uri)
&client_id=...                 (public clients, which send no Authorization header)
&code_verifier=...             (PKCE)
```

Response: `access_token`, `token_type: Bearer`, `expires_in`, `id_token`,
`scope`, and a `refresh_token` when the client holds the `refresh_token` grant.
Both access and ID tokens are **RS256-signed** with the tenant key (`kid` in the
JWS header), carry `iss = .../t/{slug}`, `aud = client_id`, and a `roles` array
derived from the user's role and super-admin flag (`OidcTokenService`). The ID
token also carries `auth_time`, `amr` and `at_hash` (§2.7). Authorization codes
are single-use and bound to the tenant and client. A code presented twice is
refused, **and the tokens the first exchange produced are revoked**, because a
replayed code means it leaked.

Access tokens are not RFC 9068 tokens: no `typ: at+jwt`, and `aud` is the
`client_id`. Resource servers should validate them accordingly
([ADR 0001](../adr/0001-rfc9068-jwt-access-token-profile.md)).

**Refreshing:**

```
POST /t/{slug}/oauth2/token
grant_type=refresh_token&refresh_token=...    (+ client authentication)
```

Refresh tokens rotate: every use returns a new refresh token, and presenting a
used one revokes its whole family (reuse detection). A refresh can **narrow**
scope but never widen it past what the user consented to.

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
| `/t/{slug}/oauth2/userinfo` | `GET` | `Authorization: Bearer <access_token>` | Verifies the token against the tenant JWKS, that `iss` is this tenant, that it is an access token, and that it has not been revoked. Returns `sub` always, `email` only with the `email` scope, and `name` / `picture` only with `profile` (OIDC Core §5.4). A failure is `401` with a `WWW-Authenticate: Bearer` challenge (RFC 6750 §3) whose `error` tells a client whether to refresh or re-authenticate (`OidcUserinfoController`). |
| `/t/{slug}/oauth2/introspect` | `POST` (form) | client authentication (§2.2) | RFC 7662. Unauthenticated → `401`; authenticated with a bad, expired or revoked token → `active=false`, not an error (`OidcIntrospectRevokeController`). |
| `/t/{slug}/oauth2/revoke` | `POST` (form) | client authentication; a **public** client sends only `client_id` | RFC 7009. Always `200` for a token the caller is entitled to revoke, known or not, so the endpoint cannot be used to probe which tokens exist. |
| `/t/{slug}/oauth2/logout` | `GET` / `POST` | browser session, optional `id_token_hint` | OIDC RP-Initiated Logout 1.0 (`end_session_endpoint`). Ends **every** session the user has, with or without `id_token_hint`, then redirects to a registered `post_logout_redirect_uri` with `state`, or returns `204`. Front- and back-channel logout are not implemented. |

**Revocation, precisely** (RFC 7009):

- **A refresh token** revokes its whole family: the token, every successor
  rotated from it, and so the login session it represents. That is what "sign
  this app out" should mean. Access tokens already minted keep working until
  they expire, unless you revoke them too.
- **An access token** is added to the revocation list. UserInfo and
  introspection refuse it immediately.
- **`token_type_hint`** is accepted and ignored (§2.2 allows this). The server
  works out what the token is: a tenant-signed JWT is an access token, anything
  else is looked up as a refresh token.
- A token issued to another client is not revoked. The response is still
  `200`.

### 2.6 Token TTLs

- **Access token**: `app.oidc.access-token-seconds` (default **3600s**), unless
  the tenant sets a per-tenant `accessTtlMs`, which takes precedence
  (`OidcTokenService.resolveAccessTtlSeconds`, PRD SSO-03).
- **ID token**: `app.oidc.id-token-seconds` (default **3600s**), capped at the
  effective access TTL.
- **Authorization code**: **300s** (5 min), single-use
  (`OidcAuthorizationService.CODE_TTL_SECONDS`).
- **Client-credentials access token**: advertised `expires_in: 3600`.

### 2.7 Session freshness: `max_age`, `prompt` and `auth_time`

**`auth_time`.** The ID token carries `auth_time`: when the user actually
authenticated to WeldForge, in seconds since the epoch. A refreshed ID token
reports the **original** authentication, not the refresh; that difference from
`iat` is the whole point of the claim. When the authentication time is not
known (a session older than the claim itself), `auth_time` is **omitted**
rather than guessed. Treat a missing `auth_time` as "unknown", never as "now".

**`amr`.** The ID token's `amr` lists the RFC 8176 methods the user actually
used — for example `["pwd"]`, `["pwd","otp","mfa"]`, `["pwd","hwk","mfa"]`.
Use it, not the presence of MFA enrolment, to decide whether a login was
strong enough.

**`at_hash`.** The ID token binds the access token issued with it (OIDC Core
§3.1.3.6). Validate it if your library supports that.

**`prompt`.**

| Value | Behaviour |
|---|---|
| `none` | Never shows UI. With no session, redirects back with `error=login_required`; with a session but no standing consent for the requested scopes, `error=consent_required`; otherwise issues a code silently. Use this for silent session checks. |
| `consent` | Always shows the consent screen, even when consent is already on file. |
| `login`, `select_account` | **Not supported; ignored.** An existing session is reused. To force a fresh login, end the session first (RP-initiated logout) or use `max_age`, with the caveat below. |

**`max_age`.** Send `max_age=N` to require that the user authenticated within
the last `N` seconds. The effective limit is the smallest of the request's
`max_age`, the client's configured maximum authentication age and the tenant's
step-up default.

> **Known deviation — read before relying on `max_age`.** WeldForge enforces
> `max_age` as **MFA step-up freshness**: it checks when the user last used a
> verified MFA factor, not when they last authenticated. When that is too old,
> or the user has no MFA factor at all, the authorization request ends with a
> `400` JSON error `{"error":"mfa_required"}` shown in the browser. It does not
> redirect back to your `redirect_uri`, and it does not prompt the user to
> re-authenticate. OIDC Core §3.1.2.1 expects re-authentication. Until that
> changes, send `max_age` only to users you know have MFA enrolled, and compare
> `auth_time` yourself. This is recorded in the
> [conformance statement](../compliance/standards-conformance.md).

---

## 3. SAML IdP onboarding (WeldForge issues assertions to your SP)

Use this when your application is a SAML **Service Provider** and you want
WeldForge to be its **Identity Provider**.

### 3.1 Where your SP fetches WeldForge's IdP metadata

```
GET /t/{slug}/saml2/idp/metadata        (public, application/samlmetadata+xml)
```

(`SamlIdpController.metadata`.) Point your SP's IdP-metadata configuration here.

What the metadata publishes:

- **`entityID`** — always the canonical
  `https://sso.weldforge.org/t/{slug}/saml2/idp/metadata`, whichever host you
  fetched it from. Endpoint `Location`s follow the host you used.
- **Signing certificate** — a real self-signed X.509 wrapping the tenant's
  current RSA signing key (subject = the entityID). The same certificate is in
  every assertion's signature `KeyInfo`, so you can pin it or validate against
  metadata; both agree. It changes when the tenant's key rotates — re-fetch
  metadata rather than hard-coding the certificate.
- **`WantAuthnRequestsSigned`** — the tenant's stated intent (see §3.4).

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
| `wantAuthnRequestSigned` | when true **and** `spCertificate` is set, the IdP verifies the XML signature on inbound AuthnRequest / LogoutRequest messages and rejects unsigned/invalid ones (B-SAML-1). See §3.4 for the order to turn this on in. |
| `useEntityIdAsIssuer` | when true, assertions **and** logout messages carry the metadata entityID as `Issuer` instead of the legacy `{slug}-idp`. Default false. See §3.6. |
| `authnContextOverride` | a fixed `AuthnContextClassRef` sent on every assertion instead of one derived from how the user signed in. On `PUT`, omit it to leave it unchanged and send `""` to clear it. See §3.6. |

The admin portal exposes the last three as per-SP toggles (**Tenants → SAML
IdP**). `PUT` is a partial update: send only the fields you are changing.

### 3.3 SSO endpoints (the runtime flow)

- **SP-initiated SSO**: `POST` or `GET` `/t/{slug}/saml2/idp/sso` with a
  `SAMLRequest` (and optional `RelayState`). The user must already be
  authenticated (else `401`). WeldForge decodes the AuthnRequest (XXE-hardened
  parse), matches the `Issuer` to a registered SP, verifies the request
  signature if required, checks the request is fresh and unused (below),
  builds a signed `SAMLResponse`, and returns an auto-submitting HTML form
  POSTing it to the SP's `acsUrl` (`SamlIdpController.handleSso`).
- **Requests are single-use and must be fresh.** An AuthnRequest whose `ID` has
  been seen before, whose `IssueInstant` is more than 10 minutes old, or that is
  dated more than 3 minutes in the future is refused with `400` and audited as
  `saml.authnrequest.replay`. Mint a new AuthnRequest per login attempt (every
  mainstream SP library does) and keep your SP's clock synchronised. A request
  with no `ID` or `IssueInstant` is accepted but cannot be protected; fix the SP.
- **`SessionIndex`.** Every assertion's `AuthnStatement` carries a
  `SessionIndex` that is stable for the user's WeldForge login session and
  different for each SP. Store it with your SP-side session if you implement
  Single Logout.
- **Single Logout** (PRD SAM-06):
  - *IdP-initiated* — `POST /t/{slug}/saml2/idp/slo` returns a `LogoutRequest`
    per SP with an `sloUrl`, each naming the session being ended by its
    `SessionIndex`.
  - *SP-initiated* — `POST /t/{slug}/saml2/sp-slo` with a `SAMLRequest`, sent
    with the user's WeldForge session. The `NameID` must be that user (a
    mismatch is answered with `status:Requester` and ends nothing). With one or
    more `SessionIndex` elements, **only those sessions end** — the user stays
    signed in on their other devices. With none, **every** session of that
    user ends (SAML Core §3.7.3.2). Either way, if the browser's own session
    ended, its cookies are cleared.

### 3.4 Enabling signed AuthnRequests (recommended, XSW-resistant)

Order matters. Turning enforcement on before your SP signs breaks its login.

1. **Tenant admin:** switch on *"Metadata asks SPs to sign AuthnRequests"*
   (`PUT /api/admin/tenants/{id}` with `"samlWantAuthnRequestsSigned": true`).
   The IdP metadata now says `WantAuthnRequestsSigned="true"`. Nothing is
   enforced yet.
2. **SP owner:** re-import WeldForge's metadata (or configure signing by hand)
   so the SP starts signing its AuthnRequests and LogoutRequests. Confirm a
   login still works.
3. **Tenant admin:** upload the SP's signing certificate in `spCertificate`,
   then set `wantAuthnRequestSigned: true` on that SP.

From step 3 the IdP rejects unsigned or invalid-signature AuthnRequests and
LogoutRequests for that SP (`SamlIdpService.verifyAuthnRequestSignature`; the
XML is parsed XXE-hardened and namespace-aware by `SamlInboundMessageParser`).
Without a certificate on file, signature verification cannot run.

### 3.5 Assertion encryption

Set `encryptAssertions: true` (with `spCertificate`) to have the IdP emit an
`EncryptedAssertion` instead of a cleartext assertion.

### 3.6 Issuer and authentication context (per-SP opt-ins)

Both change bytes your SP already checks, so both are per-SP and neither
changes on its own.

**Issuer.** By default assertions and logout messages carry `Issuer` =
`{slug}-idp`. A conformant SP expects the metadata entityID instead. To switch:
first reconfigure the SP to expect
`https://sso.weldforge.org/t/{slug}/saml2/idp/metadata` as the IdP's issuer,
then set `useEntityIdAsIssuer: true`. In the other order, every login is
rejected until the SP is updated.

**Authentication context.** `AuthnContextClassRef` reports how the user signed
in to WeldForge, strongest factor first:

| Session | `AuthnContextClassRef` |
|---|---|
| security key / passkey (`hwk`, `swk`) | `urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract` |
| one-time code (`otp`, `sms`) | `urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken` |
| password only, or unknown | `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport` |

**SPs that already existed when migration V56 was applied are pinned** to
`PasswordProtectedTransport`, because an SP that accepts only that value would
otherwise reject users the first time they sign in with MFA. When your SP
accepts the stronger classes, ask the tenant admin to clear the pin
(`authnContextOverride: ""`, or the *Auth context → from session* toggle). SPs
registered after V56 get the derived value unless they set a pin.

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
(maxResults 1000), `bulk: supported=true` with the enforced `maxOperations`
(default 100, `app.scim.bulk.max-operations`) and `maxPayloadSize`,
`sort/etag/changePassword: supported=false`, auth scheme `oauthbearertoken`.
Read the limits from `ServiceProviderConfig` rather than hard-coding them.

### 5.3 Supported resources

- **Users** — `/scim/v2/{slug}/Users`: `GET` (list with `filter`, `startIndex`,
  `count`), `GET /{id}`, `POST`, `PUT /{id}`, `PATCH /{id}`, `DELETE /{id}`
  (`ScimUserController`).
- **Groups** — `/scim/v2/{slug}/Groups`: mirror of Users
  (`ScimGroupController`).
- **Bulk** — `/scim/v2/{slug}/Bulk`, capped at the advertised
  `maxOperations`. A failed sub-operation returns a generic error detail; the
  cause is logged server-side (`ScimBulkController`).

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
- `docs/compliance/standards-conformance.md` — which standards WeldForge
  implements, to what degree, and the known deviations
- `docs/adr/` — standards considered and declined or partly adopted
- `docs/security/hardening-backlog.md` — B-SAML-1 (signed AuthnRequests,
  replay), B-SAML-3 (certificate and issuer)
- `docs/integrations/leap.md` — the always-live demo tenant
