# WeldForge — Standards Conformance Statement

> **As of:** 2026-09-10 · end of conformance programme Sprint 6 (Flyway V56)
> **Scope:** `weldforge-auth`, the identity service, as deployed at `sso.weldforge.org`
> **Owner:** Product · **Regenerated:** at the close of every sprint that changes
> protocol behaviour (CONF-8.1)

This statement says which identity standards WeldForge implements, to what
degree, and where it knowingly departs from them. It exists so a security
questionnaire can be answered without a discovery call. It is derived from the
code and from the live service, not from intentions. Every "Implemented" below
is exercised by the test suite, and the protocol metadata quoted is what the
`leap` demo tenant publishes.

**No certification is claimed.** WeldForge has not run the OpenID Foundation
conformance suite or any SAML interoperability programme. A self-certification
dry run is on the backlog (CONF-8.3). Until it has run, do not describe
WeldForge as "OpenID Certified".

**Status key:** **Implemented** · **Partial** (implemented with a recorded
limitation) · **Not implemented** · **Declined** (a recorded decision, see
[`../adr/`](../adr/)).

---

## Summary

| Area | Standard | Status |
|---|---|---|
| OAuth 2.0 | RFC 6749 authorization framework (code, refresh, client credentials) | Implemented, see deviation D4 |
| | RFC 6750 bearer token usage | Implemented |
| | RFC 7636 PKCE (`S256`) | Implemented; required for new clients, see D3 |
| | RFC 7009 token revocation | Implemented |
| | RFC 7662 token introspection | Implemented |
| | RFC 7591 dynamic client registration | Implemented (open registration, rate-limited) |
| | RFC 7592 registration management | Partial: read and delete, no update ([ADR 0003](../adr/0003-rfc7592-client-registration-management.md)) |
| | RFC 8252 native apps (loopback redirect port matching) | Implemented |
| | RFC 9207 issuer identification | Implemented ([ADR 0002](../adr/0002-rfc9207-issuer-identification.md)) |
| | RFC 9068 JWT access-token profile | Declined ([ADR 0001](../adr/0001-rfc9068-jwt-access-token-profile.md)) |
| | RFC 8414 authorization server metadata | Not implemented; OIDC Discovery serves the same purpose |
| | PAR, JAR, JARM, DPoP, mTLS, FAPI 2.0 | Not implemented |
| OpenID Connect | Core 1.0: authorization code flow | Partial, see D1 and D2 |
| | Discovery 1.0 | Implemented, per tenant |
| | Dynamic Client Registration 1.0 | Implemented |
| | RP-Initiated Logout 1.0 | Implemented |
| | Front-Channel / Back-Channel Logout | Not implemented |
| SAML 2.0 | IdP: Web Browser SSO profile | Implemented |
| | IdP: Single Logout | Partial, see D6 |
| | IdP: metadata | Implemented |
| | SP: federating an upstream IdP | Implemented (Spring Security SAML / OpenSAML) |
| SCIM 2.0 | RFC 7643 / RFC 7644: Users, Groups, PATCH, filter, Bulk | Implemented; sort, ETag, changePassword declared unsupported |
| JOSE | RFC 7515 / 7517 / 7519: JWS, JWKS, JWT | Implemented |
| Authentication | RFC 8176 `amr` values | Implemented |
| | WebAuthn Level 2 (FIDO2) | Implemented |
| | RFC 6238 TOTP | Implemented |
| | NIST SP 800-63B §5.1.1.2 memorized secrets | Implemented with two deviations, D7 and D8 ([ADR 0004](../adr/0004-nist-sp-800-63b-password-policy.md)) |
| HTTP | RFC 9457 Problem Details (on `/api/**`) | Implemented |
| | Content-Security-Policy, Referrer-Policy, HSTS | Implemented |

---

## 1. OAuth 2.0 and extensions

Each tenant is its own authorization server. Its issuer is
`https://sso.weldforge.org/t/{slug}` and its metadata is at
`/t/{slug}/.well-known/openid-configuration`.

- **Grants:** `authorization_code`, `refresh_token`, `client_credentials`. The
  implicit and resource-owner-password grants are not offered.
  `response_type=code` only, `response_mode=query`.
- **Client authentication:** `client_secret_basic`, `client_secret_post`, and
  `none` (public clients with PKCE). Presenting both Basic and form credentials
  is refused (RFC 6749 §2.3.1). Secrets are generated server-side, stored
  AES-GCM-encrypted, compared in constant time, and shown once.
- **Redirect URIs:** exact match against the registered list, checked at
  `/authorize` and again at the consent decision. The one exception is RFC 8252
  loopback redirects, which match on any port. Errors before `redirect_uri`
  is validated are never redirected.
- **Authorization codes:** single-use, 5-minute lifetime, stored hashed, bound
  to tenant, client and redirect URI. A replayed code **revokes the tokens the
  first exchange produced** (RFC 6749 §4.1.2).
- **PKCE:** `S256` only. On by default for every new client and always for
  public clients. Older clients without it are metered, not yet refused (D3).
- **Refresh tokens:** opaque, rotated on every use, reuse detection revokes the
  whole family, scope cannot widen past the original consent, and bound to the
  client they were issued to.
- **Scope:** requests are limited to the client's registered scopes plus the
  standard OIDC scopes.
- **Revocation (RFC 7009):** a refresh token revokes its family; an access
  token goes on the revocation list consulted by UserInfo and introspection.
  `token_type_hint` is accepted and ignored. The response is always `200`.
- **Introspection (RFC 7662):** client-authenticated; returns `active=false`
  for anything invalid, expired or revoked.
- **Bearer usage (RFC 6750):** a `401` from UserInfo carries a
  `WWW-Authenticate: Bearer` challenge with an `error` code.
- **Issuer identification (RFC 9207):** `iss` on every authorization response,
  advertised in discovery.

## 2. OpenID Connect

- **Core:** ID tokens are RS256-signed with a per-tenant key (`kid` in the
  header). They carry `iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, `auth_time`
  (the original authentication, preserved across refresh; omitted when
  unknown), `amr` (RFC 8176, the methods actually used), `at_hash` and `roles`.
  UserInfo releases claims by granted scope (§5.4). `prompt=none` returns
  `login_required` or `consent_required` without UI, and `prompt=consent`
  forces the consent screen. Consent is persisted per user, client and scope
  set. Subject type is `public`.
- **Discovery:** complete for the endpoints implemented. A test walks every
  advertised URL against the controller mappings.
- **Dynamic registration:** as RFC 7591 above.
- **RP-Initiated Logout:** ends every session of the user, with or without an
  `id_token_hint`. The `post_logout_redirect_uri` is validated against the
  client's registered list.
- **Not implemented:** `claims` and `request` / `request_uri` parameters, `acr`
  / `acr_values`, pairwise subjects, `prompt=login` (D2), front- and
  back-channel logout, and session management.

## 3. SAML 2.0

**WeldForge as IdP** (per tenant; metadata at `/t/{slug}/saml2/idp/metadata`):

- **Bindings:** AuthnRequest over HTTP-Redirect or HTTP-POST; Response over
  HTTP-POST. Artifact binding is not supported.
- **Signing:** the assertion is signed with RSA-SHA256 and exclusive
  canonicalisation. The signature `KeyInfo` carries a real X.509 certificate,
  the same one metadata publishes.
- **Inbound messages:** parsed XXE-hardened (no DOCTYPE) and namespace-aware.
  Signature verification is per SP and resistant to XML signature wrapping.
  AuthnRequests must be fresh (`IssueInstant` within 10 minutes, with 3 minutes
  of clock skew) and single-use.
- **Assertions:** audience, recipient and ACS come from the stored SP
  registration, never from the request. `AuthnContextClassRef` reflects the
  factors actually used; SPs registered before V56 are pinned to
  `PasswordProtectedTransport` until they opt in. `SessionIndex` is stable per
  session and different per SP. NameID formats: `emailAddress`, `persistent`,
  `transient`, `unspecified`. Per-SP attribute release policy.
- **Identity:** the metadata `entityID` is canonical. The assertion `Issuer`
  is `{slug}-idp` by default, or the entityID per SP opt-in (D5).
- **Encryption:** optional per SP, AES-256-CBC with RSA-OAEP-MGF1-SHA1 key
  transport (D9).
- **Metadata:** states `WantAuthnRequestsSigned` from a tenant-level setting.

**WeldForge as SP** (federating a tenant's upstream IdP): Spring Security SAML
2.0 service provider on OpenSAML, with per-tenant registrations, metadata
import, and signed-assertion requirement configurable per provider.

## 4. SCIM 2.0

Service at `/scim/v2/{slug}`, bearer-authenticated with a hashed, tenant-bound
API key. `ServiceProviderConfig`, `ResourceTypes` and `Schemas` are served.
Users and Groups support create, read, replace, PATCH, delete, list and filter.
Bulk is supported and advertised with its real limits. `sort`, `etag` and
`changePassword` are declared unsupported, which is the correct way to omit an
optional feature. Deactivation is `active=false`.

## 5. Authentication

- **Passwords:** NIST SP 800-63B §5.1.1.2. The minimum is 12 characters; there
  are no composition rules; new passwords are screened against the Pwned
  Passwords corpus by k-anonymity (only a 5-character hash prefix leaves the
  server). Periodic change is never required and no hints are offered.
  Throttling is a rate limit plus lockout after 5 failures in 15 minutes.
  Storage is bcrypt cost 12, upgraded on login. Deviations D7 and D8.
- **WebAuthn:** user verification is required at enrolment and at assertion
  (credentials enrolled before that are grandfathered). A signature-counter
  regression disables the credential. Ceremony state is persisted and
  single-use. Tenant subdomains are accepted as origins. No attestation is
  requested, so authenticator make and model are not verified.
- **TOTP:** RFC 6238, SHA-1, 6 digits, 30-second period, and a code cannot be
  reused within its validity window. SMS one-time codes are available per
  tenant; 800-63B classes SMS as a *restricted* authenticator.
- **MFA challenge tokens** are single-use (`jti`).

## 6. JOSE and keys

- OIDC tokens: RS256, RSA-2048, one active key per tenant, JWKS at
  `/t/{slug}/oauth2/jwks` with `kid`. The JWKS publishes rotated keys alongside
  the active one, so tokens signed before a rotation keep verifying.
- Algorithms are pinned on verification (no `alg=none`, no algorithm
  confusion), and verification allows 60 seconds of clock skew.
- Platform session tokens, consumed by WeldForge and the Tech Metropolis
  services, are HS512 with a shared secret. There is no key ring yet, so
  rotation is a coordinated cutover (D10).

## 7. HTTP and web security

- **Problem Details (RFC 9457):** every `/api/**` error is
  `application/problem+json` with `type` (a `tag:` URI per error code),
  `title`, `status`, `detail` and `instance`, and it keeps the legacy `error` /
  `message` members as extensions. The OAuth, OIDC and SCIM endpoints keep the
  error formats their own specifications require.
- **Content-Security-Policy:** every response has `default-src 'self'`, and
  scripts and styles are allowed only with a per-response nonce. It also sets
  `object-src 'none'`, `base-uri 'none'` and `frame-ancestors 'none'`.
- Also on every response: `Referrer-Policy: no-referrer`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and HSTS on
  HTTPS.
- **TLS:** terminated at the edge with a Let's Encrypt certificate covering
  `sso.weldforge.org` and `*.sso.weldforge.org`.

---

## Known deviations

| # | Standard | Deviation | Impact | Plan |
|---|---|---|---|---|
| D1 | OIDC Core §3.1.2.1 `max_age` | Enforced as MFA-factor freshness, not time since authentication. When exceeded, or when the user has no MFA factor, `/authorize` answers `400 {"error":"mfa_required"}` in the browser instead of re-authenticating the user or redirecting to the RP. `mfa_required` is not a registered error code. | An RP that sends `max_age` breaks the login of any user without MFA. | Re-authenticate on stale `auth_time`; keep MFA step-up as a separate client policy. Not yet scheduled. |
| D2 | OIDC Core §3.1.2.1 `prompt=login` | Ignored; an existing session is reused. The spec says SHOULD re-authenticate, and MUST error if it cannot. | An RP cannot force a fresh login. | Implement with D1. |
| D3 | RFC 7636 / OAuth 2.1 | Clients registered before the PKCE default can still run a code flow without a challenge. | Those clients lack PKCE's protection against code interception. | Refuse once `sso.oidc.pkce.missing` reads zero. |
| D4 | RFC 6749 §5.2 | An unknown client at the token endpoint gets `400 invalid_client`. The spec wants `401`, with `WWW-Authenticate` when HTTP Basic was attempted. | Cosmetic for most clients. | Backlog. |
| D5 | SAML 2.0 Core (Issuer) | The default assertion `Issuer` is `{slug}-idp`, not the metadata entityID. The entityID is available per SP by opt-in. | A strictly validating SP must opt in or be configured with `{slug}-idp`. | Keep the opt-in; changing it globally breaks existing SPs. |
| D6 | SAML 2.0 Single Logout bindings | The SLO endpoints return the encoded LogoutRequest / LogoutResponse as JSON for the caller to deliver, rather than performing the HTTP-Redirect or HTTP-POST binding themselves. Session termination is real (SessionIndex-scoped, or all sessions). | An SP must deliver the message itself. | Backlog. |
| D7 | NIST SP 800-63B §5.1.1.2 (length) | Maximum 72 bytes (the bcrypt limit), which for mostly multi-byte characters can fall below the recommended 64 characters. | Very long non-ASCII passphrases are refused, never silently truncated. | Only if storage moves to pre-hashed bcrypt or Argon2id. |
| D8 | NIST SP 800-63B §5.1.1.2 (screening) | Breach screening fails open if the corpus is unreachable. | An outage of a third-party service cannot block registration or reset; screening pauses, logged and metered. | Alert on `sso.password.breach_check{outcome="unavailable"}`; mirror the corpus locally if it becomes frequent. |
| D9 | XML Encryption 1.1 | Assertion encryption uses AES-CBC and RSA-OAEP with SHA-1, not AES-GCM and SHA-256. | Legacy algorithms; changing them changes what the SP must decrypt. | Per-SP opt-in to GCM (B-SAML-2). |
| D10 | Key management | The shared HS512 platform secret has no key ring. | Rotation is a synchronised cutover across four services. | CONF-7.4, when the consumers support multiple keys. |

---

## Evidence

- Tests: `./mvnw -B -ntp verify -Dtests.integration=true` — 695 tests, including
  187 BDD scenarios (`weldforge-auth/src/test/resources/features/`) and a
  Testcontainers run that applies every migration to a fresh database.
- Live metadata: `https://sso.weldforge.org/t/leap/.well-known/openid-configuration`,
  `/t/leap/oauth2/jwks` and `/t/leap/saml2/idp/metadata`.
- Engineering register: [`../security/hardening-backlog.md`](../security/hardening-backlog.md).
- Programme and change history:
  [`../product/standards-conformance-backlog.md`](../product/standards-conformance-backlog.md).
- Integration contract:
  [`../integrations/relying-party-onboarding.md`](../integrations/relying-party-onboarding.md).
