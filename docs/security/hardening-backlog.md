# WeldForge Security Hardening Backlog

> Living document. Created 2026-06-15 from a six-domain expert review (OAuth2/OIDC,
> SAML, token crypto/key management, authentication/MFA, multi-tenant isolation/SCIM,
> docs/governance). Severity is the reviewer's assessment; "as-deployed exploitability"
> is noted separately because several Critical-by-class items are gated by environment
> config that is currently set correctly in production.
>
> Companion docs: [threat-model.md](../threat-model.md),
> [runbooks/key-rotation.md](../runbooks/key-rotation.md),
> [runbooks/incident-response.md](../runbooks/incident-response.md).

## Overall posture

WeldForge is a security-conscious, above-average IAM codebase. The hardest things are
right: RS256/HS512 are algorithm-pinned (no alg-confusion / `alg=none`), tenant binding
is JWT-authoritative and refuses header spoofing, auth flows are enumeration-resistant,
the SAML *SP* path uses OpenSAML, codes are hashed/single-use/TTL-bound, and the PR #44
failed-login/lockout transaction fix is correct. Residual risk concentrates in: (1) the
hand-rolled **SAML IdP** and **OAuth2 consent/error** state machines, (2) **MFA replay /
single-use**, and (3) **governance documentation**.

---

## ✅ Fixed in the 2026-06-15 hardening pass (branch `security/hardening-pass-2026-06`)

| # | Item | Files |
|---|------|-------|
| F1 | **Secret hygiene** — removed the burned production-shape HMAC default from `application.yml`; added `SecretHygieneValidator` that always enforces minimum secret length and, when `APP_REQUIRE_SECURE_SECRETS=true` (now set on all cluster deploys via Helm), refuses to boot on a known dev/placeholder default. | `application.yml`, `config/security/SecretHygieneValidator.java`, `infrastructure/helm/weldforge/values.yaml` |
| F2 | **OAuth2 consent open redirect** — `decide()` now re-validates `redirect_uri` against the client's registered list before building any 302 (deny path was an open redirect). | `controller/OidcAuthorizationController.java` |
| F3 | **OAuth2 scope enforcement** — requested scopes are now restricted to the client's registered scopes (∪ standard OIDC scopes). Backward-compatible: only enforced when the client has a non-empty scope list (see B-OIDC-1 to tighten). | `service/oidc/OidcAuthorizationService.java` |
| F4 | **Constant-time `client_secret` compare** in introspection + revocation (matched the token endpoint, which already did this). | `controller/OidcIntrospectRevokeController.java` |
| F5 | **Clock-skew tolerance (60s)** added to all five JWT verifiers; also removed a dead double-parse in userinfo. | `service/JwtService.java`, `service/oidc/OidcIntrospectionService.java`, `service/oidc/OidcRevocationService.java`, `controller/OidcUserinfoController.java`, `controller/OidcLogoutController.java` |
| F6 | **Doc accuracy** — fixed README's false "Spring Authorization Server" claim, qualified the "independent audit" wording, corrected migration count (V34→V41) and Java version (21→25). | `README.md` |
| F7 | **Consent-flow CSRF (B-OIDC-1)** — the consent form now carries a signed, per-render `consent_csrf` token bound to the authenticated user + tenant; `decide()` requires a valid one whose subject matches the session principal. A cross-site auto-submit can't mint or read such a token, so consent CSRF is blocked despite global CSRF being disabled. | `service/JwtService.java`, `controller/OidcAuthorizationController.java` |
| F8 | **TOTP anti-replay (B-MFA-1)** — TOTP verification now records the accepted time-step (`user_mfa_factors.last_totp_step`) and rejects any code whose step is `<=` the last accepted one, both at login and on enrollment activation. `TotpService.matchingStep` returns the matched step via a constant-time check over the ±1 window. | `V42__mfa_totp_anti_replay.sql`, `model/MfaFactor.java`, `service/mfa/TotpService.java`, `service/mfa/MfaService.java` |
| F9 | **MFA challenge single-use (B-MFA-2)** — challenge tokens now carry a `jti`; `resolveChallenge` rejects a `jti` already recorded in `consumed_mfa_challenge`, and `consumeChallenge` records it on the first successful MFA completion. An hourly job prunes expired rows. | `V43__consumed_mfa_challenge.sql`, `model/ConsumedMfaChallenge.java`, `repository/ConsumedMfaChallengeRepository.java`, `service/JwtService.java`, `service/mfa/MfaService.java`, `service/mfa/ConsumedMfaChallengeCleanup.java`, `controller/MfaController.java` |
| F10 | **`setAdminRole` tenant-scoping (B-TEN-1)** — the target user is now resolved via `findByIdAndTenantId` through the caller's resolved tenant (matching every other user mutation), so a super-admin can only set admin roles within the tenant they've switched into (the X-WF-Tenant switch is audited). Covered by TDD unit tests + BDD `tenant_isolation.feature` scenarios. | `service/AdminService.java` |
| F11 | **SAML inbound XML hardening (B-SAML-1 part b)** — replaced the IdP's `indexOf`/substring scanning of inbound AuthnRequest/LogoutRequest with an XXE-hardened, namespace-aware DOM parser (`SamlInboundMessageParser`, DOCTYPE forbidden, external entities disabled). Resists parser-differential, comment/CDATA and namespace-prefix tricks, and is the prerequisite for AuthnRequest signature verification. TDD unit tests + BDD `saml_idp.feature` (issuer parse + DOCTYPE/XXE rejection). | `service/saml/SamlInboundMessageParser.java`, `service/saml/SamlMessageException.java`, `controller/SamlIdpController.java` |
| F12 | **SAML AuthnRequest signature verification (B-SAML-1 part a)** — per-SP `wantAuthnRequestSigned` flag; when set, inbound AuthnRequest/LogoutRequest signatures are verified against the SP's certificate by an XSW-resistant validator (single signature, enveloped over the root, single reference to the root ID, secure validation). Unsigned/invalid requests are rejected; SPs that don't opt in are unaffected. TDD unit tests (real signatures, incl. tamper/wrong-key/unsigned/no-ID) + BDD `saml_idp.feature` scenarios. | `V44__saml_sp_want_authn_request_signed.sql`, `model/SamlServiceProvider.java`, `service/saml/SamlSignatureValidator.java`, `service/saml/SamlIdpService.java`, `controller/SamlIdpController.java` |
| F13 | **`/authorize` spec-conformant error redirects (B-OIDC-2)** — once `client_id`+`redirect_uri` are validated, protocol errors (e.g. `unsupported_response_type`) now redirect to the registered `redirect_uri` with `error`+`state` (RFC 6749 §4.1.2.1) instead of a JSON 400. Pre-validation errors (unknown client, unregistered redirect_uri) stay non-redirecting 400s, so the deny/error path can't become an open redirect. `OidcAuthorizationException` carries an optional redirect target; unit-tested handler. | `service/oidc/OidcAuthorizationException.java`, `controller/OidcAuthorizationController.java` |
| F14 | **SSRF egress guard on outbound URLs (B-LEGACY-1)** — central `EgressGuard` (http/https only; blocks loopback/any-local/link-local incl. metadata, RFC1918, IPv6 ULA, CGNAT, multicast) wired into webhook + CRM send paths (before the circuit breaker) and webhook subscription create/update. Unit-tested (literal-IP, hermetic) + service-level create-guard test. | `service/security/EgressGuard.java`, `service/security/EgressNotAllowedException.java`, `service/webhook/JdkWebhookHttpClient.java`, `service/webhook/WebhookSubscriptionService.java`, `service/crm/HttpCrmClient.java` |
| F15 | **Platform audience on HMAC access tokens (B-JWT-1, WeldForge side)** — access tokens now carry `app.jwt.audience` (default `weldforge`) and `JwtAuthenticationFilter` requires it, scoping WeldForge's API to tokens minted for it. Transparent to external consumers (extra claim ignored); 5-min TTL self-heals rollover. Per-consumer audiences + `iss` validation remain open follow-ups. | `service/JwtService.java`, `config/JwtAuthenticationFilter.java`, `application.yml` |
| F16 | **Audit failed cross-tenant switches (B-TEN-2)** — `CrossTenantSelectorFilter` emits `admin.cross_tenant.denied` (outcome DENIED, reason `unknown_tenant`/`no_membership`) on both refusal branches; previously only successes were audited. Filter unit-tested. | `config/tenant/CrossTenantSelectorFilter.java`, `service/audit/AuditEventTypes.java` |
| F17 | **Bcrypt upgrade-on-login (B-AUTH-2)** — a verified login re-hashes a weaker stored password (lower BCrypt cost) at the current strength via `AuthService.maybeUpgradePassword`. Unit-tested (cost-4 → cost-12). | `service/AuthService.java` |
| F18 | **userinfo/introspection token-type + audience (B-OIDC-3)** — userinfo requires `token_type=access` (rejects ID tokens); introspection returns inactive when the token isn't the caller's own (`client_id`/`aud` match). Real-token unit tests. | `controller/OidcUserinfoController.java`, `service/oidc/OidcIntrospectionService.java`, `controller/OidcIntrospectRevokeController.java` |
| F19 | **redirect_uri validation at registration (B-OIDC-4, partial)** — `OidcClientService.create` rejects non-absolute / fragment-bearing / http-non-loopback redirect URIs. Unit-tested. | `service/oidc/OidcClientService.java` |
| F20 | **client_credentials honest `expires_in` (B-OIDC-5)** — token endpoint returns the resolved per-tenant TTL instead of a hardcoded 3600. | `service/oidc/OidcTokenService.java`, `controller/OidcAuthorizationController.java` |
| F21 | **SCIM bulk advertised truthfully + error sanitized (B-TEN-3)** — `ServiceProviderConfig` reports `bulk.supported=true` with the real `maxOperations`; bulk sub-op failures return a generic detail (no raw exception text). | `controller/ScimDiscoveryController.java`, `controller/ScimBulkController.java` |
| F22 | **Display-name input validation (B-LEGACY-2)** — `AuthService.validateDisplayName` rejects `<`/`>`/control chars (and over-length) at registration + profile update, closing the input side of stored XSS into SAML/email sinks. Unit-tested. | `service/AuthService.java` |
| F23 | **Rate-limit recovery + SMS-send (B-AUTH-3)** — `forgot-password`/`reset-password`/`resend-verification`/`mfa/sms/send` share a per-IP `RECOVERY` bucket. Filter routing unit-tested. | `config/security/RateLimitingFilter.java`, `service/security/RateLimitingService.java` |
| F24 | **Logout id_token_hint by kid (B-JWT-3)** — `OidcLogoutController.parseTenantJwt` resolves the key by the token's `kid` (tenant-scoped), so logout survives a key-rotation window. | `controller/OidcLogoutController.java` |
| F25 | **WebAuthn tenant-subdomain origins (CONF-3.0)** — `origins` is an exact-match allow-list and tenant hosts are minted at runtime, so registration succeeded on the apex and failed on every tenant host with an origin mismatch. `allowOriginSubdomain(true)` widens acceptance to subdomains *of the configured origins only*, consistent with `rp-id`, which is already the registrable base. **This was live in production.** | `config/mfa/WebAuthnConfig.java` |
| F26 | **Refresh must not widen scope (CONF-1.1)** — the refresh branch re-derived scope from `client.getScopeList()`, so consenting to `openid email` returned the client's whole registration on the first refresh (RFC 6749 §6). Granted scopes now ride the family like `amr` does, and act as a ceiling a `scope` parameter may narrow. Legacy families fall back and are metered on `sso.oidc.refresh.legacy_scope`. | `V48__refresh_token_granted_scopes.sql`, `model/RefreshToken.java`, `service/security/RefreshTokenService.java`, `controller/OidcAuthorizationController.java` |
| F27 | **Logout without `id_token_hint` ends the session (CONF-6.4)** — `resolveUserFromCookie` returned empty unconditionally, so `logoutAll` never ran: cookies cleared while every outstanding token stayed valid. Now parses the platform session cookie, gated on `purpose=access` and a matching tenant claim so neither an MFA-challenge token nor another tenant's session can terminate this one. | `controller/OidcLogoutController.java` |
| F28 | **WebAuthn user verification (CONF-3.2)** — both ceremonies asked `PREFERRED`, which an authenticator may ignore, leaving the "second factor" as mere possession. Enrolment now demands `REQUIRED` and records it per credential; assertions demand it only when *all* of a user's WebAuthn credentials carry it, so grandfathered credentials keep working. Metered on `mfa.webauthn.legacy_uv`. | `V49__webauthn_user_verification.sql`, `model/MfaFactor.java`, `service/mfa/WebAuthnService.java` |
| F29 | **Authenticator cloning detection (CONF-3.3)** — `AssertionResult.isSignatureCounterValid()` was computed by the library and discarded. A counter regression now refuses the assertion, disables the factor and audits `mfa.webauthn.counter_regression`. It is the only cloning evidence that ever reaches us, and it arrives exactly once. | `service/mfa/WebAuthnService.java`, `service/audit/AuditEventTypes.java` |
| F30 | **Revocation actually revokes refresh tokens (CONF-6.3)** — an opaque refresh token failed to parse as a tenant JWT, hit the catch block, logged at debug and returned. RFC 7009 mandates 200 either way, so a relying party ending a session was told it had succeeded. Now falls back to a hash lookup and kills the family, with tenant + client bindings re-checked. `client_secret` made optional so public clients can revoke; `token_type_hint` accepted and ignored per §2.1. | `service/oidc/OidcRevocationService.java`, `controller/OidcIntrospectRevokeController.java` |
| F31 | **Code replay revokes what it produced (CONF-1.2)** — rejecting the replay was the visible half of RFC 6749 §4.1.2; the other half is that a replay proves the code leaked, so the first exchange's tokens are suspect. `V50` links a code to its family; replay revokes it through the same `REQUIRES_NEW` revoker as refresh-reuse detection. | `V50__oauth_code_issued_family.sql`, `service/oidc/OidcAuthorizationService.java`, `controller/OidcAuthorizationController.java` |
| F32 | **UserInfo respects scope and revocation (CONF-6.1)** — returned `email`/`name`/`picture` to any token regardless of consent (OIDC Core §5.4) and skipped the revocation list introspection already consulted. An absent `scope` claim now releases only `sub` rather than reading as "all scopes". | `controller/OidcUserinfoController.java`, `service/oidc/OidcIntrospectionService.java` |
| F33 | **Bearer challenges on 401 (CONF-6.2)** — all six 401 branches returned a bare status; RFC 6750 §3 wants a `WWW-Authenticate` challenge so a client can tell "refresh me" from "re-authenticate me". Descriptions describe the token, never the account, so the endpoint is not an enumeration oracle. | `controller/OidcUserinfoController.java` |
| F34 | **`client_secret_basic` (CONF-4.1, B-OIDC-4)** — the token endpoint accepted only a form body while registration handed clients `client_secret_basic`. Both methods now resolve for token, introspection and revocation; presenting both at once is refused (RFC 6749 §2.3.1). | `service/oidc/ClientCredentials.java` |
| F35 | **Discovery is complete (CONF-4.2)** — advertised neither the `refresh_token` grant nor the registration endpoint. A test now walks every advertised URL against the controller mappings, so the document cannot drift again. | `controller/OidcDiscoveryController.java` |
| F36 | **Registration management (CONF-4.3, B-OIDC-4)** — every registration response carried a `registration_client_uri` that 404'd. `V52` adds a hashed registration access token and the RFC 7592 read/delete endpoints; every failure is the same 403 so client ids cannot be enumerated. | `V52__oidc_registration_access_token.sql` |
| F37 | **RFC 9207 `iss` in the authorization response (CONF-1.4)** — every tenant is a distinct issuer behind one hostname, the shape the mix-up attack targets. | `controller/OidcAuthorizationController.java` |
| F38 | **Persisted WebAuthn ceremony state (CONF-3.1)** — two unbounded per-process maps lost ceremonies across a rolling update and leaked abandoned ones. `V51` rows are single-use and bound to one user and one ceremony type. | `V51__webauthn_ceremony_state.sql`, `service/mfa/WebAuthnService.java` |
| F39 | **`max_age` is bound (CONF-2.1)** — `decide()` passed a literal null into step-up, so an RP asking for a fresh login was answered as if it had not asked. | `controller/OidcAuthorizationController.java` |
| F40 | **`auth_time` (CONF-2.2)** — `V53` records it on the code and refresh family; a refresh replays the original authentication, and an unknown time omits the claim rather than inventing one. | `V53__auth_time.sql` |
| F41 | **`prompt` handling and persisted consent (CONF-2.3)** — `prompt=none` rendered a consent page into a hidden iframe. It now answers `login_required` / `consent_required`; `V54` stores consent keyed by scope set, which also ends re-consent on every login. | `V54__oidc_consent_grants.sql` |
| F42 | **`at_hash` (CONF-2.4)** — binds the ID token to its access token; reserved against tenant custom claims. | `service/oidc/OidcTokenService.java` |
| F43 | **PKCE telemetry (CONF-1.3, B-OIDC-4)** — new clients already require PKCE; code flows without a challenge from older clients are counted on `sso.oidc.pkce.missing`, not refused. Backfill waits on the meter reading zero. | `service/oidc/OidcAuthorizationService.java` |
| F44 | **SAML authentication context tells the truth (CONF-5.1)** — `AuthnContextClassRef` was a hardcoded `PasswordProtectedTransport`, so a security-key login was described as a password. Now derived from the session's `amr`; `V56` pins every SP that predates the change to the legacy value, per the change register, until an admin un-pins it. | `service/saml/SamlIdpService.java`, `V55`, `V56__pin_existing_saml_sps_authn_context.sql` |
| F45 | **SAML session index and session-scoped logout (CONF-5.2)** — no `SessionIndex` was emitted, and the SP-initiated logout endpoint answered `Success` while ending nothing on our side. Access tokens now carry `sid` (the login's refresh family); the `SessionIndex` is derived from it per SP; a LogoutRequest naming a session revokes exactly that family, the JWT filter refuses tokens from an ended session, and a request naming no session ends them all (SAML Core §3.7.3.2). | `service/saml/SamlSloService.java`, `config/JwtAuthenticationFilter.java`, `service/JwtService.java` |
| F46 | **AuthnRequest replay and freshness (CONF-5.3, B-SAML-1(c))** — `V55` added a replay cache, but with no `IssueInstant` check a captured request became replayable again the moment its ID aged out. Requests older than 10 min (+3 min skew) or dated in the future are now refused, retention always outlasts that window, and a concurrent duplicate is refused rather than surfacing as a constraint violation. | `service/saml/SamlIdpService.java`, `service/saml/SamlInboundMessageParser.java` |
| F47 | **Coherent SAML identity (CONF-5.4, B-SAML-3)** — real self-signed X.509 per signing key in both signature `KeyInfo` and metadata; the entityID is canonical regardless of fetch host; assertions *and* logout messages share one per-SP Issuer rule (entityID opt-in). | `service/saml/SamlSigningCertificateService.java`, `service/saml/SamlIdpService.java` |
| F48 | **Metadata states the signing requirement (CONF-5.5, B-SAML-1(d))** — `WantAuthnRequestsSigned` reflects a tenant-level intent, settable via the admin API and portal. | `model/Tenant.java`, `service/TenantService.java` |
| F49 | **Password policy per NIST SP 800-63B (CONF-7.1)** — composition rules off by default, 12-character floor, new passwords screened against Pwned Passwords by k-anonymity (5-character SHA-1 prefix only, egress-guarded, fails open, metered on `sso.password.breach_check`). ADR 0004. | `service/security/PasswordPolicyService.java`, `service/security/PwnedPasswordsScreen.java` |
| F50 | **CSP and Referrer-Policy (CONF-7.2)** — `default-src 'self'` with per-response nonces on every server-rendered inline block, `object-src`/`base-uri 'none'`, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`. The SAML POST form's `onload` handler, which no nonce can cover, is now a nonce'd script. | `config/security/ContentSecurityPolicy.java`, `config/SecurityConfig.java` |
| F51 | **RFC 9457 Problem Details on `/api/**` (CONF-7.3)** — one error contract from the exception handler, the 401 entry point and the 403/415/429 filters; legacy members kept as extensions. | `config/ApiProblem.java`, `config/GlobalExceptionHandler.java` |
| F52 | **Tenant verification page answered 400 in production** — `String.formatted` over CSS containing `100%;` threw, so every emailed ownership-verification link failed. Escaped, and covered by a regression test. | `controller/AuthController.java` |
| F53 | **Hosted reset reported policy failures as an expired link** — and pre-checked a stale 8-character rule. It now shows the policy's reasons; the token survives the failed attempt. | `controller/LoginController.java` |
| F54 | **Admin tenant selector refuses instead of falling back (2026-09-11 incident)** — an admin write aimed at `cwvermaak-tech` landed in the home tenant with a 200: the portal's Tenants page sent no selector, and the backend had a second, unaudited super-admin `X-Tenant-Slug` override that fell back to the home tenant silently. `CrossTenantSelectorFilter` is now the only selector (`X-Tenant-Slug` a legacy alias under the same membership check + audit; 404/403/400 refusals); every admin response names its tenant in `X-WF-Acting-Tenant` and the portal rejects a mismatch; `V57` + `GlobalSuperAdminMembership` keep the global membership equal to the super-admin flags; the Tenants page is row-scoped; OIDC client create/rotate/delete audited. `cross-tenant-admin-spec.md` §11. | `config/tenant/CrossTenantSelectorFilter.java`, `config/JwtAuthenticationFilter.java`, `config/tenant/GlobalSuperAdminMembership.java`, `V57__backfill_global_super_admin_membership.sql`, portal `core/interceptors/tenant.interceptor.ts`, `features/tenants/tenants.component.ts` |
| F55 | **Refresh bound to its tenant; one refresh cookie per tenant (B-TEN-7)** — the base-domain `refresh_token` served every tenant, so the last sign-in anywhere overwrote the rest and an apex refresh rotated another tenant's session (observed 2026-09-11). Sign-in now sets `wf_refresh_<slug>` plus the legacy cookie (kept: the Safe Space proxy reads it by name, and it follows a refresh only when it holds the same session); refresh acts for the tenant the request names, prefers that tenant's cookie, and refuses — without consuming — a family from another tenant (`auth.refresh.tenant_mismatch`). Login, register, forgot-password and resend-verification use the requested tenant, not a leftover session cookie's. Portal refreshes name their session's tenant. | `service/AuthService.java`, `service/security/RefreshTokenService.java`, `config/tenant/TenantResolverFilter.java`, portal `core/session-refresh.ts` |
| F56 | **Request validation enforced; no 500 for a bad body (B-API-2)** — `spring-boot-starter-validation` added, so `@Valid` finally runs (register, public orders, payment gateways); validation failures list every field (`errors`). Missing-field NPEs in email verification, password reset and MFA activation, an unknown WebAuthn challenge, and a failed security-key verification are 400s; hand-built error bodies on `/api/auth/*` are problem documents; a database integrity violation is a 400/409 that names no column. `MalformedInputIntegrationTest` feeds 16 bad-body shapes to 19 endpoints and fails on any 5xx. | `config/GlobalExceptionHandler.java`, `controller/AuthController.java`, `controller/MfaController.java`, `model/dto/RegisterRequestDto.java` |
| F57 | **Self-serve orders and payment webhooks were refused in production** — `SecurityConfig` permits `/api/public/orders/**` and `/api/webhooks/**`, but `AppAuthorizationFilter` still demanded an `x-app-authorization` key neither a browser nor a payment gateway can hold, so every order (silently falling back to an email enquiry) and every gateway webhook got a 403. Both are exempt now; webhooks stay authenticated by their signatures, and orders get their own per-IP rate limit. Found by the F56 suite. | `config/AppAuthorizationFilter.java`, `config/security/RateLimitingFilter.java`, `service/security/RateLimitingService.java` |

---


> **2026-09-08 — conformance programme.** F25–F29 land Sprint 1 of the
> standards-conformance backlog at
> [`../product/standards-conformance-backlog.md`](../product/standards-conformance-backlog.md),
> which reviews the codebase against 55 normative requirements across OAuth 2.0,
> OIDC, SAML 2.0, SCIM 2.0, JOSE, WebAuthn, NIST SP 800-63B and HTTP. Ten of its
> sixteen work items are **not** tracked in this document — that backlog was
> written from a security-review lens, and protocol conformance is a different
> one. Read the two together.
>
> **2026-09-10.** F34–F48 record Sprints 3–5 and the Sprint 5 follow-up, which
> closed acceptance criteria that had shipped untested or unbuilt (replay
> freshness, session-scoped SAML logout, the existing-SP pin). F49–F53 record
> Sprint 6. The standards position these add up to is in
> [`../compliance/standards-conformance.md`](../compliance/standards-conformance.md).

## Open items

Severity key: **Critical / High / Medium / Low**. Each item lists the gap, the
relevant file(s), and the intended remediation.

### Authentication & MFA

**B-MFA-1 · High · TOTP codes are replayable within their validity window. ✅ FIXED (F8).**
`verifyTotp` (and the enrollment-activation path) now use `TotpService.matchingStep`, which
returns the matched ±1-window time-step via a constant-time compare; the step is persisted
in `user_mfa_factors.last_totp_step` and any code whose step is `<=` the last accepted one
is rejected as a replay (RFC 6238). SMS and backup codes were already single-use.
*Residual (Low):* a device whose clock is behind the server can have a valid current code
rejected after a prior future-skewed acceptance — benign, but a possible support signal.

**B-MFA-2 · High · MFA challenge token is reusable for its full 5-minute window. ✅ FIXED (F9).**
Challenge tokens now carry a `jti` (`JwtService.generateMfaChallengeToken`).
`resolveChallenge` rejects a token whose `jti` is recorded in the new
`consumed_mfa_challenge` table, and `MfaService.consumeChallenge` records it once the
second factor is verified (called from `MfaController.verify`), so the token is one-shot;
a `ConsumedMfaChallengeCleanup` job prunes expired rows hourly. *Operational residuals
(Low):* table growth depends on that single in-process scheduler (no DB TTL); and the
single-use check is skipped for tokens without a `jti` — correct for deploy rollover, but
note a rollback to a pre-F9 build re-opens replay. Combined with B-MFA-1,
replaying a challenge token now fails on both the spent-jti and the spent-TOTP-step checks.
*Residual:* the token is still not bound to the client IP/UA captured at password-verify
time — deferred (IP/UA binding risks false rejects on mobile network changes; revisit if
session-fixation hardening is prioritized).

**B-AUTH-1 · Medium · Rate-limit / lockout key on a spoofable `X-Forwarded-For`.**
`config/security/RateLimitingFilter.java`, `service/AuthService.java`. The first XFF token
is trusted without a trusted-proxy boundary, so an attacker spoofing XFF gets a fresh
per-IP bucket (per-user lockout is the backstop). Also in-memory, so it doesn't hold
across GKE replicas. Fix: configure `server.forward-headers-strategy` / a trusted-proxy
hop and derive client IP only from the ingress-set value; move buckets to the
bucket4j-Redis store the code already anticipates.

**B-AUTH-2 · Medium · No bcrypt upgrade-on-login. ✅ FIXED (F17).**
`AuthService.maybeUpgradePassword` runs on a verified login: when
`passwordEncoder.upgradeEncoding(hash)` is true (stored cost < configured 12) it re-encodes
the plaintext at the current strength and saves. Unit-tested with a real cost-4→cost-12
upgrade.

**B-AUTH-3 · Low · Recovery/SMS endpoints unthrottled. ✅ FIXED (F23).**
`forgot-password`, `reset-password`, `resend-verification` and `mfa/sms/send` now share a
dedicated per-IP `RECOVERY` rate-limit bucket (register cadence), closing the email-abuse /
SendGrid-quota / SMS-toll-fraud vectors. Filter routing unit-tested.

**B-AUTH-4 · Low · WebAuthn prod config + user-verification.**
`config/mfa/WebAuthnConfig.java` defaults RP-ID to `localhost` and uses
`userVerification(PREFERRED)`. Verify prod overrides `rp-id=sso.weldforge.org` and real
origins (a wrong RP-ID silently loosens origin binding); consider `REQUIRED` UV for a true
second factor.

**B-AUTH-5 · Low · Self-service MFA reset is password-only, unthrottled.**
`service/mfa/MfaService.java` (`selfReset`). A token+password attacker can strip all
factors. Fix: require a current valid second factor to remove the last factor; rate-limit.

### OAuth2 / OIDC

**B-OIDC-1 · High · Consent-flow CSRF. ✅ FIXED (F7).** `/t/*/oauth2/authorize/decide`
is `permitAll` with global CSRF disabled. The consent form now embeds a signed,
per-render `consent_csrf` token (`JwtService.generateConsentCsrfToken`) bound to the
authenticated user + tenant; `decide()` calls `verifyConsentCsrf` and rejects with
`access_denied` unless the token is validly signed, unexpired, of purpose
`consent_csrf`, and its subject/tenant match the session principal and slug. An attacker
can neither mint such a token (no signing secret) nor read it from the legitimate render
(Same-Origin Policy), so the cross-site auto-submit is blocked.

**B-OIDC-2 · High · `/authorize` returns JSON errors instead of spec redirects. ✅ FIXED (F13).**
`authorize()` now validates `client_id`+`redirect_uri` first; once the `redirect_uri` is
trusted, protocol errors are thrown with a redirect target and `handle()` returns a 302 to
`redirect_uri` carrying `error`/`error_description`/`state` (RFC 6749 §4.1.2.1). Pre-validation
errors (unknown client, unregistered redirect_uri) remain non-redirecting 400s. *Residual
(Low):* `invalid_scope` is still surfaced at consent/code-issue time rather than redirected
at `/authorize` (scope is validated in the service) — see `B-OIDC-4`.

**B-OIDC-3 · Medium · userinfo/introspection don't check `token_type`/audience. ✅ FIXED (F18).**
userinfo now requires `token_type=access` (rejects ID tokens, OIDC Core §5.3.1); introspection
returns `active=false` when the token's `client_id`/`aud` doesn't match the authenticated
caller, so a client can't read another client's token contents (RFC 7662).

**B-OIDC-4 · Medium · redirect_uri validation at registration. ✅ FIXED (F19, partial).**
`OidcClientService.create` now rejects redirect URIs that aren't absolute, carry a fragment,
or use plain `http` to a non-loopback host (RFC 9700 / RFC 8252; https + native custom
schemes allowed). *Still open:* making scope enforcement unconditional (needs backfilling
registered scopes for existing clients first), requiring S256 PKCE for *all* clients,
adding `at_hash` to ID tokens, and reconciling the token-endpoint client-auth methods with
the discovery document.

**B-OIDC-5 · Low · `client_credentials` hardcoded `expires_in: 3600`. ✅ FIXED (F20).**
`issueForClientCredentials` returns the resolved per-tenant TTL and the token endpoint
reports it. *Still open (minor):* prefer `Instant`/UTC over `LocalDateTime`/
`ZoneId.systemDefault()` for authorization-code expiry.

### JWT / crypto / key management

**B-JWT-1 · High · No audience validation on inbound HMAC tokens. ✅ FIXED (F15, WeldForge side).**
Access tokens now carry a platform `aud` (`app.jwt.audience`, default `weldforge`) and
`JwtAuthenticationFilter` requires it — so WeldForge's API only accepts tokens explicitly
minted for it (mfa_challenge / consent_csrf carry no `aud` and are already purpose-gated).
Adding the claim is **transparent to the external consumers** (they ignore it); a 5-min
TTL self-heals the rollover. *Open follow-ups:* (a) **per-consumer audiences** — true
cross-consumer replay segmentation needs each consumer to validate its own `aud`, which is
a coordinated change in the consumer repos (Safe Space / Krusty / Commons), not in-repo;
(b) `iss` validation is still not enforced on inbound HMAC tokens (per-tenant `iss` is only
set on the OIDC mint path).

**B-JWT-2 · High · No key-ring for the shared HMAC.** Rotation is an all-or-nothing
cutover across WeldForge + 3 consumers. Fix: accept N verification keys (newest signs) so
keys can roll with overlap; longer term, migrate consumers to JWKS/RS256 to retire the
shared symmetric secret. See [runbooks/key-rotation.md](../runbooks/key-rotation.md).

**B-JWT-3 · Medium · RP-initiated logout parses `id_token_hint` against only the active
key. ✅ FIXED (F24).** `parseTenantJwt` now resolves the verification key by the token's
`kid` (tenant-scoped), so an `id_token_hint` signed by a recently-rotated key still parses
and logout doesn't silently fail during a rotation window.

**B-JWT-4 · Low · Key lifecycle.** RSA-2048 is the floor (consider ES256 / RSA-3072 for
new tenants); JWKS retains rotated keys forever — prune keys whose newest possibly-signed
token has expired. `app.crypto.secret` derives the AES key via a single SHA-256 rather
than a salted KDF — acceptable once F1 enforces a high-entropy secret, otherwise move to
HKDF.

### SAML IdP

**B-SAML-1 · High · The IdP trusts attacker-controllable request fields. ✅ FIXED (F11, F12, F46, F48).**
`service/saml/SamlIdpService.java`, `controller/SamlIdpController.java`. Three reinforcing
gaps:
- **(a) AuthnRequest signatures are never verified.** ✅ **FIXED (F12)** — per-SP
  `wantAuthnRequestSigned` flag enables XSW-resistant signature verification against the
  SP cert. The flag is now settable through the admin API (`SamlServiceProviderDto`,
  added during the 2026-06 docs pass) — previously it required raw SQL.
- **(d) IdP metadata advertises `WantAuthnRequestsSigned="false"`** while enforcement is
  per-SP (`SamlIdpService.generateMetadata`). ✅ **FIXED (F48)** — tenant-level
  `samlWantAuthnRequestsSigned`, published in metadata; the ordering is in
  `docs/integrations/relying-party-onboarding.md` §3.4.
- **(b) inbound XML was parsed by `indexOf`/substring string-scanning, not a hardened DOM
  parser.** ✅ **FIXED (F11)** via `SamlInboundMessageParser` (XXE-hardened, namespace-aware).
- **(c) no replay / `InResponseTo` correlation.** ✅ **FIXED (F46)** — AuthnRequest IDs
  are single-use and requests must be fresh; the two only work together, since the cache
  is finite.

**B-SAML-2 · Medium · Legacy assertion-encryption crypto. ⚠️ OUTWARD-FACING — deferred.**
`service/saml/SamlAssertionEncrypter.java` uses AES-CBC + RSA-OAEP-MGF1-SHA1. Target is
AES-256-GCM + RSA-OAEP-SHA256. **However** this changes the encrypted-assertion wire format
the downstream SP must decrypt, so flipping it unilaterally could break a tenant's SP login
(same class of risk as `B-JWT-2`). Do it as a **per-SP opt-in** (new `encryptionAlgorithm`
field, default = current CBC for existing SPs, GCM for new) with an algorithm allowlist —
coordinated with the SP, not a silent switch.

**B-SAML-3 · Medium · Signature `KeyInfo` / metadata cert / issuer mismatch. ✅ FIXED (F47).**
`signXml` emitted a bare `<KeyValue>` while metadata advertised an `<X509Certificate>` that
was actually a raw SubjectPublicKeyInfo, and the assertion `Issuer` (`{slug}-idp`) ≠
metadata `entityID`. A real self-signed X.509 per signing key is now in both places, and
the entityID is available as `Issuer` per SP (opt-in, because an SP pinned to the old
value rejects every assertion if it flips unannounced). *Residual:* message build and sign
are still hand-rolled string assembly; migrating to OpenSAML (already on the classpath)
remains worthwhile.

### Multi-tenancy / SCIM / audit

**B-TEN-1 · High · `setAdminRole` is unscoped and off the audited cross-tenant path. ✅ FIXED (F10).**
`AdminService.setAdminRole` now resolves the target via
`findByIdAndTenantId(targetUserId, tenantAccessor.requireTenantId())` — identical to every
other user mutation in the class — so a super-admin can only set admin roles on users in the
tenant they have (audibly, via `X-WF-Tenant`) switched into; a target in another tenant
returns `not found` with no grant and no audit. Verified by `AdminServiceTest` (happy-path,
cross-tenant-hidden, non-super-admin-denied, null-role) and `tenant_isolation.feature`
(positive + negative scenarios).

**B-TEN-2 · Medium · Failed cross-tenant switches aren't audited. ✅ FIXED (F16).**
`CrossTenantSelectorFilter` now emits an `admin.cross_tenant.denied` audit event (outcome
DENIED, with reason `unknown_tenant` / `no_membership`) on both refusal branches, so
cross-tenant probing leaves a trail. Filter unit-tested (success → access; both refusals →
denied).

**B-TEN-3 · Medium · SCIM bulk mis-advertised + error leakage. ✅ FIXED (F21).**
`ServiceProviderConfig` now advertises `bulk: supported=true` with the real
`maxOperations` (from `app.scim.bulk.max-operations`, the same cap `ScimBulkController`
enforces) and a `maxPayloadSize`; bulk sub-operation failures return a generic
`internalError` detail instead of the raw exception message (logged server-side).

**B-TEN-4 · Medium · Membership-write SUPER_ADMIN guard (forward-looking).** When the
deferred phase-4 membership-management API ships, reject per-tenant `SUPER_ADMIN` at write
time (the read-time downgrade in `TenantAccessor.effectiveRole` is currently the only
layer). Spec: `docs/cross-tenant-admin-spec.md` §5.

**B-TEN-5 · Low · Audit log is application-append-only, not tamper-resistant.**
`service/audit/AuditService.java`. For SOC2/ISO, add a per-row HMAC chained on the previous
row's digest, or stream to append-only external storage.

**B-TEN-6 · Low · Doc/behaviour mismatch on auth-metadata endpoints.** CLAUDE.md claims
`/api/auth/tenants/*/{branding,social-providers,saml-providers}` require
`x-app-authorization`, but `AppAuthorizationFilter` exempts all of `/api/auth/**` (these
are anonymous — likely intended for the pre-auth login screen). Reconcile the doc; consider
rate-limiting the anonymous tenant-metadata disclosure. Also rename the unscoped PKI
`findBySerial` to signal its intentional cross-tenant (OCSP) use.

**B-TEN-7 · Medium · One refresh cookie for every tenant under the base domain. ✅ FIXED (F55).**
One cookie name meant one refresh session per browser across all tenants, and an apex
refresh could hand the portal another tenant's session. Refresh cookies are now per tenant
(`wf_refresh_<slug>`), a refresh is bound to the tenant the request names and refuses another
tenant's family without consuming it, and pre-sign-in operations no longer take their tenant
from a leftover session cookie. The legacy `refresh_token` stays for the Safe Space proxy —
retire it only once that proxy reads `wf_refresh_techmetropolis`. Residual: `wf_session` is
still one cookie across tenants, so signing in to tenant B ends tenant A's browser session
for OIDC `/authorize` (a re-login, never a cross-tenant session — JWT tenant binding holds).

### Previously-reported findings not yet remediated (from SECURITY_AUDIT / VALIDATION_REPORT)

**B-LEGACY-1 · Medium · SSRF on webhook + CRM URLs. ✅ FIXED (F14).** A central
`EgressGuard` (`service/security/EgressGuard.java`) validates outbound URLs:
http/https only, host must resolve, and no resolved address may be loopback,
any-local, link-local (incl. `169.254.169.254` metadata), site-local (RFC 1918),
IPv6 ULA (fc00::/7), CGNAT (100.64/10) or multicast. Wired into
`JdkWebhookHttpClient` and `HttpCrmClient` (before the circuit breaker) and into
`WebhookSubscriptionService` create/update (fail-fast at config time).
*Residual (Low):* validation resolves DNS, then the HTTP client resolves again —
a DNS-rebinding (TOCTOU) window remains; pin the validated IP into the request to
close it.

**B-LEGACY-2 · Medium · Stored-XSS input hardening on the `name` field. ✅ FIXED (F22).**
`AuthService.validateDisplayName` rejects display names containing `<`/`>` or control
characters (and over-length) at registration and on profile update — before they reach the
non-escaping SAML-attribute / email-template sinks. Unit-tested. (Angular output-escaping
already mitigated the browser path; this closes the input side.)

**B-LEGACY-3 · Low · `V2__seed_app_clients.sql` still contains plaintext API keys.** The
rows are revoked by `V30`, but the audit asked to redact the migration body; the secret
strings remain in the tree/history. Redact the literals (history rewrite is separate).

**B-LEGACY-4 · Low · Swagger/OpenAPI permitAll in `SecurityConfig`.** Now gated by
`AppAuthorizationFilter` (app-key) rather than the recommended ROLE_ADMIN; move to
role-gating in `SecurityConfig` for defense-in-depth. Also `server_tokens off;` and remove
deprecated `X-XSS-Protection` header in the nginx configmap.

**B-API-2 · Medium · Bean validation is not enforced anywhere. ✅ FIXED (F56).**
The provider is on the classpath and every `@Valid` DTO was audited: `CreateOrderRequest`'s
constraints match what www.weldforge.org sends, `PaymentGatewayDto` has none, and
`RegisterRequestDto` refuses only what used to fail at the database, plus a non-email address.
`MalformedInputIntegrationTest` keeps the anonymous and self-service surface free of 5xx.

### Governance / documentation (delivered alongside this backlog)

- ✅ [threat-model.md](../threat-model.md) — consolidated STRIDE threat model.
- ✅ [runbooks/key-rotation.md](../runbooks/key-rotation.md) — per-secret rotation.
- ✅ [runbooks/incident-response.md](../runbooks/incident-response.md) — severity matrix,
  playbooks, POPIA §22 breach notification.
- ✅ [compliance/privacy-and-data-retention.md](../compliance/privacy-and-data-retention.md)
  — POPIA data inventory, retention, data-subject rights, sub-processors (draft, needs
  legal review).
- ✅ [security/configuration-reference.md](configuration-reference.md) — every
  security-relevant flag/secret, defaults, and the fail-fast rules.
- ✅ [integrations/relying-party-onboarding.md](../integrations/relying-party-onboarding.md)
  — OIDC/SAML/SCIM onboarding incl. enabling signed AuthnRequests + deprovisioning.
- ✅ [runbooks/production-bootstrap.md](../runbooks/production-bootstrap.md) — required
  secrets + first non-dev deploy.
- ◻ **Still needed:** a Mail-send Micrometer counter (`sso.mail.send`) + Prometheus alert
  on failures; backup/DR procedure with RPO/RTO; sync remaining stale facts (LAUNCH.md HN
  template stack version; `weldforge-www/TEAMCITY.md` is obsolete — deploy is GitHub Actions).
