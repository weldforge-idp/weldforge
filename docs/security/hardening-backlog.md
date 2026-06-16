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

---

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

**B-AUTH-3 · Low · Recovery/SMS endpoints unthrottled.**
`config/security/RateLimitingFilter.java` covers only login/register/mfa-verify. Add
`forgot-password`, `reset-password`, `resend-verification`, and the authenticated
`mfa/sms/send` route (SMS toll-fraud) to the route map.

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

**B-OIDC-3 · Medium · userinfo/introspection don't check `token_type`/audience.**
`controller/OidcUserinfoController.java`, `service/oidc/OidcIntrospectionService.java`.
userinfo accepts any tenant-signed token (an ID token works there); introspection doesn't
restrict `active=true` to the calling client's audience. Fix: require an access token at
userinfo; scope introspection to the authenticated client's `aud`/`client_id`.

**B-OIDC-4 · Medium · Scope enforcement is currently opt-in (clients with an empty scope
list are unconstrained).** Follow-up to F3: backfill registered scopes for all existing
clients, then make enforcement unconditional. Also validate `redirect_uri` at registration
(absolute, no fragment, https-or-loopback for public clients) in
`service/oidc/OidcClientService.java`, and require S256 PKCE for *all* clients per
RFC 9700. Add `at_hash` to ID tokens and reconcile the token-endpoint client-auth methods
with the discovery document (registration defaults to `client_secret_basic` but the token
endpoint only reads `client_secret_post`).

**B-OIDC-5 · Low · `client_credentials` returns a hardcoded `expires_in: 3600`** that can
diverge from the per-tenant TTL; use the resolved TTL. Also prefer `Instant`/UTC over
`LocalDateTime`/`ZoneId.systemDefault()` for code expiry.

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
key.** `controller/OidcLogoutController.java` (`parseTenantJwt`). Logout silently fails for
a token signed by a recently-rotated key. Fix: use the kid-based key locator (as
introspection does).

**B-JWT-4 · Low · Key lifecycle.** RSA-2048 is the floor (consider ES256 / RSA-3072 for
new tenants); JWKS retains rotated keys forever — prune keys whose newest possibly-signed
token has expired. `app.crypto.secret` derives the AES key via a single SHA-256 rather
than a salted KDF — acceptable once F1 enforces a high-entropy secret, otherwise move to
HKDF.

### SAML IdP

**B-SAML-1 · High · The IdP trusts attacker-controllable request fields. ⚠️ MOSTLY FIXED.**
`service/saml/SamlIdpService.java`, `controller/SamlIdpController.java`. Three reinforcing
gaps:
- **(a) AuthnRequest signatures are never verified.** ✅ **FIXED (F12)** — per-SP
  `wantAuthnRequestSigned` flag enables XSW-resistant signature verification against the
  SP cert. The flag is now settable through the admin API (`SamlServiceProviderDto`,
  added during the 2026-06 docs pass) — previously it required raw SQL.
- **(d) IdP metadata advertises `WantAuthnRequestsSigned="false"`** while enforcement is
  per-SP (`SamlIdpService.generateMetadata`). **OPEN (Low).** More than cosmetic: a
  compliant SP reads the metadata and won't sign, so flipping `wantAuthnRequestSigned=true`
  on an SP can break its login until the SP is separately told to sign. Surface a
  tenant-level default or per-SP metadata, and document the ordering in the onboarding guide.
- **(b) inbound XML was parsed by `indexOf`/substring string-scanning, not a hardened DOM
  parser.** ✅ **FIXED (F11)** via `SamlInboundMessageParser` (XXE-hardened, namespace-aware).
- **(c) no replay / `InResponseTo` correlation.** **OPEN** — track issued request IDs /
  treat assertions as single-use at the SP.

Saving grace for the open part: an authenticated browser session is still required and
ACS/Audience/Recipient come from stored SP config, not the request.

**B-SAML-2 · Medium · Legacy assertion-encryption crypto.**
`service/saml/SamlAssertionEncrypter.java` uses AES-CBC + RSA-OAEP-MGF1-SHA1. Prefer
AES-256-GCM + RSA-OAEP-SHA256; keep CBC only as explicit per-SP legacy opt-in. Add an
algorithm allowlist.

**B-SAML-3 · Medium · Signature `KeyInfo` / metadata cert / issuer mismatch.**
`signXml` emits a bare `<KeyValue>` while metadata advertises an `<X509Certificate>` that
is actually a raw SubjectPublicKeyInfo, and the assertion `Issuer` (`{slug}-idp`) ≠
metadata `entityID`. Mint a real self-signed X.509 per signing key, reference it in the
signature `KeyInfo`, and use the metadata entityID as the `Issuer`. Strongly consider
migrating IdP message build/sign to OpenSAML (already on the classpath).

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

**B-TEN-3 · Medium · SCIM ServiceProviderConfig advertises `bulk: supported=false` while
`/Bulk` is live** and leaks raw exception messages. `controller/ScimDiscoveryController.java`,
`controller/ScimBulkController.java`. Advertise bulk truthfully with real
`maxOperations`/`maxPayloadSize` (or disable the controller) and sanitize sub-op errors.

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

**B-LEGACY-2 · Medium · Stored-XSS input hardening on the `name` field.**
`RegisterRequestDto` has no validation; `service/AuthService.java` stores `getName()`
verbatim (Angular output-escaping mitigates, but SAML attributes and email templates are
non-escaping sinks). Add input validation.

**B-LEGACY-3 · Low · `V2__seed_app_clients.sql` still contains plaintext API keys.** The
rows are revoked by `V30`, but the audit asked to redact the migration body; the secret
strings remain in the tree/history. Redact the literals (history rewrite is separate).

**B-LEGACY-4 · Low · Swagger/OpenAPI permitAll in `SecurityConfig`.** Now gated by
`AppAuthorizationFilter` (app-key) rather than the recommended ROLE_ADMIN; move to
role-gating in `SecurityConfig` for defense-in-depth. Also `server_tokens off;` and remove
deprecated `X-XSS-Protection` header in the nginx configmap.

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
