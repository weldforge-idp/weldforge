# WeldForge — Consolidated Threat Model

> **Status:** living document. Review every release (and after any change to the
> auth surface, tenant-resolution, token-signing, or external-consumer
> contract). Last consolidated 2026-06-15.
>
> **Scope:** the `weldforge-auth` Spring Boot backend, the Angular admin portal,
> the per-tenant auth subdomains, and the trust relationships with external
> consumers and relying parties. Marketing site (`weldforge-www`) is in scope
> only where it funnels into the auth surface.
>
> **Companions:**
> [security/hardening-backlog.md](security/hardening-backlog.md) (the canonical
> list of open items — every "open/residual" risk below points at a `B-*` ID
> there), [auth-url-spec.md](auth-url-spec.md) (the authoritative source for the
> phishing / cross-tenant-cookie / CSRF reasoning consolidated here),
> [cross-tenant-admin-spec.md](cross-tenant-admin-spec.md),
> [runbooks/key-rotation.md](runbooks/key-rotation.md),
> [runbooks/incident-response.md](runbooks/incident-response.md), and the
> April-2026 [SECURITY_AUDIT](../SECURITY_AUDIT_2026-04-15.md) /
> [VALIDATION_REPORT](../VALIDATION_REPORT_2026-04-17.md).

This document uses **STRIDE** (Spoofing, Tampering, Repudiation, Information
disclosure, Denial of service, Elevation of privilege) organised by **trust
boundary**, followed by ten concrete attack scenarios with the existing
mitigation (cited to real code/spec) and the residual risk.

---

## 1. System overview & trust boundaries

WeldForge is a multi-tenant SSO/IAM platform: a hand-rolled OIDC/OAuth2 issuer
and SAML 2.0 IdP, per-tenant RS256 signing keys, MFA (TOTP / WebAuthn / SMS /
backup codes), SCIM provisioning, per-tenant PKI, and HMAC-signed audit
webhooks. It runs as one Spring Boot jar + PostgreSQL on GKE Autopilot (GCP
`africa-south1`), public at `https://sso.weldforge.org` with per-tenant
subdomains `https://{slug}.sso.weldforge.org`.

### Trust boundaries

```
                          (TB1) browser ⇄ edge
   End user / browser ───────────────────────────► GKE ingress / nginx
       │  per-tenant subdomain   apex                     │
       │  {slug}.sso…/login      sso…/t/{slug}/oauth2     │ (TB2) edge ⇄ app
       ▼                                                  ▼
   Password managers                          Spring Boot (weldforge-auth)
   (host-keyed)                                 TenantResolverFilter
                                                JwtAuthenticationFilter
                                                CrossTenantSelectorFilter
                                                 │            │        │
        (TB5) RP ⇄ issuer                        │            │        │ (TB3)
   OIDC/SAML relying parties ◄──── tokens/assertions          │        ▼
                                                 │            │   PostgreSQL
        (TB6) consumer ⇄ HMAC                    │            │   (tenant-scoped
   Safe Space / Krusty / Commons ◄── shared HS512 HMAC        │    DAO queries)
                                                 │            │
        (TB7) SCIM client ⇄ app                  │      (TB4) app ⇄ outbound
   Okta / Workday / Entra ──► /scim/v2/**        │      webhooks, CRM, SMTP,
                                                 │      LDAP, SMS  ────►  third
                                                 ▼                        parties
                                  Tenant admins vs platform super-admins
                                          (TB8) admin authority boundary
```

| # | Boundary | What crosses it | Who is trusted on the far side |
|---|----------|-----------------|--------------------------------|
| **TB1** | Browser ⇄ edge | Credentials, session/refresh cookies, OIDC redirects | Untrusted end users; **a malicious tenant operator is a peer on a sibling subdomain** (base-domain cookie scope) |
| **TB2** | Edge (ingress/nginx) ⇄ app | `X-Forwarded-*`, `Host`, `X-Tenant-Slug`, `X-WF-Tenant` | Edge trusted to set `X-Forwarded-*`; app must not trust client-supplied forwarding |
| **TB3** | App ⇄ DB | Tenant-scoped queries | DB trusted; isolation enforced at the DAO by `tenant_id` filtering |
| **TB4** | App ⇄ outbound | Webhook/CRM/SMTP/LDAP/SMS calls to admin-configured URLs | Targets are **tenant-admin-supplied and untrusted** |
| **TB5** | Relying party ⇄ issuer | OIDC tokens, SAML assertions, JWKS, discovery | RPs validate our signatures; we must not over-disclose |
| **TB6** | External consumer ⇄ shared HMAC | HS512 platform tokens for Tech Metropolis (Safe Space / Krusty / Commons) | All consumers share **one** symmetric key — mutual blast radius |
| **TB7** | SCIM client ⇄ app | Bearer-token provisioning of Users/Groups | Authenticated per `app_clients`; tenant-scoped |
| **TB8** | Tenant admin ⇄ platform super-admin | Admin-console reads/writes, cross-tenant switch | Tenant admins confined to their tenant; super-admins cross boundaries explicitly + audited |

### Two distinct token systems (important)

- **Session/access JWT (`wf_session` cookie, `Authorization: Bearer`)** is
  signed with the **platform-wide HMAC** `app.jwt.secret` and verified by
  `JwtService.parse` with `verifyWith(getSigningKey())` — the key is pinned to
  the HMAC `SecretKey`, so algorithm-confusion / RSA-substitution is rejected by
  construction. This is also the key **shared with the external consumers**
  (TB6).
- **OIDC ID/access tokens and SAML assertions** are signed with **per-tenant
  RS256** keys (`OidcTokenService`, `SamlIdpService` via
  `TenantSigningKeyService`); each carries a tenant-scoped `iss` and `kid`. A
  token minted for tenant A cannot verify against tenant B's JWKS.

---

## 2. Assets

| Asset | Why it matters | Where it lives |
|-------|----------------|----------------|
| **Per-tenant RS256 private keys** | Sign OIDC tokens + SAML assertions; compromise = forge identity for that tenant's RPs | `tenant_signing_keys` (encrypted under `app.crypto.secret`) |
| **Shared platform HMAC** (`app.jwt.secret`) | Signs every session JWT **and** is mirrored to all three Tech Metropolis consumers' `WELDFORGE_JWT_SECRET` | GCP Secret Manager `wf-jwt-secret`; **single key, many holders** |
| **Password hashes** | Credential DB | `users.password`, BCrypt cost 12 (`SecurityConfig`) |
| **MFA secrets** | TOTP shared secrets, WebAuthn public keys, backup-code hashes | `mfa_factors`, `backup_codes` (BCrypt-hashed) |
| **Session / access / refresh tokens** | Live authentication material | Cookies (`HttpOnly`, `Secure`, base-domain scope), `refresh_tokens` |
| **Single-use codes** | OIDC auth codes, password-reset / email-verify / tenant-verify tokens | All stored **hashed** (SHA-256/BCrypt), TTL-bound, single-use |
| **Audit logs** | Forensics, lockout/anti-stuffing signal, compliance | `audit_events` (append-only at app layer) |
| **Tenant isolation itself** | The core product guarantee | Enforced by `TenantResolverFilter` + JWT-authoritative binding + DAO `tenant_id` filters |

---

## 3. STRIDE analysis per trust boundary

### TB1 — Browser ⇄ edge (and malicious-sibling-subdomain peer)

| STRIDE | Threat | Primary control |
|--------|--------|-----------------|
| **S** | Phishing tenant impersonation (`acme-bank-secure.sso…`) | Reserved-label allowlist (resolution + creation time), V1 unverified banner, V2a email-control challenge (`auth-url-spec.md`); **open:** V2b/V2c (`B-TEN`/spec roadmap, `M3`) |
| **S** | Stolen tenant-A cookie replayed on tenant-B subdomain | **JWT-authoritative tenant binding** — `JwtAuthenticationFilter` compares JWT `tid`/`tenant` to the *implicit* tenant (host/path, not `X-Tenant-Slug`); mismatch ⇒ runs anonymous |
| **T** | Cross-site request forgery on auth POSTs | `SameSite=Lax` + **JSON-only** `AuthJsonContentTypeFilter` (415 on form-encoded `/api/auth/**`); consent-form CSRF closed — signed per-render `consent_csrf` token required by `decide()` (`B-OIDC-1`, F7) |
| **R** | User denies an action | Per-action audit events (`AuditService`) on login/MFA/reset/profile/OIDC |
| **I** | Tenant existence / branding enumeration | Tenant subdomains `noindex` (`TenantSubdomainNoIndexFilter` + nginx); generic errors |
| **D** | Credential stuffing / brute force | `RateLimitingFilter` (login 10/15m, register 5/60m) + per-user lockout 5/15m; **open:** XFF spoof + in-memory buckets (`B-AUTH-1`) |
| **E** | Header-swap to fake cross-tenant access | JWT is authoritative over the resolver's `X-Tenant-Slug` pick; only `sa=true` JWTs honour the override |

### TB2 — Edge ⇄ app (forwarding headers, host)

| STRIDE | Threat | Control / status |
|--------|--------|------------------|
| **S** | Spoofed `X-Forwarded-For` to evade IP rate-limit / poison audit IP | Tomcat `remoteip` configured; **open:** no trusted-proxy boundary, first XFF hop trusted (`B-AUTH-1`) |
| **S** | Spoofed `Host` to resolve a different tenant | `TenantResolverFilter` validates subdomain against slug regex + base-domain suffix; JWT binding still gates auth |
| **E** | `X-WF-Tenant` / `X-Tenant-Slug` to cross tenants | Cross-tenant switch requires `SUPER_ADMIN` effective role; `CrossTenantSelectorFilter` audits the switch |

### TB3 — App ⇄ DB (tenant isolation)

| STRIDE | Threat | Control / status |
|--------|--------|------------------|
| **E/I** | Horizontal read of another tenant's rows | DAO queries filter by the **resolved** `tenantId` (`findByIdAndTenantId`, `findByTenantId…`); audit's tenant-isolation findings satisfied (`cross-tenant-admin-spec.md` §7) |
| **E** | Admin-role grant in an arbitrary tenant | Closed (F10): `AdminService.setAdminRole` resolves the target via `findByIdAndTenantId` on the audited resolved tenant (`B-TEN-1`). Residual: per-tenant SUPER_ADMIN write-guard for the deferred membership API (`B-TEN-4`) |
| **T** | SQL injection | Parameterised JPA/Hibernate; no string-built SQL on the auth paths |

### TB4 — App ⇄ outbound (webhooks, CRM, SMTP, LDAP, SMS)

| STRIDE | Threat | Control / status |
|--------|--------|------------------|
| **I/E** | SSRF via admin-configured webhook/CRM URL (cloud metadata, RFC-1918) | RBAC gate (TENANT_ADMIN+) only; **open:** no egress denylist — `JdkWebhookHttpClient` does `URI.create(url)` unchecked (`B-LEGACY-1`) |
| **D** | Slow/failing receiver exhausts threads | Resilience4j circuit breaker + retry/dead-letter queue (`WebhookRetryScheduler`) |
| **R** | Tampered webhook payload | HMAC signature header (`WebhookSigner`) so receivers detect tampering |
| **I** | SMS toll-fraud via unthrottled send | **Open:** `mfa/sms/send` not in the rate-limit map (`B-AUTH-3`) |

### TB5 — Relying party ⇄ issuer (OIDC/SAML SPs)

| STRIDE | Threat | Control / status |
|--------|--------|------------------|
| **S** | Forged token accepted by an RP | Per-tenant RS256; RPs validate against tenant JWKS; `iss` matches discovery |
| **T** | SAML assertion forgery / XML Signature Wrapping | Assertion signed (XML-DSig, enveloped, exclusive C14N, SHA-256), encrypt-after-sign; inbound XML now XXE-hardened DOM-parsed (F11) and AuthnRequest signatures verified per-SP via an XSW-resistant validator (`wantAuthnRequestSigned`, F12); **open:** no `InResponseTo`/replay correlation (`B-SAML-1`(c)) |
| **I** | Over-release of user attributes to an SP | Per-SP attribute release policy (`_release` allowlist, SAM-08) |
| **E** | Over-broad OIDC scope | Scope restricted to client's registered list **when non-empty**; **open:** empty-list clients unconstrained (`B-OIDC-4`) |
| **T** | Open redirect via `redirect_uri` / consent deny path | `redirect_uri` checked against the client's registered list at authorize and at `decide` (F2); reset `returnTo` is same-origin validated |

### TB6 — External consumer ⇄ shared HMAC (Tech Metropolis trio)

| STRIDE | Threat | Control / status |
|--------|--------|------------------|
| **S** | Token minted for consumer A replayed against consumer B | Same key verifies all three; **open:** no `aud`/`iss` validation on inbound HMAC tokens (`B-JWT-1`) |
| **E** | Key compromise at any one consumer | **Blast radius = all consumers + WeldForge sessions**; **open:** no HMAC key-ring, rotation is an all-or-nothing cutover (`B-JWT-2`, key-rotation runbook) |

### TB7 — SCIM client ⇄ app

| STRIDE | Threat | Control / status |
|--------|--------|------------------|
| **S** | Forged SCIM bearer | `ScimAuthenticationFilter` authenticates against `app_clients`, tenant-scoped |
| **I** | Capability/error leakage | **Open:** ServiceProviderConfig advertises `bulk` falsely + leaks sub-op exceptions (`B-TEN-3`) |
| **E** | SCIM deactivation race / privilege | Deactivated users fail login with generic error; SCIM writes tenant-scoped |

### TB8 — Tenant admin ⇄ platform super-admin

| STRIDE | Threat | Control / status |
|--------|--------|------------------|
| **E** | Tenant admin self-promotes to verified / super-admin | `updateTenant` cannot set `verifiedAt`; per-tenant `SUPER_ADMIN` downgraded to `TENANT_ADMIN` at read time (`cross-tenant-admin-spec.md` §5) |
| **R** | Cross-tenant action without trace | Successful switch emits `admin.cross_tenant.access`; `setAdminRole` is now tenant-scoped through the audited switch (`B-TEN-1`, F10); **open:** denied switches still unaudited (`B-TEN-2`) |

---

## 4. Key attack scenarios

Each scenario: **Threat → Existing mitigation (cited) → Residual risk**.

### S1 — Phishing / tenant impersonation
- **Threat.** A malicious operator registers `acme-bank-secure`, lifts Acme's
  public branding, and lures Acme users to
  `acme-bank-secure.sso.weldforge.org/login`.
- **Mitigation.** Reserved-label allowlist enforced at **both** resolution time
  (`TenantResolverFilter`) and creation time (`TenantService.requireSlug`),
  covering identity/federation-flavoured labels (`oauth`, `login`, `bank`-class
  handled by roadmap). V1 amber "unverified tenant" banner rendered **outside
  the tenant's branding palette** so it can't be toned down
  (`AuthShellComponent`). V2a email-control challenge proves the operator
  controls `contact_email` before `verified_at` flips
  (`TenantVerificationService`). Subdomains are `noindex`.
  (`docs/auth-url-spec.md` §"Tenant identity-proofing".)
- **Residual risk.** Onboarding-time **trust gating** is unbuilt: V2b domain
  gate and V2c watchword auto-flag (`hardening-backlog.md` §M3 / spec roadmap).
  A free-mail-verified `acme-bank` can still go live. This is the platform's
  largest standing abuse risk.

### S2 — Cross-tenant isolation breach
- **Threat.** A user with a tenant-A session reaches tenant-B's UI/API on B's
  subdomain (the base-domain cookie is sent to every sibling subdomain).
- **Mitigation.** **JWT-authoritative tenant binding** —
  `JwtAuthenticationFilter` recomputes the *implicit* tenant from the host
  subdomain / `/t/{slug}/` path (deliberately **not** the `X-Tenant-Slug`
  header) and refuses to authenticate when the JWT's `tenant`/`tid` doesn't
  match (the request runs anonymous; logged as `jwt_tenant_mismatch`).
  Super-admins are the only exemption, and only via an explicit `sa=true` claim.
  DAO queries are tenant-scoped. (`JwtAuthenticationFilter` lines 116-165;
  `auth-url-spec.md` §"The four mitigations".)
- **Residual risk.** `AdminService.setAdminRole` resolves the target by id with
  no tenant filter and off the audited cross-tenant path (`B-TEN-1`, High). XSS
  inside a tenant's own subdomain stays scoped to that tenant but compromises
  its own users (`auth-url-spec.md` §"Cross-tenant trust model").

### S3 — Token forgery / algorithm confusion
- **Threat.** Attacker submits `alg=none`, or an RS256 token signed with a key
  whose public half is published in JWKS, hoping a verifier treats it as the
  HMAC key (classic RS↔HS confusion).
- **Mitigation.** `JwtService.parse` calls `verifyWith(getSigningKey())` where
  the key is a fixed HMAC `SecretKey` — JJWT rejects any token whose header
  algorithm doesn't match the key type, and rejects `none`. OIDC/SAML tokens
  use per-tenant RS256 with `kid` selection from JWKS. Non-access purposes
  (`mfa_challenge`) are rejected for API auth by the `purpose` claim check.
- **Residual risk.** Low for confusion itself. Open: inbound HMAC tokens carry
  no `aud`/`iss` validation (`B-JWT-1`); RP-initiated logout parses
  `id_token_hint` against only the active key, breaking after rotation
  (`B-JWT-3`).

### S4 — Shared-HMAC blast radius across consumers
- **Threat.** The one `app.jwt.secret` signs WeldForge sessions and is mirrored
  to Safe Space, Krusty, and Commons. A leak anywhere lets an attacker forge
  session tokens for **all** of them; and a token minted for one consumer is
  structurally valid against another.
- **Mitigation.** Secret lives only in GCP Secret Manager (`wf-jwt-secret`),
  injected at deploy, never committed; `SecretHygieneValidator` refuses to boot
  on a known dev/placeholder default when `APP_REQUIRE_SECURE_SECRETS=true`
  (set on all cluster deploys).
- **Residual risk.** **High by design.** No `aud`/`iss` segmentation between
  consumers (`B-JWT-1`) and no key-ring, so rotation is an all-or-nothing
  cutover across four systems (`B-JWT-2`). Strategic fix: migrate consumers to
  per-tenant RS256/JWKS and retire the shared symmetric secret. See
  [runbooks/key-rotation.md](runbooks/key-rotation.md).

### S5 — SAML assertion forgery / XSW
- **Threat.** An attacker forges or wraps a SAML message to log in as another
  user, or tampers an AuthnRequest to redirect the assertion.
- **Mitigation.** Outbound assertions are signed (enveloped XML-DSig, exclusive
  C14N, RSA-SHA256) over the `Assertion` element, with `NotBefore`/
  `NotOnOrAfter`/`AudienceRestriction`/`Recipient` set, and optional
  encrypt-after-sign (`SamlIdpService`). The ACS/Audience/Recipient come from
  **stored SP config**, not from the request, and an authenticated browser
  session is required to issue one.
- **Mitigations added (2026-06).** Inbound AuthnRequest/LogoutRequest are now
  parsed with an XXE-hardened, namespace-aware DOM parser (`SamlInboundMessageParser`,
  F11), closing the string-scan/parser-differential and XXE exposure. AuthnRequest
  signatures are verified per-SP when `wantAuthnRequestSigned` is set, via an
  **XSW-resistant** validator (`SamlSignatureValidator`, F12): single signature,
  enveloped over the root, single reference to the root ID, secure validation.
- **Residual risk.** **Medium (`B-SAML-1`(c)).** No `InResponseTo`/replay
  correlation yet — requests/assertions are not single-use at the SP. Minor:
  the IdP metadata still advertises `WantAuthnRequestsSigned="false"` while
  enforcement is per-SP — a compliant SP reads that and won't sign, so flipping
  `wantAuthnRequestSigned=true` can break that SP's login until it is told to
  sign (`B-SAML-1`(d)). Also `KeyInfo`/metadata-cert/issuer mismatch (`B-SAML-3`)
  and legacy CBC + OAEP-SHA1 encryption (`B-SAML-2`).

### S6 — Consent / CSRF
- **Threat.** A malicious site auto-submits the OIDC consent decision for a
  logged-in user, granting an attacker's client.
- **Mitigation.** `SameSite=Lax` cookies; the JSON-only filter blocks classic
  form-CSRF on `/api/auth/**`; `redirect_uri` is registered-list-validated at
  authorize and `decide` (F2 closed the deny-path open redirect). The consent
  form now carries a signed per-render `consent_csrf` token bound to the
  authenticated user + tenant, which `decide()` requires and validates before
  acting (`JwtService.generateConsentCsrfToken` + `verifyConsentCsrf`, F7) — an
  attacker can neither mint the token nor read it cross-origin.
- **Residual risk.** Low. Consent CSRF is closed (`B-OIDC-1`). Separately,
  `/authorize` still returns errors as JSON rather than spec redirects
  (`B-OIDC-2`) — a conformance gap, not a CSRF hole.

### S7 — MFA bypass / replay
- **Threat.** Replay a captured TOTP within its window, or reuse a leaked MFA
  challenge token; strip factors via self-service.
- **Mitigation.** Backup codes are BCrypt-hashed, single-use, atomically marked
  consumed (`BackupCodeService`). Tenant policy can force enrollment/step-up;
  OIDC step-up enforces `max_age`/`require_mfa` freshness
  (`OidcAuthorizationService.enforceStepUp`). The `mfa_challenge` JWT is purpose-
  scoped so it can't authenticate API calls.
- **Mitigations added (2026-06).** TOTP replay is closed (F8/`B-MFA-1`): the
  accepted time-step is persisted (`user_mfa_factors.last_totp_step`) and any
  step `<=` the last accepted is rejected. Challenge-token reuse is closed
  (F9/`B-MFA-2`): tokens carry a `jti` recorded in `consumed_mfa_challenge` on
  first successful use, so the token is one-shot.
- **Residual risk.** Low. The challenge token is still not IP/UA-bound
  (deferred — `B-MFA-2` note); self-service MFA reset is password-only and
  unthrottled (`B-AUTH-5`); a clock-behind device can have a current code
  rejected after a prior future-skewed acceptance (benign, `B-MFA-1` note).

### S8 — Credential stuffing
- **Threat.** Automated login attempts with breached credential lists.
- **Mitigation.** `RateLimitingFilter` (login 10/15m) + per-user lockout
  (5/15m) that runs **before** the BCrypt compare (no timing oracle), with the
  audit/lockout writes in a `REQUIRES_NEW` transaction so a
  `BadCredentialsException` rollback can't lose them (PR #44 — the previously
  documented consumer-side bug is resolved). Enumeration-resistant: unknown
  user, inactive user, locked account, and bad password all return an identical
  generic error (`AuthService.login`). BCrypt cost 12.
- **Residual risk.** IP buckets key on a spoofable first `X-Forwarded-For` hop
  and are in-memory (don't span GKE replicas) (`B-AUTH-1`). No bcrypt
  upgrade-on-login (`B-AUTH-2`). Per-user lockout is the backstop against the
  XFF-spoof bypass.

### S9 — Open redirect
- **Threat.** Coerce a WeldForge URL (reset link, consent deny, OIDC error) into
  redirecting to an attacker site.
- **Mitigation.** Password-reset `returnTo` is base64url-decoded and accepted
  **only** when same-origin with the tenant subdomain or the apex
  (`PasswordResetService.resolveReturnTo` / `sameOrigin`), gated on the
  per-tenant `returnToCallerEnabled` flag, re-checked at completion. OIDC
  `redirect_uri` is validated against the client's registered list, including
  the consent deny path (F2).
- **Residual risk.** Low. Watch new redirecting endpoints; `B-OIDC-2` (errors
  returned as JSON instead of spec redirects) is a conformance gap rather than
  an open-redirect.

### S10 — SSRF via webhooks
- **Threat.** A tenant admin points a webhook (or CRM provider URL) at
  `http://169.254.169.254/…` (GCP metadata), `127.0.0.1`, or an RFC-1918
  service, using WeldForge as an SSRF pivot inside the VPC.
- **Mitigation.** Creating a webhook/CRM target requires TENANT_ADMIN+
  (RBAC-gated, per `VALIDATION_REPORT_2026-04-17.md`); delivery runs inside a
  circuit breaker with bounded timeouts.
- **Residual risk.** **Open (`B-LEGACY-1`, Medium).** `JdkWebhookHttpClient`
  does `URI.create(url)` with **no** egress allow/deny list, no
  internal-range/metadata-IP block, no scheme restriction, and no
  re-validation across redirects. RBAC is the only barrier. Fix: a central
  egress guard before any outbound HTTP.

---

## 5. Known open risks (cross-reference)

These are **identified but not yet mitigated**. Do **not** re-derive fixes
here — each is owned by [security/hardening-backlog.md](security/hardening-backlog.md):

| Area | Item(s) | Severity |
|------|---------|----------|
| Shared-HMAC: no `aud`/`iss` validation; no key-ring | **B-JWT-1**, **B-JWT-2** | High |
| SAML: no `InResponseTo`/replay correlation (sig verify + XXE parse now done) | **B-SAML-1**(c) | Medium |
| `X-Forwarded-For` trusted from first hop (rate-limit / audit) | **B-AUTH-1** | Medium |
| SSRF denylist on webhook/CRM URLs | **B-LEGACY-1** | Medium |
| OIDC scope enforcement opt-in for empty-list clients | **B-OIDC-4** | Medium |
| `/authorize` error responses not spec-compliant redirects | **B-OIDC-2** | High (conformance) |
| SAML KeyInfo/metadata/issuer mismatch; legacy CBC+OAEP-SHA1 | **B-SAML-3**, **B-SAML-2** | Medium |
| SCIM bulk mis-advertised + error leakage | **B-TEN-3** | Medium |
| Stored-XSS hardening on `name` (SAML/email sinks) | **B-LEGACY-2** | Medium |
| Failed cross-tenant switches unaudited | **B-TEN-2** | Medium |
| Tamper-evident audit log (HMAC chain) | **B-TEN-5** | Low |
| Actuator / Swagger gated only by ingress/app-key, not role | **L1/L2** / **B-LEGACY-4** | Low |

Recently **closed** (now counted as mitigations above, not open): failed-login
audit + lockout in `REQUIRES_NEW` (#44); 400-not-500 input hardening (#43);
identity-proofing V1 (#36) / V2a (#37); secret hygiene boot validator (F1);
OAuth2 consent open-redirect (F2); OAuth2 scope enforcement (F3); constant-time
client-secret compare (F4); JWT clock-skew tolerance (F5); **consent-form CSRF
token (F7); TOTP anti-replay (F8); MFA challenge single-use (F9); `setAdminRole`
tenant-scoping (F10); SAML inbound XXE-hardened parsing (F11); SAML AuthnRequest
signature verification (F12)**. The genuine remaining Highs are now only the
shared-HMAC items (`B-JWT-1`/`B-JWT-2`) and `/authorize` error-redirect
conformance (`B-OIDC-2`).

---

## 6. Assumptions & out of scope

**Assumptions (must hold for the controls above to be valid):**

1. The GKE ingress / nginx edge is the **only** network path to the backend and
   correctly sets `X-Forwarded-*`; the backend is not directly reachable. (If
   violated, `B-AUTH-1` becomes trivially exploitable.)
2. `app.jwt.secret` and `app.crypto.secret` are high-entropy, set via Secret
   Manager, and `APP_REQUIRE_SECURE_SECRETS=true` on every cluster deploy.
3. The wildcard TLS cert for `*.sso.weldforge.org` is valid and HSTS is in
   force, so cookies (`Secure`) and host-based password-manager distinctness
   actually bind. (Per `CLAUDE.md`, wildcard DNS/TLS provisioning is operator
   work — verify before relying on per-tenant URL behaviour in prod.)
4. Tenant operators are **semi-trusted** at most: a paying operator is a peer on
   a sibling subdomain and is treated as a potential adversary to other tenants.
5. RPs validate token signatures, `iss`, `aud`, and (for OIDC) `nonce`; SAML SPs
   validate the assertion signature and audience.
6. External consumers (Tech Metropolis trio) protect their copy of the shared
   HMAC as a production secret.

**Out of scope for this document:**

- GCP/GKE platform security, Cloud SQL hardening, node/OS patching, and IAM on
  the `weldforge` GCP project (infra responsibility).
- Physical/operational security of GCP `africa-south1`.
- The marketing site (`weldforge-www`) except where it funnels into auth.
- Source-code supply-chain / dependency SCA beyond noting it was in the April
  2026 audit scope.
- POPIA/privacy data-handling specifics — see
  [compliance/privacy-and-data-retention.md](compliance/privacy-and-data-retention.md).
- Incident handling procedure — see
  [runbooks/incident-response.md](runbooks/incident-response.md).
- Penetration-test execution: a full independent third-party pentest has **not**
  been completed (only the April 2026 internal passive review + validation).

---

*Memories and specs record what was true when written. Before relying on any
mitigation above, re-verify it against the live code and infrastructure — tenant
binding, signing-key behaviour, and the edge/forwarding configuration in
particular.*
