# Standards Conformance — Product Backlog

> **Programme:** `CONF` · **Created:** 2026-09-08 · **Owner:** Product
> **Source:** conformance review of `feat/oidc-native-app-and-amr` at Flyway V47 —
> 55 normative requirements across OAuth 2.0, OpenID Connect, SAML 2.0, SCIM 2.0,
> JOSE, WebAuthn, NIST SP 800-63B and HTTP. Result: 24 met, 17 partial, 12 gaps.
>
> **Companion docs:** [`../security/hardening-backlog.md`](../security/hardening-backlog.md)
> (engineering control register — the `B-*` and `F*` IDs referenced here),
> [`../threat-model.md`](../threat-model.md),
> [`../integrations/relying-party-onboarding.md`](../integrations/relying-party-onboarding.md)
> (the externally-visible contract these stories change).

---

## 1. Why this programme exists

WeldForge is a hand-rolled OIDC issuer and SAML IdP, not Spring Authorization
Server. Every normative rule an off-the-shelf issuer satisfies for free is here a
decision someone made — or didn't. The review found the hard things are right
(algorithm pinning, refresh rotation with family reuse detection, RFC 8252
loopback matching, XSW-resistant SAML parsing, faithful `amr` propagation) and
that the residual risk concentrates in three places:

1. **Grant integrity** — scope widens across a refresh; a replayed code revokes nothing.
2. **The request-parameter boundary** — `max_age`, `prompt` and `auth_time` are unbound,
   so a step-up mechanism that exists in the service layer is unreachable from the wire.
3. **Truthfulness of published metadata** — discovery, dynamic registration and the
   token endpoint disagree about client authentication.

Plus one live production defect that outranks all of the protocol work: WebAuthn
fails on every tenant subdomain because the origin allow-list is exact-match —
and the one-line fix is already written, sitting uncommitted in the working tree
(CONF-3.0).

### Business drivers

| Driver | What it needs |
|---|---|
| Enterprise procurement | A published conformance statement. It is asked for ahead of any certification, and none exists today. |
| OpenID self-certification | Gated on CONF-2.x, CONF-4.x and CONF-6.1 — the test suite exercises exactly those. |
| Reduce support load | Findings 4 and 11 (client-auth and discovery mismatches) surface first as RP integration tickets. |
| Close audit findings | Enterprise buyers increasingly audit password policy against NIST SP 800-63B directly. |

---

## 2. Deployment context — Xneelo / k3s / Flux

> **Revised 2026-09-08** after reviewing `C:\dev\CWVermaak\Tech\infrastructure`.
> The original draft of this plan assumed a GKE deployment blocked by closed
> billing. That is no longer the situation, and four of the four Sprint 0
> impediments have cleared.

**Production migrated off GKE on 2026-08-31** and now runs on the
`cwvermaak.tech` cluster — single-node **k3s** on `tech01.cwvermaak.tech`
(xneelo TruServ, Cape Town, `196.40.100.82`, Xeon E-2334 / 32 GB / 2×894 GB),
reconciled by **Flux** from the separate `infrastructure` GitOps repository.

Verified independently on 2026-09-08, not taken from the manifests:

| Check | Result |
|---|---|
| `sso.weldforge.org` resolves to | `196.40.100.82` (the Xneelo node) |
| `/t/leap/.well-known/openid-configuration` | **HTTP 200**, correct issuer |
| `leap.sso.weldforge.org` | **HTTP 200**, TLS verified |
| Certificate | Let's Encrypt, SAN `sso.weldforge.org` + `*.sso.weldforge.org`, issued 2026-08-31, expires 2026-11-29 |

**Production is up.** The wildcard certificate also retires the per-tenant
`ManagedCertificate` trap that took `leap` down on 2026-07-14 and `intellisuite`
on 2026-07-16 — that failure mode no longer exists.

### Where the deployment now lives

| Concern | Location |
|---|---|
| Flux Kustomization | `infrastructure/clusters/production/weldforge-production.yaml` |
| Manifests | `infrastructure/apps/weldforge/base` + `overlays/production` |
| Database | shared in-cluster PostgreSQL 16, database `weldforge_prod`, role `weldforge_prod` |
| Ingress | Traefik, hostPort 80/443, cert-manager DNS-01 via Cloudflare |
| Secrets | SOPS/age; the age key is in Bitwarden and was verified by actually decrypting |
| Backups | `postgres-backup` CronJob, 02:15 Africa/Johannesburg |
| Staging | `staging.weldforge.org` — independent instance, own database |

### Revised impediments

| # | Impediment | Status | Owner |
|---|---|---|---|
| ~~D1~~ | GCP billing closed | **Resolved** — migrated off GKE 2026-08-31 | — |
| ~~D2~~ | `deploy-gcp.yml` is dispatch-only | **Superseded** — production deploys via Flux, not that workflow. DoD updated in §3. | — |
| ~~D3~~ | GCP project split | **Moot** — but see D5, it left a tail | — |
| ~~D4~~ | No staging environment | **Resolved** — `staging.weldforge.org` is live and independent | — |
| **D5** | **Production images are pinned to a dead registry.** The overlay pins `weldforge-auth:r2` and `weldforge-admin-portal:r1` to `africa-south1-docker.pkg.dev/weldforge-499409/...`, imported into the node's containerd. That project's billing is closed and inside its resource-deletion grace period. Once Artifact Registry is purged those exact tags cannot be re-pulled, and the node's containerd copy becomes the only one in existence. | **Open — urgent** | Eng |
| **D6** | **Single node, no HA.** One bare-metal box serving seven tenants and twelve users, nine of them belonging to another organisation. Node loss is a re-bootstrap, and the Postgres CronJob writes its dump **on the node** — off-box shipping is documented but needs confirming as actually running. | **Open** | Eng |
| **D7** | **Infrastructure docs are stale.** `docs/weldforge-hosting.md` and `docs/app-inventory.md` both still describe production as living on GKE at `34.117.149.97`, with a section headed *"Why production was not moved to this cluster"*. It was moved, eight days later. | **Open — trivial** | Eng |

**D5 is the one to action this week**, independently of this programme: build
both images from the commit production is actually running and push them to
`ghcr.io/weldforge-idp`, which is where staging already pulls from and which is
public. Until that is done there is no recoverable copy of the running artefact.

---

## 3. Estimation and process assumptions

State these openly so the plan can be recalibrated rather than quietly missed.

- **Team:** 1 backend engineer at ~80% allocation, plus admin-portal support for CONF-4.3 and CONF-7.1.
- **Velocity:** ~20 points per two-week sprint. Fibonacci scale.
- **Duration:** six sprints, ~12 weeks, assuming Sprint 0 impediments clear first.
- **Migrations:** next free Flyway slot is **V48**. Reserve in story order; renumber
  if a branch lands first (`ls weldforge-auth/src/main/resources/db/migration/ | tail -3`).
- **Branching:** one branch per epic, one PR per story, squash-merged to `main`.

### Definition of Ready

- Acceptance criteria written as Gherkin against a named existing `.feature` file.
- Files to change identified; Flyway slot reserved if schema changes.
- Outward-facing impact assessed and recorded in §6.

### Definition of Done

- [ ] `./mvnw -B -ntp verify -Dtests.integration=true` green (this flag is CI-only).
- [ ] Unit tests for the new branch logic; BDD scenarios added to the named feature file.
- [ ] Flyway migration applied cleanly against a fresh DB *and* an existing one.
- [ ] Discovery document and `docs/integrations/relying-party-onboarding.md`
      updated if the external contract moved.
- [ ] Corresponding `B-*` item in `hardening-backlog.md` marked fixed with an `F*` row.
- [ ] Image built and pushed to `ghcr.io/weldforge-idp/weldforge-auth` with an
      immutable tag; tag pinned in `infrastructure/apps/weldforge/overlays/staging`.
- [ ] Verified on `staging.weldforge.org` before the production overlay is touched.
- [ ] Production tag bumped in `infrastructure/apps/weldforge/overlays/production`
      and merged — **Flux reconciles within 30 minutes**; `flux get kustomizations`
      to confirm, or `flux reconcile` to force it.
- [ ] Smoke-tested against the `leap` tenant's public endpoints
      (`/t/leap/.well-known/openid-configuration`, `/oauth2/jwks`,
      `/saml2/idp/metadata` — all 200, no auth) **and** a tenant subdomain
      (`leap.sso.weldforge.org`), which the apex check does not cover.

> **Rolling updates are single-pod-overlapping.** Both deployments run
> `replicas: 1` with `maxUnavailable: 0, maxSurge: 1`, so during a rollout two
> pods exist briefly. Any in-process state does not survive that window — see
> CONF-3.1.

---

## 4. Epics

| Epic | Title | Stories | Points | Priority |
|---|---|---|---|---|
| CONF-E1 | Grant integrity | 4 | 26 | Must |
| CONF-E2 | OIDC Core request parameters and session freshness | 4 | 21 | Must |
| CONF-E3 | WebAuthn production readiness | 4 | 18 | Must |
| CONF-E4 | Client authentication and discovery truthfulness | 3 | 15 | Must |
| CONF-E5 | SAML assertion fidelity | 5 | 21 | Should |
| CONF-E6 | Token lifecycle endpoints | 4 | 18 | Must |
| CONF-E7 | Platform security baseline | 4 | 21 | Should |
| CONF-E8 | Conformance evidence and documentation | 4 | 15 | Should |
| | **Total** | **32** | **155** | |

---

## 5. Stories

### CONF-E1 · Grant integrity

Closes review findings 1, 6, 8 and the PKCE half of `B-OIDC-4`.

---

#### CONF-1.1 · A refresh must not widen scope · **8 pts · Must · Sprint 1**

> **As a** relying party's end user
> **I want** a refreshed token to carry only the permissions I actually consented to
> **so that** an application cannot quietly acquire its full registered scope set
> the first time my session renews.

**Problem.** The `refresh_token` branch re-issues with `client.getScopeList()` —
the client's entire registration — rather than the scopes recorded on the grant.
Consenting to `openid email` yields everything the client registered for, silently
and permanently. RFC 6749 §6 says the scope of a refreshed token MUST NOT exceed
what was originally granted. The `scope` request parameter is read into the method
signature but never applied, so a client also cannot deliberately narrow.

**Acceptance criteria** — `refresh_token_rotation.feature`

```gherkin
Scenario: A refreshed token carries the originally granted scopes
  Given a client registered for scopes "openid email profile admin:read"
  And a user completed an authorization code flow granting "openid email"
  When the client exchanges the refresh token
  Then the access token's scope claim is "openid email"
  And the response scope field is "openid email"

Scenario: A client may narrow but not widen on refresh
  Given a refresh token whose grant carries "openid email profile"
  When the client refreshes requesting scope "openid email"
  Then the issued token's scope is "openid email"
  When the client refreshes requesting scope "openid email admin:read"
  Then the response is 400 with error "invalid_scope"

Scenario: A legacy refresh token with no recorded scope falls back safely
  Given a refresh-token family issued before this change
  When the client refreshes it
  Then the issued scopes are the intersection of the client's registration
  And a "sso.oidc.refresh.legacy_scope" counter is incremented
```

**Changes**
- `V48__refresh_token_granted_scopes.sql` — add `granted_scopes TEXT` to `refresh_tokens`.
- `model/RefreshToken.java` — carry the column; propagate across rotation.
- `service/security/RefreshTokenService.java` — persist on `issueNewForClient`, replay on `rotate`.
- `controller/OidcAuthorizationController.java:273` — use the family's scopes, intersected
  with the `scope` parameter when present.

**Risk.** Outward-facing — see §6. Ship behind `app.oidc.enforce-refresh-scope`
defaulting to log-only for one release.

---

#### CONF-1.2 · Code replay revokes what the code produced · **5 pts · Must · Sprint 2**

> **As a** security operator
> **I want** a replayed authorization code to invalidate the tokens minted from it
> **so that** a leaked code cannot leave a live session behind after the theft is detected.

**Problem.** Replay is detected, rejected and audited — the visible half of RFC 6749
§4.1.2. The other half is that a replay proves the code leaked, so the tokens from
the legitimate first exchange should die too. Today an attacker who loses the race
still leaves the victim's tokens live, and the victim gets no signal. The machinery
already exists: `RefreshTokenService` does exactly this for families, and
`RevokedOidcToken` covers access tokens.

**Acceptance criteria** — `oidc_issuer.feature`

```gherkin
Scenario: Replaying a code kills the tokens it already produced
  Given a code exchanged once, yielding an access and a refresh token
  When the same code is presented again
  Then the response is 400 with error "invalid_grant"
  And the refresh-token family issued from that code is revoked
  And the access token is present in the revocation list
  And introspection of that access token returns active=false
  And an "oidc.code.replay_detected" audit event is recorded with outcome DENIED
```

**Changes**
- `V49__oauth_code_issued_tokens.sql` — link the code row to the family it produced.
- `service/oidc/OidcAuthorizationService.java:201` — on replay, call the family
  revoker and blocklist the access token.
- `service/audit/AuditEventTypes.java` — new event type.

---

#### CONF-1.3 · PKCE for every code-flow client · **8 pts · Should · Sprint 4**

> **As a** platform operator
> **I want** PKCE required of confidential clients too
> **so that** WeldForge matches the current OAuth security BCP rather than the 2012 baseline.

**Problem.** RFC 9700 §2.1.1 wants PKCE on every client using the code flow.
`requirePkce` is set true only at public-client registration
(`OidcClientService.java:71`), so a confidential client can still run a bare code flow.

**Acceptance criteria** — `epic_b_step1_oidc_completeness.feature`

```gherkin
Scenario: New confidential clients require PKCE
  When an admin registers a confidential client without specifying requirePkce
  Then the stored client has requirePkce=true

Scenario: Telemetry precedes enforcement for existing clients
  Given an existing confidential client with requirePkce=false
  When it starts an authorization request without a code_challenge
  Then the request succeeds
  And a "sso.oidc.pkce.missing" counter is incremented tagged with the client_id

Scenario: Enforcement once backfilled
  Given the client has been migrated to requirePkce=true
  When it starts an authorization request without a code_challenge
  Then the response redirects with error "invalid_request"
```

**Changes**
- `service/oidc/OidcClientService.java:71` — default true for all new clients.
- New counter so the backfill decision rests on evidence, not hope.
- `V50__backfill_require_pkce.sql` — run only after telemetry shows every live
  client sends a challenge. **Do not bundle with the code change.**

**Risk.** Outward-facing — see §6.

---

#### CONF-1.4 · Issuer identification in the authorization response · **5 pts · Should · Sprint 3**

> **As a** relying party integrating against several WeldForge tenants
> **I want** the authorization response to name the issuer that produced it
> **so that** I can detect a mix-up between two tenants sharing one hostname.

**Problem.** RFC 9207 exists for exactly this shape of deployment — multiple issuers
behind one host. Every tenant is a distinct issuer under `/t/{slug}`, which makes the
mix-up class more reachable here than in a single-issuer deployment. Not implemented,
not advertised, not mentioned anywhere in the repository.

**Acceptance criteria** — `oidc_issuer.feature`

```gherkin
Scenario: The authorization response identifies its issuer
  When a user completes consent for tenant "leap"
  Then the redirect carries iss="https://sso.weldforge.org/t/leap"
  And it also carries the original state value

Scenario: Discovery advertises the capability
  When a client fetches the discovery document for any tenant
  Then authorization_response_iss_parameter_supported is true
```

**Changes**
- `controller/OidcAuthorizationController.java` — append `iss` in `decide()` and in
  the error path of `handle()`.
- `controller/OidcDiscoveryController.java` — advertise the flag.

---

### CONF-E2 · OIDC Core request parameters and session freshness

Closes review finding 2 and the `at_hash`/`auth_time` remainder of `B-OIDC-4`.

---

#### CONF-2.1 · Bind `max_age` so step-up can be requested · **8 pts · Must · Sprint 4**

> **As a** relying party protecting a sensitive operation
> **I want** `max_age` on the authorization request to force re-authentication
> **so that** I can demand a fresh factor before a high-value action.

**Problem.** `enforceStepUp` implements a careful three-way minimum across the
client's `max_authentication_age_s`, the tenant default and a requested `max_age`.
But `authorize()` declares no `max_age` parameter and `decide()` passes literal
`null` into the field. The request-driven half of the feature is unreachable, and an
RP asking for fresh authentication is answered as though it hadn't asked.

**Acceptance criteria** — `mfa_policies.feature`

```gherkin
Scenario: max_age forces a fresh factor
  Given a user whose last MFA factor use was 40 minutes ago
  When a client starts an authorization request with max_age=600
  Then the user is redirected to the MFA challenge
  And a "mfa.stepup.required" audit event records reason "stale_factor"

Scenario: max_age is honoured through the consent round-trip
  Given an authorization request carrying max_age=600
  When the consent form is rendered
  Then max_age is present as a hidden field
  And the value is applied when the code is issued

Scenario: A fresh session passes straight through
  Given a user whose last MFA factor use was 2 minutes ago
  When a client starts an authorization request with max_age=600
  Then an authorization code is issued without a challenge
```

**Changes**
- `controller/OidcAuthorizationController.java:66-77` — bind `max_age`;
  `:203` — pass it instead of `null`; add it to `renderConsent`'s hidden fields.

**Dependency.** CONF-2.2 must ship in the same release — OIDC Core makes `auth_time`
required in the ID token whenever `max_age` was requested.

---

#### CONF-2.2 · `auth_time` in the ID token · **5 pts · Must · Sprint 4**

> **As a** relying party
> **I want** to know when the user actually authenticated
> **so that** I can apply my own freshness policy rather than trusting the request I sent.

**Problem.** `auth_time` is absent. OIDC Core §2 makes it REQUIRED when `max_age` was
requested and RECOMMENDED otherwise. It appears in the repository only as a
parenthetical inside `B-OIDC-4`'s "still open" list, which understates it.

**Acceptance criteria** — `epic_e_tokens.feature`

```gherkin
Scenario: auth_time is present when max_age was requested
  Given an authorization request carrying max_age=600
  When the code is exchanged
  Then the ID token carries an auth_time claim
  And auth_time is not later than iat

Scenario: auth_time survives a refresh
  When the refresh token is exchanged
  Then the new ID token carries the original login's auth_time
```

**Changes**
- `V51__auth_time_on_grant.sql` — record the authenticating login instant on the
  authorization code and the refresh family, alongside the existing `amr` column.
- `service/oidc/OidcTokenService.java` — emit the claim; add `auth_time` to
  `isReservedOidcClaim` so tenant config cannot forge it, matching the `amr` treatment.

---

#### CONF-2.3 · `prompt` parameter handling · **5 pts · Should · Sprint 4**

> **As a** relying party doing a silent session check
> **I want** `prompt=none` to return `interaction_required` rather than a consent page
> **so that** my background token refresh does not hijack the user's browser.

**Problem.** No `prompt` binding. `prompt=none` renders a consent page — the exact
behaviour the parameter exists to prevent.

**Acceptance criteria** — `epic_b_step1_oidc_completeness.feature`

```gherkin
Scenario: prompt=none with no session
  When an unauthenticated request arrives with prompt=none
  Then the redirect carries error "login_required"

Scenario: prompt=none with a session and prior consent
  Given the user has an active session and has previously consented to this client
  When a request arrives with prompt=none
  Then an authorization code is issued with no consent screen

Scenario: prompt=none with a session but no prior consent
  Then the redirect carries error "consent_required"

Scenario: prompt=login forces re-authentication
  Given an active session
  When a request arrives with prompt=login
  Then the user is redirected to the login page
```

**Changes**
- `V52__oidc_client_consent_grants.sql` — persist granted consent per user+client+scope
  set. Required because `prompt=none` cannot be answered without knowing whether
  consent was previously given; today consent is re-rendered every time.
- `controller/OidcAuthorizationController.java` — bind `prompt`; skip the consent
  screen when a matching prior grant exists.

**Note.** This story also removes a usability wart: users currently re-consent on
every single login.

---

#### CONF-2.4 · `at_hash` in the ID token · **3 pts · Could · Sprint 4**

> **As a** relying party
> **I want** the ID token to bind the access token it was issued with
> **so that** I can detect a substituted access token.

**Acceptance criteria** — `epic_e_tokens.feature`

```gherkin
Scenario: at_hash binds the paired access token
  When a code exchange returns an access token and an ID token
  Then the ID token's at_hash equals the base64url of the left-most half
       of the SHA-256 of the access token
```

**Changes** — `service/oidc/OidcTokenService.java`; add `at_hash` to the reserved list.

---

### CONF-E3 · WebAuthn production readiness

Closes review finding 3. **Re-scoped 2026-09-08** after the Xneelo review.

The original draft led with ceremony state, on the basis that the GKE Helm chart
shipped `api.replicas: 2`. The Xneelo manifests run **`replicas: 1`** on a
single node, so that defect is latent rather than live. A different WebAuthn
defect *is* live, and it is a one-line fix already sitting uncommitted in the
working tree — that becomes CONF-3.0 and leads the epic.

---

#### CONF-3.0 · Ship the tenant-subdomain WebAuthn fix · **2 pts · Must · Sprint 1**

> **As a** user of any tenant other than the apex
> **I want** to register and use a security key from my tenant's own login page
> **so that** MFA works where I actually sign in.

**Problem — live in production.** The production overlay sets
`APP_MFA_WEBAUTHN_ORIGINS=https://sso.weldforge.org` as a single exact origin,
with `APP_MFA_WEBAUTHN_RP_ID=sso.weldforge.org`. Yubico's `origins` list is
exact-match with no wildcard syntax, and tenant hosts are created at runtime as
`https://{slug}.sso.weldforge.org`, so they can never be enumerated in config.
Result: WebAuthn succeeds on the apex and fails on every tenant host with an
origin mismatch. The overlay's own comment flags this as a known gap.

**The fix already exists and is not committed.** `WebAuthnConfig.java` in the
working tree adds `.allowOriginSubdomain(true)` with a well-reasoned comment —
twelve added lines, absent from `origin/main` — so the running image
(`weldforge-auth:r2`, built before this) does not have it.

**Acceptance criteria** — `mfa_policies.feature`

```gherkin
Scenario: A security key registers from a tenant subdomain
  Given a tenant "leap" reachable at https://leap.sso.weldforge.org
  When a user starts and completes a WebAuthn registration there
  Then the credential is stored against that user

Scenario: An unrelated origin is still refused
  When a ceremony is completed with origin "https://evil.example.com"
  Then the assertion is rejected
```

**Changes** — commit the working-tree change to
`config/mfa/WebAuthnConfig.java`; rebuild; push to `ghcr.io`; verify on
`staging.weldforge.org` from a tenant subdomain before promoting.

**Note.** Doing this also discharges **D5** for the API image, since it forces a
rebuild and a push to a registry that is not the dead GCP one.

---

#### CONF-3.1 · Persist WebAuthn ceremony state · **8 pts · Should · Sprint 3**

> **As a** platform operator
> **I want** ceremony state to survive a pod restart and a second replica
> **so that** deployments do not break in-flight enrolments and the service can scale.

**Problem — latent, not live.** Pending registrations and assertions live in two
`ConcurrentHashMap`s on the instance that started the ceremony. On the Xneelo
cluster both deployments run `replicas: 1`, so the class javadoc's "fine for
single-node" is currently accurate and most users never hit it.

Two things keep it on the backlog rather than closing it:

1. **Rolling updates already break it.** `maxUnavailable: 0, maxSurge: 1` means
   two pods exist during every rollout, and Traefik will load-balance across
   both — so a ceremony spanning a deploy fails. Flux reconciles every 30
   minutes and each image bump is a rollout.
2. **It is the single blocker on ever running two replicas**, which D6 (no HA,
   one box, another organisation's users) makes a question of when, not if.

The maps are also unbounded and never evicted, so abandoned ceremonies leak
until restart.

**Acceptance criteria** — `mfa_policies.feature`

```gherkin
Scenario: A ceremony survives a rolling update
  Given a WebAuthn registration started against the outgoing pod
  When the completion request is served by the incoming pod
  Then the credential is registered successfully

Scenario: Ceremony state expires
  Given a ceremony started more than 5 minutes ago
  When it is completed
  Then the response is 400 "Unknown or expired WebAuthn registration challenge"
  And the row has been pruned by the cleanup job
```

**Changes**
- `V53__webauthn_ceremony_state.sql` — TTL-bounded table. Follow the existing
  `consumed_mfa_challenge` pattern (`V43`), including its hourly prune job.
- `service/mfa/WebAuthnService.java:41-42` — replace both maps with a repository.
- New scheduled cleanup mirroring `ConsumedMfaChallengeCleanup`.

**Exit criterion worth naming.** When this closes, `replicas: 2` becomes safe —
this is the only in-process state in an otherwise genuinely stateless design.
Say so in the PR, and pair it with a decision on whether to scale, which D6
makes a question of when rather than if.

---

#### CONF-3.2 · Require user verification for second-factor credentials · **5 pts · Should · Sprint 1**

> **As a** security operator
> **I want** a security key used as a second factor to verify the user
> **so that** possession of the key alone is not the whole factor.

**Problem.** `UserVerificationRequirement.PREFERRED` at both
`WebAuthnService.java:57` and `:108`. For a credential whose entire purpose is to be
a *second* factor, this should be `REQUIRED`.

**Acceptance criteria** — `mfa_policies.feature`

```gherkin
Scenario: New enrolments demand user verification
  When a user starts a WebAuthn registration
  Then the creation options request userVerification "required"

Scenario: Existing credentials keep working
  Given a credential enrolled before this change
  When the user authenticates with it
  Then the assertion succeeds
  And an "mfa.webauthn.legacy_uv" counter is incremented
```

**Risk.** Outward-facing — see §6. Apply to new enrolments only; grandfather existing
credentials behind a per-factor flag.

---

#### CONF-3.3 · Detect authenticator cloning · **3 pts · Should · Sprint 1**

> **As a** security operator
> **I want** a signature-counter regression treated as a cloned authenticator
> **so that** a duplicated credential is detected rather than silently accepted.

**Problem.** `AssertionResult.isSignatureCounterValid()` is never consulted. The
counter is read and stored but its validity is discarded.

**Acceptance criteria** — `mfa_policies.feature`

```gherkin
Scenario: A regressed signature counter fails the assertion
  Given a stored credential with signature count 42
  When an assertion arrives reporting signature count 30
  Then authentication fails
  And an "mfa.webauthn.counter_regression" audit event is recorded with outcome DENIED
  And the factor is flagged for review
```

**Changes** — `service/mfa/WebAuthnService.java:128-144`.

---

### CONF-E4 · Client authentication and discovery truthfulness

Closes review findings 4 and 11, and the client-auth remainder of `B-OIDC-4`.

---

#### CONF-4.1 · Support `client_secret_basic` · **5 pts · Must · Sprint 3**

> **As a** relying party using a standard OIDC client library
> **I want** to authenticate with HTTP Basic
> **so that** my library's default configuration works without customisation.

**Problem.** RFC 6749 §2.3.1 says the token endpoint MUST support HTTP Basic. Only
form-encoded credentials are read. Discovery is honest about that — but dynamic
registration defaults an omitted `token_endpoint_auth_method` to
`client_secret_basic` (`OidcRegistrationController.java:71`), then quietly settles
on post and echoes the substitution. A conformant client reads the registration
response, sees Basic, and authenticates in a way the server cannot parse.

**Acceptance criteria** — `oidc_issuer.feature`

```gherkin
Scenario Outline: Both client authentication methods work
  When a confidential client calls the token endpoint using <method>
  Then the exchange succeeds
  Examples: | method | client_secret_basic | client_secret_post |

Scenario: Presenting both is rejected
  When a client supplies credentials in both the header and the body
  Then the response is 400 with error "invalid_request"

Scenario: Discovery advertises both
  Then token_endpoint_auth_methods_supported contains
       "client_secret_basic", "client_secret_post" and "none"
```

**Changes** — extract client-credential resolution into one helper used by the token,
introspection and revocation endpoints; update `OidcDiscoveryController.java:54`.

**Note.** Additive and non-breaking — schedule before CONF-4.3, which depends on it.

---

#### CONF-4.2 · Discovery describes what the server actually does · **3 pts · Must · Sprint 3**

> **As a** relying party
> **I want** the discovery document to list every grant and endpoint the server supports
> **so that** capability detection works, which is the entire point of discovery.

**Problem.** `grant_types_supported` lists `authorization_code` and
`client_credentials`; the token endpoint also implements `refresh_token`
(`:247`). `registration_endpoint` is absent though the RFC 7591 endpoint is live and
`permitAll`. `claims_supported` omits `amr`, `roles` and `picture`, all of which
are minted.

**Acceptance criteria** — `oidc_issuer.feature`

```gherkin
Scenario: Discovery is complete and truthful
  Then grant_types_supported contains "refresh_token"
  And registration_endpoint is present and resolves to the live endpoint
  And claims_supported contains "amr", "roles", "picture" and "auth_time"
  And response_modes_supported is present
  And every advertised endpoint returns a non-404 response
```

**Changes** — `controller/OidcDiscoveryController.java:41-58`. Add a test that walks
every advertised URL, so the document cannot drift again.

---

#### CONF-4.3 · Registration honours the method it advertises · **8 pts · Should · Sprint 3**

> **As a** relying party registering dynamically
> **I want** the registration response to describe credentials that actually work
> **so that** I am not told to use an authentication method the server rejects.

**Problem.** Two halves. The default `token_endpoint_auth_method` becomes real once
CONF-4.1 lands. Separately, `registration_client_uri` is returned to every client but
the RFC 7592 management endpoint behind it does not exist — a 404 waiting to be found.

**Acceptance criteria** — `epic_b_step1_oidc_completeness.feature`

```gherkin
Scenario: The advertised auth method is the one that works
  When a client registers without specifying token_endpoint_auth_method
  Then the response reports "client_secret_basic"
  And authenticating with HTTP Basic succeeds

Scenario: The management URI resolves
  When a client GETs its registration_client_uri with its registration access token
  Then the current client metadata is returned
  When it presents a different client's token
  Then the response is 403
```

**Changes**
- `V54__oidc_registration_access_token.sql`.
- `controller/OidcRegistrationController.java` — issue a registration access token;
  add `GET`/`PUT`/`DELETE` on the management URI, or **stop returning the URI**
  if RFC 7592 is deliberately out of scope. Either is defensible; silence is not.

**Decision needed.** Product to confirm whether open, unauthenticated dynamic
registration remains the intent. It is currently public with no initial access token
and no software statement — a defensible choice for a self-service product, an
abuse vector for an enterprise one.

---

### CONF-E5 · SAML assertion fidelity

Closes review finding 5 and the open remainder of `B-SAML-1` and `B-SAML-3`.

---

#### CONF-5.1 · Report how the user really authenticated · **5 pts · Should · Sprint 5**

> **As a** service provider gating on authentication context
> **I want** the assertion to reflect the factors actually used
> **so that** my authorisation decision is based on something true.

**Problem.** `AuthnContextClassRef` is a string literal —
`PasswordProtectedTransport`, on every assertion (`SamlIdpService.java:403`). A user
who authenticated with a security key is described as having typed a password. The
failure under-reports rather than over-reports, so it is silent. The OIDC side gets
this right via `amr`; the information is available, the SAML builder just never asks.

**Acceptance criteria** — `saml_idp.feature`

```gherkin
Scenario Outline: The authentication context matches the session
  Given a user whose session amr is <amr>
  When an assertion is issued
  Then AuthnContextClassRef is <context>
  Examples:
    | amr    | context                                                          |
    | pwd    | urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport |
    | otp    | urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken              |
    | hwk    | urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract    |

Scenario: An SP may pin the legacy value
  Given an SP with authnContextOverride set
  Then the assertion uses the pinned value
```

**Risk.** Outward-facing — see §6. Follow the `B-SAML-2` precedent: per-SP opt-in
with the current literal as the default for existing SPs.

---

#### CONF-5.2 · Emit `SessionIndex` · **3 pts · Should · Sprint 5**

> **As a** service provider performing single logout
> **I want** a `SessionIndex` on the assertion
> **so that** I can terminate the right session rather than all of them.

**Problem.** No `SessionIndex` is emitted anywhere. `SamlSloService` exists but has
nothing to correlate against, so SLO cannot scope to a session.

**Acceptance criteria** — `saml_idp.feature`

```gherkin
Scenario: Assertions carry a session index
  When an assertion is issued
  Then the AuthnStatement carries a SessionIndex
  And the value is stable for the lifetime of the browser session

Scenario: Logout targets that session
  When a LogoutRequest arrives carrying that SessionIndex
  Then only the matching session is terminated
```

---

#### CONF-5.3 · Reject replayed AuthnRequests · **5 pts · Should · Sprint 5**

> **As a** security operator
> **I want** an AuthnRequest ID to be usable once
> **so that** a captured request cannot be replayed to mint a second assertion.

**Problem.** No replay cache — `B-SAML-1(c)`, still open. Mitigated by requiring an
authenticated browser session and by ACS and audience being config-derived, but
mitigation is not the control.

**Acceptance criteria** — `saml_idp.feature`

```gherkin
Scenario: A request ID is single-use
  Given an AuthnRequest with ID "_abc123" was processed
  When the same ID arrives again within the retention window
  Then it is rejected
  And a "saml.authnrequest.replay" audit event is recorded with outcome DENIED
```

**Changes** — `V55__saml_request_replay.sql` (TTL-bounded, with a prune job, same
pattern as `V43`); `service/saml/SamlIdpService.java`.

---

#### CONF-5.4 · Coherent certificate and issuer identity · **5 pts · Could · Sprint 5**

> **As a** service provider validating an assertion
> **I want** the signature `KeyInfo`, the metadata certificate and the assertion
> `Issuer` to agree
> **so that** standard SAML tooling can validate without manual configuration.

**Problem** (`B-SAML-3`). The signature emits a bare `<KeyValue>`; metadata
advertises an `<X509Certificate>` that is actually a raw SubjectPublicKeyInfo; the
assertion `Issuer` (`{slug}-idp`) differs from the metadata `entityID`. Three
mismatches that each break a different SP implementation.

**Acceptance criteria** — `epic_b_step2_saml_completeness.feature`

```gherkin
Scenario: Signature, metadata and issuer agree
  Then the signature KeyInfo contains an X509Certificate
  And that certificate parses as a valid X.509 certificate
  And it matches the certificate published in IdP metadata
  And the assertion Issuer equals the metadata entityID
```

**Changes** — mint a real self-signed X.509 per signing key in
`TenantSigningKeyService`; reference it in `signXml`; use the metadata `entityID`
as `Issuer`. Consider migrating message build and sign to OpenSAML, already on
the classpath.

**Risk.** Outward-facing — changing `Issuer` breaks SPs pinned to the current value.

---

#### CONF-5.5 · Metadata states the signing requirement · **3 pts · Could · Sprint 5**

> **As a** service provider reading IdP metadata
> **I want** `WantAuthnRequestsSigned` to reflect what the IdP will actually enforce
> **so that** enabling signed requests does not break my login.

**Problem** (`B-SAML-1(d)`). Metadata hardcodes `WantAuthnRequestsSigned="false"`
while enforcement is per-SP. A compliant SP reads the metadata, doesn't sign, and
flipping `wantAuthnRequestSigned=true` breaks its login until the SP is separately
told. More than cosmetic.

**Acceptance criteria** — `saml_idp.feature`

```gherkin
Scenario: Metadata reflects the tenant default
  Given a tenant whose default requires signed AuthnRequests
  Then its IdP metadata advertises WantAuthnRequestsSigned="true"
```

**Changes** — add a tenant-level default; `SamlIdpService.generateMetadata`; document
the ordering (turn on at the SP first, then at WeldForge) in the onboarding guide.

---

### CONF-E6 · Token lifecycle endpoints

Closes review findings 7, 9 and 10.

---

#### CONF-6.1 · UserInfo respects scope and revocation · **5 pts · Must · Sprint 2**

> **As a** user
> **I want** an application to receive only the profile data I consented to share
> **so that** granting sign-in does not also grant my name and photograph.

**Problem.** A token granted only `openid` still receives `email`, `name` and
`picture` (`OidcUserinfoController.java:90-93`) — OIDC Core §5.4 says claims must
correspond to granted scopes. The endpoint also skips the revocation list that
introspection consults, so a revoked access token keeps working here until expiry.

**Acceptance criteria** — `oidc_issuer.feature`

```gherkin
Scenario Outline: Claims follow granted scope
  Given an access token granted <scopes>
  When userinfo is called
  Then the response contains exactly <claims>
  Examples:
    | scopes              | claims                    |
    | openid              | sub                       |
    | openid email        | sub, email                |
    | openid profile      | sub, name, picture        |

Scenario: A revoked token is refused
  Given an access token that has been revoked
  When userinfo is called
  Then the response is 401
```

---

#### CONF-6.2 · Bearer challenges on 401 · **3 pts · Must · Sprint 2**

> **As a** relying party
> **I want** a 401 to tell me whether my token expired or was malformed
> **so that** I refresh instead of forcing the user to log in again.

**Problem.** All six 401 branches in userinfo return a bare status. SCIM advertises
`oauthbearertoken` and does the same. RFC 6750 §3 requires a `WWW-Authenticate`
challenge.

**Acceptance criteria** — `oidc_issuer.feature`

```gherkin
Scenario Outline: 401s carry a challenge
  When <endpoint> is called with <token>
  Then the response is 401
  And WWW-Authenticate contains Bearer with error <error>
  Examples:
    | endpoint | token          | error              |
    | userinfo | (none)         | (no error param)   |
    | userinfo | expired        | invalid_token      |
    | userinfo | an ID token    | invalid_token      |
    | SCIM     | wrong secret   | invalid_token      |
```

---

#### CONF-6.3 · Revocation actually revokes refresh tokens · **5 pts · Must · Sprint 2**

> **As a** relying party ending a user's session
> **I want** revoking a refresh token to work
> **so that** a 200 response means what it says.

**Problem.** A refresh token posted to `/oauth2/revoke` fails to parse as a
tenant-signed JWT, falls into the catch block, logs at debug and returns. The caller
gets the mandated 200 and reasonably concludes the token is dead. It isn't.
`token_type_hint` is unsupported, and `client_secret` is a required parameter, so a
public client cannot revoke anything at all.

**Acceptance criteria** — `epic_e_tokens.feature`

```gherkin
Scenario: Revoking a refresh token kills the family
  When a client revokes a refresh token it was issued
  Then the response is 200
  And the whole family is revoked
  And a later refresh with any token in that family returns invalid_grant

Scenario: A public client may revoke its own token
  Given a public client authenticating with client_id only
  When it revokes its refresh token
  Then the response is 200 and the family is revoked

Scenario: token_type_hint is honoured but not trusted
  When a refresh token is submitted with token_type_hint="access_token"
  Then it is still revoked correctly
```

---

#### CONF-6.4 · Logout ends the session without an `id_token_hint` · **3 pts · Must · Sprint 1**

> **As a** user clicking "sign out"
> **I want** my tokens invalidated, not just my cookies cleared
> **so that** signing out on a shared machine actually signs me out.

**Problem.** `resolveUserFromCookie` iterates the cookies, finds the session cookie,
and returns `Optional.empty()` with a comment deferring the work
(`OidcLogoutController.java:186-197`). With no `id_token_hint`, no user resolves,
`logoutAll` never runs and the token version is never bumped — cookies are cleared
but every outstanding access and refresh token stays valid.

**Acceptance criteria** — `epic_e_tokens.feature`

```gherkin
Scenario: Cookie-only logout still ends the session
  Given an authenticated session with an outstanding refresh token
  When logout is called with no id_token_hint
  Then the user's token version is bumped
  And the refresh token no longer works
  And an "auth.logout.rp_initiated" audit event is recorded
```

**Changes** — parse the session cookie with `JwtService` (already injected in sibling
controllers) and resolve the user from its subject.

---

### CONF-E7 · Platform security baseline

Closes review findings 12 and 13, plus `B-JWT-2`.

---

#### CONF-7.1 · Password policy aligned to NIST SP 800-63B · **8 pts · Should · Sprint 6**

> **As a** user
> **I want** to choose a long passphrase without character-class puzzles
> **so that** I pick something memorable and strong rather than `Password1!`.

**Problem.** 800-63B §5.1.1.2 says verifiers SHALL NOT impose composition rules and
SHALL screen against a breached-password corpus. WeldForge requires uppercase,
lowercase, digit and symbol by default and checks no corpus. Everything else is
right — 10-character floor, 72-byte bcrypt guard, cost-12 with upgrade-on-login.
This is a defaults change, not an architectural one, and enterprise buyers
increasingly audit against 800-63B directly.

**Acceptance criteria** — `password_policy.feature`

```gherkin
Scenario: A long passphrase with no symbols is accepted
  When a user registers with "correct horse battery staple"
  Then registration succeeds

Scenario: A breached password is refused
  When a user registers with a password present in the breach corpus
  Then registration fails with a message naming the reason
  And the password is never transmitted in full to any third party

Scenario: Deployments may re-enable composition rules
  Given app.security.password.require-symbol=true
  Then a password with no symbol is refused
```

**Changes**
- `service/security/PasswordPolicyProperties.java:18-26` — default the four
  composition flags to `false`; raise `minLength` to 12.
- New breach screening via k-anonymity range query, behind `EgressGuard`, failing
  **open** with a logged warning so an outage cannot block all registration.
- `docs/security/configuration-reference.md` — record the rationale.

**Product decision needed.** Confirm relaxing composition rules is acceptable —
it reads as "weaker" to a non-specialist reviewer even though it is current guidance.

---

#### CONF-7.2 · Content-Security-Policy and Referrer-Policy · **5 pts · Should · Sprint 6**

> **As a** security operator
> **I want** a CSP on the server-rendered consent page
> **so that** an injected script cannot read or drive the consent form.

**Problem.** `SecurityConfig` never calls `.headers()`, so Spring Security's defaults
apply (nosniff, frame-deny, HSTS on HTTPS, no-store) but there is no CSP and no
`Referrer-Policy`. The consent screen is hand-built HTML on an authenticated origin
— the one place a CSP earns its keep.

**Acceptance criteria**

```gherkin
Scenario: Security headers are present
  When any response is returned
  Then Content-Security-Policy is present with default-src 'self'
  And Referrer-Policy is "no-referrer"
  And X-Content-Type-Options is "nosniff"

Scenario: The consent page renders under its own policy
  When the consent screen is served
  Then its inline styles carry a per-render nonce matching the CSP
  And the page renders correctly
```

**Changes** — `config/SecurityConfig.java:89-92`; the consent page's inline `<style>`
needs a nonce or extraction to a served stylesheet.

---

#### CONF-7.3 · RFC 9457 Problem Details on `/api/**` · **3 pts · Could · Sprint 6**

> **As a** front-end developer
> **I want** a consistent machine-readable error shape
> **so that** error handling is written once instead of per-endpoint.

**Problem.** Every handler in `GlobalExceptionHandler` hand-rolls a
`Map<String,Object>` when Spring 6 ships `ProblemDetail`. Scope is `/api/**` only —
the OAuth and SCIM endpoints are correct to use their own specified error shapes.

**Acceptance criteria**

```gherkin
Scenario: API errors are Problem Details
  When an /api/** call fails validation
  Then the content type is application/problem+json
  And the body carries type, title, status and detail

Scenario: Protocol endpoints are unchanged
  When an OAuth2 token request fails
  Then the body is still {error, error_description}
  When a SCIM request fails
  Then the body is still a SCIM error response
```

**Risk.** The admin portal parses the current shape — coordinate the frontend change
in the same release.

---

#### CONF-7.4 · Multi-key verification for the shared HMAC · **5 pts · Should · Backlog**

> **As a** platform operator
> **I want** to rotate the shared HMAC secret with an overlap window
> **so that** rotation is not a synchronised outage across four codebases.

**Problem** (`B-JWT-2`). One key, no ring. Rotation is an all-or-nothing cutover
across WeldForge and the three Tech Metropolis consumers (Safe Space, Krusty,
Commons).

**Not scheduled.** WeldForge's half is small; the value only arrives once the
consumer repositories accept N-key verification too, which is coordination work
outside this repository. Schedule when that conversation happens. Longer term,
migrate consumers to JWKS/RS256 and retire the symmetric secret entirely.

---

### CONF-E8 · Conformance evidence and documentation

---

#### CONF-8.1 · Publish the conformance statement · **5 pts · Should · Sprint 6**

> **As** enterprise procurement
> **I want** a document stating which profiles WeldForge implements and to what degree
> **so that** I can complete a security questionnaire without a discovery call.

**Problem.** Nothing in the tree says this. For enterprise procurement that document
is usually the first thing asked for, ahead of any certification.

**Acceptance criteria**
- `docs/compliance/standards-conformance.md` exists, listing each standard with
  status, scope notes and known deviations.
- Linked from `README.md` and `docs/integrations/relying-party-onboarding.md`.
- Regenerated at the close of each sprint in this programme.

---

#### CONF-8.2 · Record out-of-scope standards as decisions · **3 pts · Should · Sprint 6**

> **As** a future maintainer
> **I want** to know a standard was considered and declined
> **so that** I do not re-litigate it or assume it was overlooked.

**Problem.** Four standards appear nowhere in the repository: RFC 9068 (JWT
access-token profile), RFC 9207 (issuer identification — now CONF-1.4), RFC 7592
(registration management, though its URI is returned to clients) and NIST SP 800-63B.
The first three are legitimate scope decisions; they should be recorded as decisions
rather than absences.

**Acceptance criteria** — one short ADR per standard under `docs/adr/`, each naming
the standard, the decision, the reasoning and the conditions that would reverse it.

---

#### CONF-8.3 · OpenID self-certification dry run · **5 pts · Could · Backlog**

> **As** the product owner
> **I want** to know how far we are from Basic OP certification
> **so that** I can decide whether to pursue the badge.

**Blocked on** CONF-2.1, 2.2, 2.3, 4.1, 4.2 and 6.1 — the conformance suite exercises
exactly those. **Do not make any certification claim until they close.**

**Acceptance criteria** — the OpenID Foundation Basic OP profile suite runs against a
staging tenant; results committed to `docs/compliance/`; remaining failures either
fixed or recorded as ADRs.

---

#### CONF-8.4 · Update the relying-party onboarding guide · **2 pts · Must · Sprint 6**

> **As a** relying party integrating today
> **I want** the onboarding guide to match the server
> **so that** I do not build against documentation that has moved.

**Acceptance criteria** — §2.3 reflects the new PKCE default; §2.5 documents refresh
revocation and `token_type_hint`; a new §2.7 covers `max_age`, `prompt` and
`auth_time`; §3.4 documents the signed-AuthnRequest ordering from CONF-5.5. Every
code sample re-verified against the running `leap` tenant.

---

## 6. Outward-facing change register

Six stories change behaviour relying parties depend on. The repository already has
the right precedent for this — `B-JWT-2` and `B-SAML-2` were both deferred rather
than flipped unilaterally. Apply the same discipline.

| Story | Who it can break | Mitigation | Notice |
|---|---|---|---|
| CONF-1.1 | RPs that came to rely on the widened scope set | `app.oidc.enforce-refresh-scope` — log-only for one release, with a counter on the delta, then enforce | 30 days |
| CONF-1.3 | Confidential clients not sending a `code_challenge` | Telemetry first; backfill migration only once the counter reads zero | 30 days |
| CONF-3.2 | Authenticators without user-verification capability | New enrolments only; grandfather existing credentials | Release note |
| CONF-5.1 | SPs gating on the literal `PasswordProtectedTransport` | Per-SP opt-in, current value the default for existing SPs | 30 days |
| CONF-5.4 | SPs pinned to the current `Issuer` value | Per-SP opt-in; coordinate individually | 60 days |
| CONF-7.3 | The admin portal's error handling | Ship the frontend change in the same release | Internal |

**Affected parties.** The Tech Metropolis trio (Safe Space, Krusty, Commons) all share
the `techmetropolis` tenant, plus the `leap`, `default` and `intellisuite` tenants.
Regenerate any partner communication from the live specs — do not reuse cached drafts.

---

## 7. Sprint plan

Revised 2026-09-08 for the Xneelo deployment. CONF-3.0 is new and leads;
CONF-3.1 moves to Sprint 3 now that `replicas: 1` makes it latent rather than live.

| Sprint | Theme | Stories | Points |
|---|---|---|---|
| **1** ✅ | Fix what is broken in production — **delivered 2026-09-08** | 3.0, 3.2, 3.3, 1.1, 6.4 | 21 |
| **2** | Grant integrity and token lifecycle | 1.2, 6.1, 6.2, 6.3 | 18 |
| **3** | Interoperability truthfulness | 4.1, 4.2, 4.3, 1.4, 3.1 | 29 |
| **4** | OIDC Core request parameters | 2.1, 2.2, 2.3, 2.4, 1.3 | 29 |
| **5** | SAML assertion fidelity | 5.1, 5.2, 5.3, 5.4, 5.5 | 21 |
| **6** | Baseline and evidence | 7.1, 7.2, 7.3, 8.1, 8.2, 8.4 | 26 |
| — | Backlog, not scheduled | 7.4, 8.3 | 10 |

Sprint 1 now lands on the velocity assumption. Sprints 3, 4 and 6 run over and
will need trimming at planning — CONF-2.4, CONF-7.3 and CONF-5.5 are the natural
drop candidates, all rated `Could`. CONF-3.1 can also slip to Sprint 4 if the
decision on `replicas: 2` (see D6) is deferred.

### Sprint 1 — delivered 2026-09-08

All five stories are on `feat/oidc-native-app-and-amr`, each its own commit,
recorded as F25–F29 in [`../security/hardening-backlog.md`](../security/hardening-backlog.md).
`./mvnw -B -ntp verify -Dtests.integration=true` → **547 tests, 0 failures,
0 errors, 0 skipped**, including all 153 BDD scenarios and the Testcontainers
integration run, so migrations V48 and V49 applied cleanly against a fresh
database.

| Story | Commit | What changed |
|---|---|---|
| CONF-3.0 | `4a54051` | `allowOriginSubdomain(true)` — WebAuthn now works on tenant subdomains |
| CONF-6.4 | `7a3e190` | Logout without `id_token_hint` bumps the token version |
| CONF-1.1 | `07cffb0` | V48 + granted scopes carried on the refresh family |
| CONF-3.2 / 3.3 | `dafe583` | V49 + UV required at enrolment, cloning detection |

**Still to do before this reaches users:** build both images from this branch,
push to `ghcr.io/weldforge-idp`, verify on `staging.weldforge.org` **from a
tenant subdomain** (the apex check does not exercise CONF-3.0), then bump the
production overlay. That last step also discharges **D5** for the API image.

### Sprint goals

**Sprint 1 — "MFA works where people actually sign in, and sign-out signs you out."**
The only sprint whose value is visible to end users, and it opens with a two-point
fix that is already written and uncommitted. Exits when a security key can be
enrolled from a tenant subdomain on production and a cookie-only logout
invalidates tokens.

**Sprint 2 — "A token carries only what was granted, and revocation revokes."**
Closes the grant-integrity gaps. Exits when a replayed code kills its own tokens and
UserInfo respects scope.

**Sprint 3 — "What we publish is what we do."**
The lowest-risk, highest-support-value sprint on the protocol side. Exits when a
stock OIDC client library integrates with no custom configuration, and when
WebAuthn ceremonies survive a rolling update — which is what unblocks `replicas: 2`.

**Sprint 4 — "Relying parties can ask for a fresh login."**
Makes the step-up machinery reachable. Also lands persisted consent, which removes
the re-consent-every-login wart. Exits when `max_age` and `prompt` behave per spec.

**Sprint 5 — "SAML assertions tell the truth."**
Exits when the authentication context reflects the real factors and a request ID
cannot be replayed.

**Sprint 6 — "We can answer the questionnaire."**
Exits when `docs/compliance/standards-conformance.md` is published and the onboarding
guide matches the server.

---

## 8. Traceability

| Review finding | Story | `hardening-backlog.md` |
|---|---|---|
| 1 · Refresh widens scope | CONF-1.1 | *new* |
| 2 · Step-up unreachable | CONF-2.1, 2.2, 2.3 | *new* |
| 3 · WebAuthn per-process state | CONF-3.1, 3.2, 3.3 | *new* |
| — · WebAuthn tenant-subdomain origin | CONF-3.0 | *new — live in prod* |
| 4 · Client-auth disagreement | CONF-4.1, 4.3 | `B-OIDC-4` |
| 5 · SAML authn context | CONF-5.1, 5.2 | *new* |
| 6 · Code replay revokes nothing | CONF-1.2 | *new* |
| 7 · UserInfo scope and 401s | CONF-6.1, 6.2 | `B-OIDC-3` (partial) |
| 8 · PKCE and RFC 9207 | CONF-1.3, 1.4 | `B-OIDC-4` |
| 9 · Refresh revocation | CONF-6.3 | *new* |
| 10 · Logout without hint | CONF-6.4 | *new* |
| 11 · Discovery under-reports | CONF-4.2 | *new* |
| 12 · Password policy | CONF-7.1 | *new* |
| 13 · CSP and Problem Details | CONF-7.2, 7.3 | *new* |
| — · SAML replay | CONF-5.3 | `B-SAML-1(c)` |
| — · SAML KeyInfo/entityID | CONF-5.4 | `B-SAML-3` |
| — · Metadata signing flag | CONF-5.5 | `B-SAML-1(d)` |
| — · HMAC key-ring | CONF-7.4 | `B-JWT-2` |

**Eleven of the seventeen work items are new** — not previously tracked in
`hardening-backlog.md`. That backlog was written from a security-review lens; this
programme adds the protocol-conformance lens, and they overlap less than expected.

---

## 9. Not in scope

Recorded so the omissions read as decisions.

- **Migrating to Spring Authorization Server.** It would deliver CONF-2.x, 4.x and
  1.4 for free, along with JAR and PAR — but means rebuilding per-tenant issuers,
  per-tenant signing keys and the tenant-scoped consent flow on an abstraction that
  assumes one issuer per application. The current design is a defensible answer to an
  awkward multi-tenancy requirement. Revisit if the conformance surface starts
  regressing between releases.
- **RFC 9068 JWT access-token profile.** Access tokens are JWTs but not RFC 9068 JWTs
  (no `typ: at+jwt`, `aud` is the `client_id`, no `jti`). Never claimed, and changing
  `aud` semantics would break every current resource server. ADR under CONF-8.2.
- **FAPI 2.0.** No financial-grade requirement today. Would need mTLS or DPoP sender
  constraining, PAR and JARM.
- **Back-channel and front-channel OIDC logout.** Neither advertised nor implemented.
  Genuine gap for enterprise SSO; separate epic once RP-initiated logout is correct
  (CONF-6.4).
- **SCIM `ETag` concurrency.** Declared `etag.supported: false` — honestly unsupported,
  which is the correct way to skip an optional feature.
