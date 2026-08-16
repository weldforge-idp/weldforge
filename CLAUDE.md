# CLAUDE.md — WeldForge project memory

**Portable project memory for Claude Code.** This file auto-loads the instant the
repo is opened on *any* installation — copied, cloned, or fresh — so everything
below is in context with **zero setup steps**. It is the authoritative,
always-loaded copy of the project memory.

`docs/agent-memory/` holds the same notes as individual files (the on-disk format
the Claude Code memory tool uses); it exists only to re-seed the machine-local
memory tool if wanted — see *Keeping this in sync* at the end. Nothing needs to
be run for the knowledge here to be available.

---

## Project orientation

WeldForge is a multi-tenant SSO / IAM platform — authentication, OIDC, SAML,
SCIM, MFA. Components:

- **`weldforge-auth`** — Spring Boot backend (Java 25, Spring Boot 3.5.8, Lombok,
  Flyway, JPA/Hibernate, JSONB columns).
- **`weldforge-admin-portal`** — Angular admin SPA (zoneless change detection,
  signals, Angular Material M2 theming).
- **`weldforge-www`** — marketing site.
- **`infrastructure/helm/weldforge`** — Helm chart for GKE Autopilot.

See `README.md` and `LAUNCH.md` for the full platform overview.

---

## Tenant consumers — the Tech Metropolis trio  *(reference)*

WeldForge serves several adopter tenants; the most active is
`techmetropolis`. **All three Tech Metropolis customer-facing apps**
share that one tenant for cross-app SSO. The relevant repos live
elsewhere; cross-app architecture is at
`christiaanwvermaak/tech-metropolis-docs`.

| Tech Metropolis component | Repo | Talks to WeldForge how? |
|---|---|---|
| Safe Space backend | `christiaanwvermaak/safe_space_backend` | Legacy JSON proxy (`/api/auth/*` with `X-Tenant-Slug: techmetropolis`); HS512 token verification with shared HMAC. |
| Krusty backend | `christiaanwvermaak/krusty-api` | Same pattern as Safe Space. |
| Commons microservice | `christiaanwvermaak/tech-metropolis-commons-api` | Same — verifies tokens issued for the same tenant. |
| WeldForge tenant | tenant slug **`techmetropolis`** (id 6) | |

The platform-wide HMAC secret (`app.jwt.secret` here) is mirrored to
each consumer's `WELDFORGE_JWT_SECRET` env via GCP Secret Manager
`wf-jwt-secret`. Rotating it requires rotating every consumer at the
same time, since they all verify with the same key.

Known consumer-side bug worth knowing about (out of scope for
weldforge-auth itself but planned): failed-login audit + lockout
counter writes happen inside `AuthService.login`'s `@Transactional`;
the `BadCredentialsException` rolls them back. Result: failed logins
are not audited and account lockout never engages. `REQUIRES_NEW` on
the audit/lockout writes when next touched here.

---

## Infrastructure & production access  *(reference)*

- **GitHub repo:** `weldforge-idp/weldforge` (private). Default branch `main`.
- **Deploy workflow:** `.github/workflows/deploy-gcp.yml` — fires on push to
  `main` whenever `weldforge-auth/**`, `weldforge-admin-portal/**`,
  `infrastructure/helm/weldforge/**`, or the workflow itself changes. A single
  `build-push-deploy` job builds both images, pushes to Artifact Registry, and
  runs `helm upgrade --wait --timeout=10m`. PR merge → ~10 min to live.
- **CI workflow:** `.github/workflows/ci.yml`. The backend job runs
  `./mvnw -B -ntp verify -Dtests.integration=true` — the `-Dtests.integration`
  flag is set **only** in CI; a local `./mvnw clean verify` skips the
  Testcontainers Postgres tests.
- **GCP project:** `weldforge` (region `africa-south1`).
- **Artifact Registry:**
  `africa-south1-docker.pkg.dev/weldforge/images/{weldforge-auth,weldforge-admin-portal}`.
- **GKE cluster:** `weldforge-gke` in `africa-south1`. Get creds:
  `gcloud container clusters get-credentials weldforge-gke --region africa-south1`.
  Context name: `gke_weldforge_africa-south1_weldforge-gke` — pass it explicitly
  with `kubectl --context=...`, because the default context on the dev machine
  can revert to an unrelated cluster.
- **Cloud SQL:** instance `weldforge-db`, database `weldforge`.
- **Public URL:** `https://sso.weldforge.org`. Internal API health:
  `kubectl -n sso exec deploy/sso-api -c sso-api -- curl -s http://localhost:8076/actuator/health`.
  Note `/actuator/**` is **not** exposed through the public ingress — an
  external request to it falls through to the marketing SPA and returns HTML,
  so it's useless as an outside-in liveness check (use a live tenant's OIDC
  discovery instead).
- **`leap` — the live public demo tenant.** Slug `leap` (seeded by
  `V40__add_leap_tenant.sql`); it's the canonical "prove WeldForge is live"
  tenant that `weldforge.org`'s `llms.txt` / `agents.html` self-verify steps
  point at. All of its public protocol endpoints return 200, no auth:
  `https://sso.weldforge.org/t/leap/{.well-known/openid-configuration,oauth2/jwks,saml2/idp/metadata}`.
  Use `leap` (not `demo` — there is no `demo` tenant) for any public
  self-verify / smoke test. The `default` bootstrap tenant also serves these
  now (its legacy signing key was regenerated in `V41`, PR #47, 2026-06-05).
- **Outbound email:** SendGrid SMTP (`smtp.sendgrid.net`); the API key lives in
  GCP Secret Manager as `wf-sendgrid-api-key` and is injected at deploy time —
  never commit it.
- Pre-existing quirk: `/api/auth/tenants/*/{branding,social-providers,saml-providers}`
  are gated by `AppAuthorizationFilter` (require an `x-app-authorization` header).

> Memories record what was true when written — verify cluster names, accounts,
> and branch state against the live repo/infra before relying on them.

---

## GitHub account & pushing  *(user / feedback)*

**Account.** Use `christiaanwvermaak` <christiaan.vermaak@outlook.com> — admin on
the `weldforge-idp` org that owns the private repo. Another `gh`-logged-in
account on the dev machine (`cwvermaak-codeinfinity`) is **not** a member and
gets "Repository not found". `gh` periodically reverts the active account between
shell invocations — re-run `gh auth switch --user christiaanwvermaak` if `gh`
calls fail unexpectedly.

**Pushing.** With multiple `gh` accounts logged in, `gh auth git-credential get`
can return the wrong account's token, so `git push` fails with the misleading
"Repository not found". Reliable workaround:

```
TOKEN=$(gh auth token --user christiaanwvermaak)
git push https://christiaanwvermaak:${TOKEN}@github.com/weldforge-idp/weldforge.git <branch>
```

Do **not** apply `git config --global credential.helper=` overrides — they break
other repos. Setting `credential.https://github.com.username` alone is not
enough.

---

## Deployment pipeline  *(project)*

Deployment runs on **GitHub Actions**, not TeamCity. The user corrected this on
2026-05-10: *"We are no longer using TeamCity. GitHub Actions takes care of
deployment."* Stale references remain in tree (`weldforge-www/TEAMCITY.md`,
comments in `weldforge-www/scripts/deploy.sh`) — do not cite them as
authoritative. Before referencing any deploy mechanism, check
`.github/workflows/` for the live workflow. Cleaning up the stale files is a
separate task the user has not asked for — don't preempt it.

---

## In-flight work / branch state  *(project)*

> These are point-in-time WIP notes — confirm against the live repo before
> acting; branches may since have merged or been discarded.

### PlatformSettings — on a feature branch, not on main
The PlatformSettings + DB-backed-SMTP feature lives on `feature/write-buddy-integration`
at commit `1a321df`, **not merged to `main`**. Files: `PlatformSettings(+Dto,
Repository, Service)`, `PlatformSettingsAdminController`, an early `MailService`,
`V33__platform_settings.sql`, and `platform-settings.service.ts`. Before relying
on any PlatformSettings class, check `git ls-tree HEAD -r | grep PlatformSettings`.

**Migration-version collision (UPDATED 2026-05-23).** The earlier note said V33
was contested between this branch and `feat/host-based-tenant-routing`
(`V33__tenant_hosts.sql`). Neither merged: a third unrelated change landed
`V33__oidc_public_clients_and_origins.sql` on main, and main has since
reached **V40** (`V40__add_leap_tenant.sql`). Both stale-V33 branches now
need to renumber to the next free slot (V41 at time of writing) when revived.
Run `ls weldforge-auth/src/main/resources/db/migration/ | tail -5` before
merging either branch.

### origin/dev is behind main
As of 2026-05-23, `origin/dev` is **61 commits behind `origin/main`** —
the drift has compounded from 1 (2026-05-04) → 25 (2026-05-14) → 61
(2026-05-23) as PRs kept landing on main. Re-check with
`git rev-list --count origin/main ^origin/dev` before quoting the
number. Fast-forward when ready: `git push origin main:dev` (main is
strictly ahead; if branch protection blocks it, open a no-op PR).
**Confirm with the user first** — the drift may be intentional.

### Admin REST tenant-nesting refactor — WIP
Branch `feat/admin-rest-tenant-nesting` at `1ff7451` moves the admin REST surface
from flat `/api/admin/<resource>` to nested `/api/admin/tenants/{tenantId}/<resource>`,
so `tenantId` is an explicit path arg. Backend compiles green; the frontend
`ng build` fails with 5 `TS2554` errors, all in
`weldforge-admin-portal/src/app/features/service-accounts/service-accounts.component.ts`
(`list`, `create`, `rotate`, `update`, `delete` call-sites need `tenantId`).
Source for the id: `TenantPickerService.outgoingTenantId()` — guard for
null/undefined on first paint.

---

## Open work as of 2026-05-23 (for session resumption)  *(project)*

> Project memory decays — re-verify with the listed commands before
> acting. This snapshot was taken at the end of the per-tenant-auth-URL
> + security-hardening + portability session.

### Production state at snapshot time
- **Per-tenant subdomain auth URLs** (the `*.sso.weldforge.org` shape from
  `docs/auth-url-spec.md`): **shipped to code but unreachable in prod**.
  `host demo.sso.weldforge.org` returns NXDOMAIN; apex TLS cert SAN is
  `DNS:sso.weldforge.org` only. No regression — apex still serves login
  via the `default` tenant fallback. The visible loss is per-tenant
  branding on bookmarked legacy URLs.
- **JWT tenant-binding, iss, slug holdback, 415 Content-Type guard,
  noindex, tenant verify/unverify, V2a email verification challenge**:
  all live in prod. Verify: `curl -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'a=b' https://sso.weldforge.org/api/auth/login` → **HTTP 415**.

### Open agenda
1. **Wildcard DNS + TLS** — `*.sso.weldforge.org` A-record + Google
   Certificate Manager wildcard cert. **Pending user**; needs gcloud +
   DNS Admin on `weldforge.org`. Runbook:
   `docs/runbooks/wildcard-tls-setup.md`.
2. **TechMetropolis + WriteBuddy heads-up** — partners not yet notified
   of URL-contract change. **Held** until subdomain URLs resolve (sending
   now would point them at NXDOMAIN). Regenerate drafts from
   `docs/auth-url-spec.md` when ready.
3. **Identity-proofing V2b** — domain gate (`contact_email` domain ⊆
   tenant's OIDC `webOrigins`). Designed in spec, not built.
4. **Identity-proofing V2c** — watchword auto-flag for phishing-prone
   slugs (`bank`, `pay`, `secure`, …). Designed in spec, not built.
5. **Identity-proofing V2d** — positive verified-tenant logo badge.
   Designed in spec, not built.
6. **Prometheus alert on `sso.mail.send` failure counter** — orthogonal
   observability gap from #38: silent SMTP breaks return success to the
   caller. Not built.
7. **SendGrid smoke test on 2026-07-14** — 48h before trial perks expire.
   `curl /api/auth/forgot-password` + check SendGrid Activity Feed.
8. **`origin/dev` sync** — 61 commits behind main (2026-05-23). Confirm
   with user before pushing.

### Things explicitly NOT to do on resume
- **Don't re-send TechMetropolis / WriteBuddy heads-up from cached form.**
  Regenerate from the live `docs/auth-url-spec.md` — the spec has evolved
  since the original drafts.
- **Don't run the wildcard-TLS runbook on the user's behalf.** Needs
  their gcloud + DNS Admin scope; walk them through it if asked.
- **Don't `git push origin main:dev`** without explicit user
  confirmation — `dev` may be intentionally pinned.

---

## Session log 2026-06-08 — shipped + how to resume  *(project)*

> Re-verify with the listed commands before acting. Supersedes specifics in
> the 2026-05-23 snapshot above where they conflict.

### Shipped this session (all merged to `main` unless noted)
- **PR #46** — fixed `weldforge.org`'s agent self-verify. `llms.txt` /
  `agents.html` told agents to curl `/actuator/health` (not public — falls
  through to the marketing SPA → HTML) and `/t/demo/...` (no `demo` tenant →
  404). Repointed at the live **`leap`** tenant (OIDC discovery, JWKS, SAML
  metadata, all 200). Deployed via `deploy-www`. See [[leap demo tenant]] note
  in the infra section.
- **PR #47** — `V41__regenerate_default_tenant_signing_key.sql`. The `default`
  tenant's JWKS + SAML metadata were **500-ing** in prod (legacy
  `tenant_signing_keys` row whose PEM no longer loaded under the current crypto
  secret). Migration deletes `default`'s key rows; the service lazily re-mints a
  clean RS256 key. Verified 200 post-deploy. Migrations now at **V41**.
- **PR #48** — JMeter non-functional test suite at **`perf/jmeter/`**
  (`01-load`, `02-performance-baseline`, `03-spike`, `04-security`, plus
  `run.ps1` / `seed.ps1` / README). Placed at **repo root on purpose** so
  test-only edits don't match the `weldforge-auth/**` trigger in
  `deploy-gcp.yml`. [merge state: confirm with `gh pr view 48`.]

### Resume here: run the NFT suite locally (was blocked on Docker)
- **Blocker:** Docker Desktop is installed but its daemon won't start — **WSL2
  is not installed** (`wsl --status` → not installed). Fix: admin PowerShell
  `wsl --install`, **reboot**, start Docker Desktop, wait for "Engine running".
  (Or switch Docker Desktop to the Hyper-V backend.)
- **Then:** `cd weldforge-auth && docker compose up -d --build` → app on
  `:8076`, Postgres on `:5437`. App boots on all-defaults (the dev
  `app.crypto.secret` + baked `JWT_SECRET` defaults; social OAuth2 is commented
  out in `application.yml`). A local **`.env`** (gitignored) already exists in
  `weldforge-auth/` with a non-empty `JWT_SECRET` (compose has no fallback, so
  an unset var would override the app default with "").
- **Seed + run:** `perf/jmeter/seed.ps1 -Tenant leap`, then
  `perf/jmeter/run.ps1 -Plan 02-performance-baseline` (baseline first). JMeter
  lives at `C:\dev\tools\jmeter`. Tenant is selected by the **`X-Tenant-Slug`**
  header; login body is `{identifier,password}`.
- **Test gotchas:** rate limiting is ON by default (login 10/15min, register
  5/60min) — set `APP_RATE_LIMIT_ENABLED=false` for an auth-throughput
  baseline; BCrypt cost 12 makes real logins ~hundreds of ms by design; lockout
  is 5/15min. SAML metadata (XML signing) is the CPU-heaviest read path.

### Backlog reconciliation (the 2026-05-23 agenda is partly stale)
- **Done:** failed-login audit + lockout in a new transaction (**#44** — the
  old "consumer-side bug planned" note is resolved); 400-not-500 hardening
  (#43); identity-proofing **V1 (#36)** and **V2a (#37)**.
- **Genuinely open to implement:** identity-proofing **V2b** (domain gate),
  **V2c** (watchword auto-flag), **V2d** (verified badge) — all spec'd in
  `docs/auth-url-spec.md` §349-356. And **mail-send instrumentation + alert**:
  the `sso.mail.send` counter **does not exist yet** (grep is empty), so this is
  *instrument the Micrometer counter first*, then add the Prometheus alert —
  closes the silent-account-recovery-failure gap.
- **Stale WIP branches** (each ~1 commit ahead, 40-48 behind `main`):
  `feat/admin-rest-tenant-nesting`, `feat/host-based-tenant-routing`,
  `feat/cross-tenant-membership-api`, `docs/fix-oidc-client-name-field` — rebase
  + migration-renumber or retire. `origin/dev` is now **71 behind** main.
- Architecture note for evaluations: the OIDC/OAuth2 **issuer** + SAML **IdP**
  are hand-rolled (no Spring Authorization Server; `grep` = 0). Crypto
  primitives are library-backed (JJWT, Yubico WebAuthn, samstevens TOTP).

### Uncommitted at session end (not on a branch)
- `CLAUDE.md` + `docs/agent-memory/reference_infra.md` — the `leap`-tenant note
  and this session log (commit these).
- Pre-existing, **not mine**: `weldforge-auth/.idea/*` deletions,
  `weldforge-auth/mvnw`, `weldforge-www/scripts/deploy.sh`. Leave them.

---

## Session log 2026-06-15 — identity review + security hardening pass  *(project)*

> Re-verify with the listed commands before acting. Work landed on branch
> `security/hardening-pass-2026-06` (commit it / open a PR when ready).

A six-domain expert review (OIDC/OAuth2, SAML, token crypto/key-mgmt,
authN/MFA, multi-tenancy/SCIM, docs) produced a prioritized findings set.
The full catalogue — what's fixed and what's open, each with severity +
file refs + remediation — now lives in **`docs/security/hardening-backlog.md`**
(the canonical to-do). Companion governance docs added the same session:
`docs/threat-model.md`, `docs/runbooks/key-rotation.md`,
`docs/runbooks/incident-response.md`,
`docs/compliance/privacy-and-data-retention.md` (POPIA — draft, needs legal
review).

### Shipped this session (code, compiles + 145 BDD / full unit suite green)
- **Secret hygiene** — removed the burned production-shape HMAC default from
  `application.yml`; new `config/security/SecretHygieneValidator` always
  enforces min secret length and, when `APP_REQUIRE_SECURE_SECRETS=true`
  (now set on cluster deploys in `infrastructure/helm/weldforge/values.yaml`),
  refuses to boot on a known dev/placeholder secret. Local dev still boots on
  defaults (flag unset). Prod already injects real secrets via Secret Manager
  → `secretRef`, so removing the default is safe there.
- **OAuth2 consent open-redirect** fixed — `decide()` re-validates
  `redirect_uri` against the client's registered list before any 302.
- **OAuth2 scope enforcement** — requested scopes restricted to the client's
  registered set ∪ standard OIDC scopes; *backward-compatible* (only enforced
  when a client has a non-empty scope list, so live RPs don't break — tighten
  per backlog B-OIDC-4).
- **Constant-time `client_secret`** compare in introspect/revoke; **60s
  clock-skew** on all five JWT verifiers; dead double-parse removed in userinfo.
- **README accuracy** — killed the false "Spring Authorization Server" claim,
  qualified the "independent audit" wording, fixed V34→V41 and Java 21→25.

### Top open items (see backlog for the rest)
SAML IdP (B-SAML-1: AuthnRequest sigs unverified + string-scanned XML + no
replay), consent-form CSRF token (B-OIDC-1), MFA single-use (B-MFA-1 TOTP
replay, B-MFA-2 challenge `jti`), JWT iss/aud + HMAC key-ring (B-JWT-1/2),
`setAdminRole` tenant-scoping (B-TEN-1), `X-Forwarded-For` trust (B-AUTH-1),
SSRF denylist (B-LEGACY-1), V2 plaintext-key redaction (B-LEGACY-3).

### Not done deliberately
Did **not** touch the pre-existing uncommitted working-tree changes
(`weldforge-auth/mvnw`, `weldforge-www/scripts/deploy.sh`,
`config/tenant/PublicHostProperties.java`, `.idea/*` deletions) — not mine.

---

## Operational deadlines

### SendGrid trial perks expire 2026-07-16 — verify, don't downgrade
`weldforge-auth` sends transactional email (password reset, email verification,
tenant identity-proofing challenges from PR #37) via SendGrid SMTP. The API key
lives in GCP Secret Manager as `wf-sendgrid-api-key`.

**Plan state confirmed 2026-05-22 by the account owner.** The SendGrid dashboard
shows **Free** as "Your Current Plan" — the 2026-07-16 date is when SendGrid's
*trial-tier perks* on top of Free expire (extended activity history, etc.), not
a hard plan cliff. After that date the account stays on Free at the standard
100/day limit. **There is no "Downgrade to Free" button to click; the account
is already there.**

**How to apply:**
- Don't try to "downgrade" the account — there's nothing in the SendGrid UI to
  do.
- Hold a calendar reminder for **2026-07-14** (48h before the trial-perks
  expire) to run a smoke test: `curl -X POST https://sso.weldforge.org/api/auth/forgot-password`
  for a throwaway test account, confirm Activity Feed in SendGrid shows
  "Delivered". This catches the case where SendGrid's behaviour around trial
  expiry surprises us.
- If delivery breaks anyway, fail-safe is a support ticket — the Free tier
  includes Ticket Support (per the dashboard's own plan-feature listing).
- The 100/day cap is comfortably above current send volume (single-digit
  emails per day across all tenants), so the cap itself isn't a concern.

**Why this matters even on the benign reading.** `SmtpMailService` logs a
delivery failure but the triggering security operation (password reset, email
verification) still returns success — so if delivery DOES silently break for
any reason (not just plan changes), account recovery breaks for every tenant
without a user-visible signal. The 2026-07-14 smoke test is cheap insurance.

---

## Working guidance & gotchas  *(feedback)*

### Angular zoneless pitfalls
The admin portal runs `provideZonelessChangeDetection()` with signals throughout.
Two patterns have silently broken pages here:

**1. `computed()` over a plain (non-signal) field memoises to its first value
forever.** `computed()` only re-evaluates when a tracked *signal* changes; a
plain object field is not tracked even when `[(ngModel)]` mutates it. Symptom: a
button stays disabled forever, or a guard returns a stale value. Fix: make the
field a `signal(...)`, or make the derived value a plain method (methods
re-evaluate every CD pass). *(Bit us in PR #24 — dead Service Accounts Create
button.)*

**2. A template `t.x!.y` non-null assertion throws at runtime if `x` is undefined,
silently truncating the change-detection pass.** The TS `!` is compile-time only;
at runtime `undefined.y` throws and in zoneless mode aborts CD partway through
the iteration — rows before the throw render, rows after are blank. The "first
row works, rest are empty" pattern is the tell. Fix: initialise the optional
draft eagerly in the data-load callback, or guard with `@if (t.x) { ... }`.
*(Bit us in PR #23.)* When you see "only the first iteration works", check the
DevTools console for a runtime throw before assuming a CD/iteration bug.

### Document auth-form branding in all docs/tutorials
Whenever writing or editing any tutorial, README section, integration guide, or
onboarding runbook for WeldForge, include an explicit *"Customising the login and
password-reset forms"* section. Cover: (1) where to set branding — admin portal
Tenants → Branding subtab, or `PUT /api/admin/tenants/{id}` with a `branding`
JSON; (2) the supported `tenants.branding` keys (`logoUrl`, `primaryColor`,
`primaryDarkColor`, `accentColor`, `bgColor`, `bg2Color`, `textColor`,
`displayFont`, `sansFont`, `tagline`, `eyebrow`, `headline`, `ctaLabel`, etc.)
plus `displayName`; (3) the per-tenant feature toggles (`registrationEnabled`,
`passwordRecoveryEnabled`, `emailVerificationRequired`, `returnToCallerEnabled`);
(4) how the tenant slug enters auth URLs — each tenant lives at
`https://{slug}.sso.weldforge.org/{login,forgot-password,reset-password,register,verify-email}`,
its own subdomain so browser and third-party password managers treat each
tenant as a distinct site (the legacy `?tenant=<slug>` query-param form was
removed — see `docs/auth-url-spec.md`). The path-prefix `/t/{slug}/...` is
reserved for OIDC/SAML deep-link endpoints and stays on the apex host.
Adopters expect the auth forms to feel native to their site — don't leave
readers to discover this.

### Verify operator-asserted infra state before acting on it
When the user answers a yes/no AskUserQuestion about **external infra
state** ("DNS is live", "the cert is provisioned", "the secret is
set") that can be verified independently in seconds with `host` /
`dig` / `openssl` / `curl` / `kubectl` / `gcloud`, **run the
verification before merging anything that depends on the answer** —
even when the user says yes. The user genuinely believes they're
answering truthfully but humans confuse "I'm about to do this" with
"I've already done this", check the wrong staging-vs-prod scope, or
remember a different account.

**Why:** on 2026-05-20, before merging #32 (per-tenant subdomain
auth URLs), I asked: *"Are the wildcard DNS A-record + wildcard TLS
cert live in production?"* User selected **"Yes, proceed"**. Five PRs
later, smoke-test on 2026-05-21 found `host demo.sso.weldforge.org`
returns NXDOMAIN and the apex cert SAN is `sso.weldforge.org` only.
Neither piece of infra was live. No regression (legacy URLs still
worked via apex fallback) but the new URL shape was non-functional
in prod. A 5-second `host` + `openssl s_client` would have caught it.

**How to apply:** for any user yes/no answer about external state
verifiable with a one-liner, just run the one-liner. Don't ask the
user to verify; do it inline. Applies to DNS resolution, TLS cert
SANs, k8s resource presence, GCP resource state, secret-manager
existence, ingress IPs, etc. The exception is attestations that
can't be verified externally (e.g. "I told the team", "the customer
agreed") — there the user's word is the source of truth.

---

## Keeping this portable memory in sync

- **`CLAUDE.md`** (this file) — the authoritative, always-loaded copy. Edit it
  here when project knowledge changes.
- **`docs/agent-memory/`** — verbatim per-note mirror, in the Claude Code memory
  tool's on-disk format. Keep it in step with this file.
- **Machine-local memory store** — `~/.claude/projects/<path-slug>/memory/`. Not
  portable (path-keyed, outside the repo). Optional re-seed from the mirror, run
  from the project root (PowerShell):

  ```powershell
  $slug = (Get-Location).Path -replace '[:\\/]','-'
  $dest = Join-Path $env:USERPROFILE ".claude\projects\$slug\memory"
  New-Item -ItemType Directory -Force $dest | Out-Null
  Copy-Item docs\agent-memory\*.md $dest -Force
  ```

  This step is **optional** — it only re-populates the interactive memory tool.
  The knowledge above is already loaded from this file with no action needed.
