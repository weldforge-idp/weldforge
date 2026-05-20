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
  `kubectl -n sso exec deploy/sso-api -c sso-api -- curl -s http://localhost:8080/actuator/health`.
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
Migration-number hazard: `feat/host-based-tenant-routing` also introduced a
`V33__tenant_hosts.sql` — whichever lands on `main` first wins V33; the other
must renumber.

### origin/dev is behind main
As of 2026-05-14, `origin/dev` had drifted well behind `origin/main` (~25
commits). Fast-forward when ready: `git push origin main:dev` (main is strictly
ahead; if branch protection blocks it, open a no-op PR). **Confirm with the user
first** — the drift may be intentional.

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

## Operational deadlines

### SendGrid free trial ends 2026-07-16
`weldforge-auth` sends transactional email (password reset, email verification)
via SendGrid SMTP. The SendGrid account is on a **free trial that ends
2026-07-16** — downgrade to the permanent Free plan in the SendGrid dashboard
before then. If the trial lapses, delivery stops with **no visible error** in the
app (`SmtpMailService` logs a delivery failure but the triggering security
operation still succeeds), so account recovery silently breaks for every tenant.

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
