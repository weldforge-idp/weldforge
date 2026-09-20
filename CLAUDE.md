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

**Refresh-cookie contract.** The Safe Space backend reads WeldForge's
refresh cookie by its exact name, `refresh_token` (extracted from Set-Cookie
on login/register, sent back as `Cookie: refresh_token=…` with
`X-Tenant-Slug: techmetropolis`). Browsers now use per-tenant
`wf_refresh_<slug>` cookies (B-TEN-7), but keep writing and accepting the
legacy `refresh_token` until that proxy reads `wf_refresh_techmetropolis`:
its fallback is to silently stop renewing sessions.

Known consumer-side bug worth knowing about (out of scope for
weldforge-auth itself but planned): failed-login audit + lockout
counter writes happen inside `AuthService.login`'s `@Transactional`;
the `BadCredentialsException` rolls them back. Result: failed logins
are not audited and account lockout never engages. `REQUIRES_NEW` on
the audit/lockout writes when next touched here.

---

## Infrastructure & production access  *(reference)*

- **GitHub repo:** `weldforge-idp/weldforge` — **public**, default branch
  `main`. (It was private when this note was first written; the
  `publish-images` workflow depends on it being public, because GitHub's arm64
  runners are only free for public repos.)
- **Where it runs (since 2026-08-31):** a single-node **k3s** cluster on
  `tech01`, not GCP. Namespaces `weldforge-staging` and `weldforge-production`.
  **This is not the only live instance** — a second one runs on GKE and is the
  identity provider for Safe Space, Krusty and Commentalk. See the two-instance
  table below before touching anything GCP-related.
- **Deploy = two repos, and there is no push-to-deploy.**
  1. Merging to `main` runs `.github/workflows/publish-images.yml`, which
     builds `ghcr.io/weldforge-idp/{weldforge-auth,weldforge-admin-portal}`
     multi-arch and tags them `sha-<short-sha>` (e.g. `sha-0992ad2`).
  2. Nothing deploys until someone bumps `newTag` in the **infrastructure**
     repo (`christiaanwvermaak/cwvermaak_infrastructure`, branch `main`) at
     `apps/weldforge/overlays/{staging,production}/kustomization.yaml`, pushes,
     and Flux reconciles. Staging first, then production — always.

     ```sh
     ssh tech01
     export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
     flux reconcile source git flux-system -n flux-system
     flux reconcile kustomization weldforge-staging -n flux-system
     flux reconcile kustomization weldforge-production -n flux-system
     ```

     Pre-deploy dump before a migration:
     `kubectl -n postgres create job <name> --from=cronjob/postgres-backup`
     (dumps land at `/var/backups/postgres` on the node, hostPath).
  3. **Before promoting, run `./scripts/Test-PrePromotion.ps1`** against
     staging, and again against production afterwards. Read-only, ~20 checks,
     each one a defect that reached production at some point — ingress routing,
     public `/actuator` exposure, 415/400-not-500 handling, edge security
     headers, wildcard TLS expiry. The unit and integration suites cannot see
     any of it, because it lives in the other repo.
- **External uptime check:** `.github/workflows/uptime.yml` probes the public
  surface every 15 minutes from GitHub's infrastructure and opens a labelled
  `uptime` issue when it fails. It exists because the in-cluster monitoring runs
  *on* `tech01` and therefore cannot report that `tech01` is down. Set the
  optional `NTFY_UPTIME_URL` repo secret to a topic on a server that is **not**
  `tech01` to get a push as well.
- **CI workflow:** `.github/workflows/ci.yml`. The backend job runs
  `./mvnw -B -ntp verify -Dtests.integration=true` — the `-Dtests.integration`
  flag is set **only** in CI; a local `./mvnw clean verify` skips the
  Testcontainers Postgres tests.
- **Secrets** are SOPS/age encrypted in the infrastructure repo, one file per
  environment: `apps/weldforge/overlays/{staging,production}/secret.sops.yaml`.
  Not GCP Secret Manager. The age key is at `.important/sops-age.key` in that
  repo (git-ignored). sops here is **3.7.3**, which has no `edit` subcommand —
  it is `sops <file>`, and `code --wait` hangs, so use `notepad`.
  **Staging and production hold different values** — verify, never assume they
  match, and never copy one into the other without checking.
- **A changed Secret does not restart anything.** ConfigMaps generated by
  kustomize carry a name-suffix hash and so force a rollout; plain Secrets do
  not. After editing a secret, `kubectl rollout restart` the deployment or the
  change deploys and silently does nothing (this is exactly how the SendGrid
  settings looked live on 2026-09-13 while the pods still held the old ones).
- **⚠️ THERE ARE TWO LIVE WELDFORGE INSTANCES. Read this before touching GCP.**
  An earlier version of this file said "GCP is dormant". **That was wrong, and
  acting on it could take down the identity provider for three production
  apps.** Corrected 2026-09-20 after the Safe Space session flagged it; verified
  by request, not taken on trust.

  | | **tech01 (k3s)** | **GKE `weldforge-499409`, namespace `sso`** |
  |---|---|---|
  | Host | `https://sso.weldforge.org` → 196.40.100.82 | `https://sso-api.weldforge.org` → 136.68.154.69 |
  | Database | `weldforge_prod`, in-cluster | Cloud SQL `weldforge-db` via cloudsql-proxy |
  | Mail | SendGrid | Xneelo SMTP, hand-patched |
  | Deploy | Flux from the infrastructure repo | `kubectl set image` — **never `helm upgrade`** |
  | Image | current | `weldforge-auth:r2`, built **2026-06-17** |
  | Serves | the portal, `leap`, `cwvermaak-tech`, `intellisuite` | **Safe Space, Krusty, Commentalk** via `techmetropolis` |

  The deploy workflow `deploy-gcp.yml` is genuinely dormant — its push trigger
  was removed on 2026-08-16 and it fails on billing. **The dormant thing is the
  workflow, not the cluster.** Confusing the two is how this error happened.

  **Before changing anything, check which hostname the caller uses.** Safe Space
  calls `sso-api.weldforge.org`. Never `helm upgrade` the GKE release: revision 5
  is FAILED and an upgrade wipes the hand-patched mail secret. Roll images with
  `kubectl set image`; the public GHCR tags pull fine from GKE.

- **⚠️ The two instances share `techmetropolis`'s private signing key.** Verified
  2026-09-20: both publish `kid: wf-66256c5b-a66c-4044-bd98-a3d97b81adc0` for
  that tenant. tech01's copy began as a restored clone and, since the catch-up
  on 2026-09-20, holds the same **10** users with **all 10 password hashes
  identical**. Consequences, none of them recorded anywhere before now:
  - Compromise of **either** instance compromises the tenant on **both**.
  - A token minted by one validates against the other's JWKS.
  - **`iss` does NOT separate them.** An earlier version of this note said it
    did. It is wrong, and it is the kind of wrong that gets built on. Both
    instances set `APP_PUBLIC_BASE_DOMAIN=sso.weldforge.org`, and the legacy
    access token's issuer is derived from *config*, not from the request host —
    so both stamp the identical `https://sso.weldforge.org/t/techmetropolis`.
    Same key, same `kid`, same `iss`, same `tenant`: **nothing in a token says
    which instance minted it.** (OIDC *discovery* documents do differ per host;
    that is a different code path and is where the confusion came from.)
  - Because of the above, the instance that served a request can only be
    identified from the server side. Use `sso_auth_login_total{tenant="..."}`,
    which both images export (the tenant tag predates the GKE build). Note the
    tech01 edge has **no Traefik `--accesslog`** — there is no per-request edge
    trail to fall back on.
  - The platform HS512 `app.jwt.secret` is shared the same way, so rotating it
    is a **four-way** coordination (GKE, tech01, and three app backends), not
    the three-way one the handover describes.

  **Cutover status: DONE 2026-09-20.** Data catch-up applied and verified
  (10/10 accounts, 10/10 password hashes identical, delta clean before *and*
  after the repoint). Safe Space and Krusty both now point at
  `https://sso.weldforge.org`; verified with `printenv` inside the running
  safe-space pod, plus JWKS 200 and `/health` 200 from that pod. An estate-wide
  scan of Secrets, ConfigMaps, Deployments, StatefulSets and CronJobs across
  `safe-space`, `krusty` and `default` finds **no remaining reference to
  `sso-api.weldforge.org`**. GKE stays up as the parallel window; decommission
  is the operator's call.

  **⚠️ What moved is the SSO pointer ONLY — the apps did not move.** An earlier
  instruction ("only the tech01 instance is used by TechMetropolis
  applications") reads as though the apps migrate to tech01. They do not, and
  clarified by the operator 2026-09-20:

  | | stays / goes |
  |---|---|
  | `techmetropolis-501911` — Safe Space, Krusty, (Commons) | **STAYS on GKE** |
  | `weldforge-499409` ns `sso` — the old WeldForge SSO | **decommission** |

  Only the `WELDFORGE_BASE_URL` / `WELDFORGE_LEGACY_BASE_URL` /
  `WELDFORGE_JWKS_URI` values in each app's secret were repointed. The Tech
  Metropolis apps keep running where they always have.
- **Public URLs:** production `https://sso.weldforge.org`, staging
  `https://staging.weldforge.org`. Per-tenant subdomains resolve on both
  (`*.sso.weldforge.org`, `*.staging.weldforge.org`) with matching wildcard
  certs from `letsencrypt-dns`.
  Outside-in liveness: `GET /health` → 200 `application/json`. Internal:
  `kubectl -n weldforge-production exec deploy/weldforge-auth -c api -- curl -s http://localhost:8076/actuator/health`.
  **`/actuator/**` is not routed by the ingress** and an external request falls
  through to the SPA as HTML. That is deliberate as of 2026-09-13: the route
  existed until then and served `/actuator/prometheus` and `/actuator/health`
  unauthenticated to the internet. Prometheus scrapes the ClusterIP Service
  in-cluster, so nothing needs the public route back.
- **Monitoring and alerting** live on the same node — Prometheus, Alertmanager,
  Grafana (`https://grafana.cwvermaak.tech`) and self-hosted ntfy
  (`https://ntfy.cwvermaak.tech`, topic `alerts`). Design, alert list and
  runbook: `docs/monitoring.md` in the infrastructure repo. Alerts to know
  about here: `WeldForgeMailDeliveryFailing` (the counter is the *only* signal
  that account recovery is broken, since `SmtpMailService` returns success to
  the caller by contract) and `WeldForgeAuthDown`.
- **`leap` — the live public demo tenant.** Slug `leap` (seeded by
  `V40__add_leap_tenant.sql`); it's the canonical "prove WeldForge is live"
  tenant that `weldforge.org`'s `llms.txt` / `agents.html` self-verify steps
  point at. All of its public protocol endpoints return 200, no auth:
  `https://sso.weldforge.org/t/leap/{.well-known/openid-configuration,oauth2/jwks,saml2/idp/metadata}`.
  Use `leap` (not `demo` — there is no `demo` tenant) for any public
  self-verify / smoke test. The `default` bootstrap tenant also serves these
  now (its legacy signing key was regenerated in `V41`, PR #47, 2026-06-05).
  **Staging has no `leap` tenant** — smoke-test staging against `default`.
- **Outbound email:** SendGrid SMTP, `smtp.sendgrid.net:587`, STARTTLS **true**
  and SSL **false** (not interchangeable — setting the SSL flag on 587 fails),
  username the literal string `apikey`, password in `SPRING_MAIL_PASSWORD` in
  the SOPS secret. Sender domain authenticated via the `em1505` CNAME and
  `s1/s2._domainkey` on `weldforge.org`. From address `no-reply@weldforge.org`.
- ~~Pre-existing quirk: `/api/auth/tenants/*/{branding,social-providers,saml-providers}`
  are gated by `AppAuthorizationFilter`.~~ **Not true — corrected 2026-09-20.**
  `AppAuthorizationFilter` exempts `path.startsWith("/api/auth/")` wholesale, so
  those endpoints take no `x-app-authorization` at all. Verified against both
  live instances: they answer **200 with a bogus key and with no key**.

  Worth knowing because it is an easy way to fool yourself. I used one of these
  endpoints to "prove" a legacy API key still authenticated after a cutover;
  the 200 meant nothing. If you need to test whether a key is accepted, pick a
  path the filter actually guards — `/api/admin/**` — not one under
  `/api/auth/`.

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

> Reconciled 2026-09-14. Items 1, 6 and 7 are closed; 3-5 are still the real
> remaining work.

1. ~~**Wildcard DNS + TLS**~~ — **DONE, differently.** Not Google
   Certificate Manager: the k3s move brought cert-manager with a
   `letsencrypt-dns` (DNS-01/Cloudflare) ClusterIssuer, and both
   `*.sso.weldforge.org` and `*.staging.weldforge.org` resolve and carry
   valid wildcard certs. The GCP runbook is obsolete.
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
6. ~~**Prometheus alert on `sso.mail.send` failure counter**~~ —
   **DONE 2026-09-13**, and it took building the whole monitoring stack
   first (there was none). `WeldForgeMailDeliveryFailing` on
   `sso_mail_send_total{outcome="failure"}` → ntfy.
7. ~~**SendGrid smoke test on 2026-07-14**~~ — **obsolete.** Different
   account now, and the alert above replaces the manual check.
8. **`origin/dev` sync** — still open and still growing: 61 (2026-05-23)
   → 71 (2026-06-08) → **192** (2026-09-14). Nothing has merged *from* dev
   in that time, which is itself the signal that it may be abandoned rather
   than pinned. Confirm with the user before pushing.

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

## Session log 2026-09-10 — Sprint 5 gaps + Sprint 6  *(project)*

> Re-verify with `git branch -a` / `gh pr list` before acting.

- **Shipped:** PRs #93 (Sprint 5 gaps) and #94 (Sprint 6) merged; `sha-797c70b`
  live on staging and production (infra `c145ce3`, `ad7b8f7`). Migrations at
  **V56**. Deploy = bump `infrastructure/apps/weldforge/overlays/{staging,production}`,
  then on the node: `ssh tech01`, `export KUBECONFIG=/etc/rancher/k3s/k3s.yaml`,
  `flux reconcile source git flux-system -n flux-system` and
  `flux reconcile kustomization weldforge-<env> -n flux-system`. Pre-deploy dump:
  `kubectl -n postgres create job <name> --from=cronjob/postgres-backup`.
- Staging has no `leap` tenant — smoke-test staging against `default`.
- Record of what shipped and why: `docs/product/standards-conformance-backlog.md`
  §7, `docs/security/hardening-backlog.md` F44–F53, and the new
  `docs/compliance/standards-conformance.md` (regenerate each sprint) plus
  `docs/adr/0001–0004`.
- Fixed and live: `/api/auth/tenants/verify-contact-page` had answered 400
  "Conversion = ';'" in prod (identity-proofing V2a emails were dead links).
- Open: B-API-2 — no Bean Validation provider, `@Valid` enforced nowhere.
- **Open, needs a product decision:** OIDC `max_age` is enforced as MFA-factor
  freshness and ends in a browser `400 mfa_required`; `prompt=login` ignored
  (conformance statement D1/D2).
- Product decisions taken: 800-63B password defaults + HIBP screening
  (fail-open); pre-existing SAML SPs pinned to `PasswordProtectedTransport` (V56).

---

## Session log 2026-09-11 to 09-14 — ten production defects + observability  *(project)*

> Re-verify with `gh pr list --state merged` and the infra repo's overlay
> `newTag` before acting. Live on staging and production: **`sha-0992ad2`**
> (PRs #96-#103). Migrations at **V57**.

### What was actually wrong in production

This started as "the admin-portal tenant picker writes to the wrong tenant" and
turned up ten live defects. Worth reading as a list, because the common thread
is that **most of them were silent** — the system returned 200 while doing the
wrong thing or nothing at all.

1. **Misdirected admin writes.** The Tenants page drew one tenant's lists under
   every row and sent no selector; the backend had a second, unaudited
   super-admin override that fell back to the home tenant. A KeyCrypt OIDC
   client created from the `cwvermaak-tech` row landed in `default` with a 200.
   Fixed in F54 — one selector, `CrossTenantSelectorFilter`, refuses rather than
   falls back. See the *Admin calls* note under Working guidance.
2. **`/tenants` returned 403.** The ingress had `path: /t` and Traefik reads
   `pathType: Prefix` as a **string** prefix, so `/tenants` matched the OIDC
   deep-link rule and was answered by the API. Fixed to `/t/`.
3. **403 instead of 401 for a signed-out admin.** An expired session hit the
   selector unauthenticated and got "Caller has no admin membership", which
   reads as a permissions bug rather than "log in again".
4. **One refresh cookie shared across tenants** (B-TEN-7) — now
   `wf_refresh_<slug>`, with the legacy `refresh_token` still written for the
   Safe Space proxy (see the refresh-cookie contract above).
5. **No Bean Validation provider** (B-API-2) — `@Valid` was enforced nowhere, so
   malformed input produced 500s. Added the starter; 313-case
   `MalformedInputIntegrationTest` covers it.
6. **The order funnel and payment webhooks were 403'd in production** by
   `AppAuthorizationFilter`.
7. **A tenant's OIDC secret was displayed in a `window.alert`.**
8. **Password hints overlapped the fields below them** (Material subscript
   sizing).
9. **Passkey sign-in was impossible** — three separate causes stacked:
   the ceremony row was keyed by the MFA challenge JWT and overflowed
   `varchar(128)`; the username lookup was global rather than tenant-scoped, so
   a duplicate email in another tenant hijacked the ceremony; and the login page
   had no passkey UI at all.
10. **Outbound email had never been configured since the GCP move** — no SMTP
    host on k3s for two weeks. See the SendGrid section below.

Plus the meta-defect: **`disableNameSuffixHash: true` meant config changes
deployed without restarting any pod**, so fix #10 looked applied and wasn't.
Fixed estate-wide.

### Then: monitoring, because none of this was observable

The cluster had no metrics, no alerts and no dashboards. Built on 2026-09-13/14:
kube-prometheus-stack + Alertmanager + Grafana + self-hosted **ntfy** on
`tech01`. Full design, alert list and runbook: **`docs/monitoring.md` in the
infrastructure repo**. The short version for this repo:

- `WeldForgeMailDeliveryFailing` closes the 2026-05-23 backlog item #6.
- ntfy over Slack on weight; a small `ntfy-alertmanager` bridge exists because
  Alertmanager does not template webhook bodies and ntfy would otherwise notify
  raw JSON.
- **Known gap:** a monitoring stack on `tech01` cannot alert that `tech01` is
  down. Needs an external dead-man's-switch pointed at Alertmanager's
  `Watchdog` or `https://sso.weldforge.org/health`. **Operator action** — not
  built.

### Found and fixed while surveying
`/actuator/prometheus` and `/actuator/health` were reachable **unauthenticated
from the internet** on production (200) — every metric, tenant slugs and request
URIs included. The ingress `/actuator` route is gone; details in the
Infrastructure section above.

### Also shipped 2026-09-14

- **Monitoring + alerting** — see the Infrastructure section above and
  `docs/monitoring.md` in the infrastructure repo.
- **`scripts/Test-PrePromotion.ps1`** — ~20 read-only black-box checks against a
  deployed environment, each one a defect that actually reached production. Run
  it against staging before promoting and against production after.
- **`.github/workflows/uptime.yml`** — external uptime probe, because the
  in-cluster monitoring runs *on* `tech01` and cannot report that `tech01` is
  down. Opens one labelled `uptime` issue and closes it on recovery.
- **Horizontal scaling unblocked** — ShedLock (`V58`) leases each of the eight
  `@Scheduled` jobs so exactly one instance runs them. Before this, two replicas
  meant two provisioning retries per paid order, two webhook deliveries and two
  concurrent signing-key rotations. **The rate limiter is still per-instance**,
  so N replicas = N × the configured limit; divide the limits or move the
  buckets to Redis before raising the count. Deliberately no HPA. Full
  procedure: `docs/scaling.md` in the infrastructure repo.
- **Hosted sign-up captures leads** — `POST /api/public/orders` used to throw
  when no payment gateway was configured, *before* writing the order row, so the
  funnel discarded every sign-up. It now records the order either way and
  returns an explicit `nextStep` (`CHECKOUT` | `MANUAL_FOLLOW_UP`). Self-serve
  card checkout still needs a merchant account, which is an operator task.
- **`X-Robots-Tag: noindex, nofollow` on the SSO host** — it had no robots.txt,
  no meta tag and no header, so every tenant's login and password-reset page was
  indexable.
- **Marketing site brought in line with reality** (PRs #105, #106) — per-tenant
  subdomains documented as live, `admin.weldforge.org` removed (it does not
  resolve), competitor pricing re-checked and corrected where it had gone stale
  in our favour.

### Session log 2026-09-15 — security review + the atomic-claim fix  *(project)*

**`docs/security/review-2026-09-14.md`** is the expert read of implementation
and documentation: eight findings not already in the hardening backlog, with a
suggested order. Two were High and are now **fixed** (PR #109).

**B-OIDC-6 / B-AUTH-6 — single-use enforcement was a check-then-write race.**
Authorization codes and refresh tokens were guarded by reading the row, testing
`usedAt` in Java, and writing afterwards. Under READ COMMITTED two concurrent
redemptions both passed. Demonstrated, not argued: with the fix's predicate
removed, eight concurrent rotations of one refresh token gave *"8 succeeded and
0 were refused"*. Both claims are now conditional `UPDATE`s returning a row
count; zero means the reuse path, never a retry.

Two hazards the new test found that were not the bug being fixed — **read these
before touching either service**:

1. **The refresh claim must stay `REQUIRES_NEW`.** A lost claim is followed by
   the family revoke, itself `REQUIRES_NEW` so the rejection cannot roll the
   containment back — and both target the same row. In one transaction the
   failed claim holds a tuple lock the revoke waits for, while the caller waits
   for the revoke to return. **Postgres sees no cycle, so the deadlock detector
   never fires and the request hangs.** The authorization-code claim
   deliberately does *not* do this: its reuse path revokes `refresh_tokens`, a
   different table.
2. **Never mutate the managed `RefreshToken` in the rotation path.** JPA flushes
   every column at commit from a snapshot taken at load, so a concurrent reuse
   sweep's `revoked_at` was being overwritten with a stale `null` — the
   containment ran, audited itself as successful, and was silently undone. Both
   writes go through targeted `UPDATE`s (`claim`, `markReplacedBy`).

**Test-mock trap.** Mockito answers an unstubbed `int` with `0`, which these
services read — correctly — as "already spent". Any mock of
`RefreshTokenRepository` or `OAuthAuthorizationCodeRepository` must stub
`claim()`, or every rotation and code exchange in that suite becomes a reuse
detection. Five classes needed it.

### Product decisions taken 2026-09-15

- **Dynamic client registration:** gated on the hosted `weldforge.org` tenants,
  open on self-hosted deployments. Implement RFC 7592 rather than keep
  returning a `registration_client_uri` that 404s — the Dynamic OP conformance
  profile exercises it anyway.
- **Password composition:** relax toward 800-63B, **and** make the rules
  per-tenant configurable in the management interface. To be planned,
  documented and implemented properly — not yet started.
- **OpenID certification: yes.** Self-certification against the OpenID
  Foundation suite, Basic OP first. The known blockers are `prompt=login` being
  ignored and `max_age` enforced as MFA-factor freshness ending in a browser
  400 — the suite tests both directly.
- **Out of scope, confirmed:** Spring Authorization Server (assumes one issuer
  per application; would rebuild the per-tenant design on an abstraction that
  fights it), FAPI 2.0, SCIM ETags. **Back-channel logout is the one worth
  funding** — the only item enterprise buyers ask for by name, and today
  RP-initiated logout leaves every relying party signed in. RFC 9068 when a
  breaking audience change happens anyway.

### Next, in the agreed order

1. ~~B-OIDC-6 / B-AUTH-6~~ — done, PR #109.
2. **`SECURITY.md` + `/.well-known/security.txt`** — none exist on a public
   identity product.
3. **`SameSite=Strict` on the refresh cookie** — one line; the session cookie
   beside it sets `Lax` deliberately and the longer-lived credential sets
   nothing.
4. **Rewrite the threat model against k3s** — it still analyses GKE, which
   invalidates the trust boundaries drawn on it.
5. Expired-refresh-token purge; then B-OIDC-7, B-AUTH-5, B-PROV-2, B-JWT-2.

---

### Answered, so it does not get re-asked

**`/login` serves the admin portal SPA, not this service's `LoginController`,
and that is correct.** The Ingress forwards `/api`, `/t/`, `/saml2`, `/scim` and
`/health` to the backend and everything else to the portal. The OIDC
`/authorize` state machine redirects unauthenticated users to
`{tenant-origin}/login/?oidcReturnTo=…` *expecting the SPA*, which reads that
parameter (`core/oidc-continuation.ts`) and applies the tenant's branding via
`TenantBrandingService`. `LoginController` serves the same paths for deployments
that reach the API directly with no separate portal host — a docker-compose
self-host. Both exist on purpose. Verified: `/login` and `/login/` both answer
200 on the apex and on tenant subdomains.

### Still open after this session
- Stray prod OIDC client `oidc_clients` id 10 in `default` (zero dependents).
  **The auto-mode classifier blocks Claude from running production DELETEs** —
  asking again won't help. Operator deletes it from the portal's `default` row.
- `wf_session` is still one base-domain cookie across tenants: signing in to
  tenant B ends A's browser session for OIDC `/authorize`. A re-login, never a
  cross-tenant session, but a design gap.
- Local pre-promotion E2E script (user chose a local script over CI-against-
  staging) — not built.
- Dead Cloudflare records `em8050`, `107605731`, `url7762`.
- ~~Stale GitHub issues #79/#80/#81~~ — all three closed 2026-09-14. #79 was
  resolved structurally by the k3s move: cert-manager issues a wildcard, so the
  hand-maintained `tenantCerts` list is no longer in the path and a brand-new
  tenant subdomain gets a valid certificate with no manual step (verified).
  `origin/dev` is still 192 behind main.
- **Needs the operator, not Claude:** a merchant account (the only thing between
  a captured sign-up and a self-serve paying customer), and deleting the stray
  production OIDC client — the classifier blocks Claude from production DELETEs.
- Dead Cloudflare records from the old SendGrid account: `em8050`,
  `107605731`, `url7762`.

### Process notes worth keeping
- **The infrastructure repo has several Claude sessions working in it at once.**
  They share one working tree and therefore one **index**, so `git add <path>`
  followed by a bare `git commit` still commits another session's staged files —
  which happened twice. Use a pathspec commit: `git commit -- <paths>`, which
  reads the working tree and ignores the index.
- I merged PR #102 while backend CI was still pending. It passed; don't rely on
  that.

---

## Operational deadlines

### SendGrid — rebuilt 2026-09-13 on a new account

The old account and its 2026-07-16 trial-perks date are **history**. What
matters now:

- Outbound mail was **dead from the GCP move (2026-08-31) until 2026-09-13** —
  no SMTP was configured on k3s at all. Nobody noticed for two weeks, because
  `SmtpMailService` catches the failure and the triggering security operation
  (password reset, email verification, identity-proofing challenge) still
  returns success. Every account recovery in that window silently failed.
- A new SendGrid account was set up and sender domain authentication completed
  on `weldforge.org` (`em1505` CNAME, `s1`/`s2._domainkey`) via Cloudflare.
  Delivery confirmed by the operator receiving real mail from staging and
  production on 2026-09-13.
- Free tier, 100 emails/day — comfortably above current volume (single digits
  per day across all tenants). Trial perks on the new account run to
  **2026-11-12** per the dashboard at signup; that is a perks date, not a plan
  cliff, and there is nothing to click when it passes.
- **This no longer needs a calendar reminder.** The
  `WeldForgeMailDeliveryFailing` Prometheus alert now watches
  `sso_mail_send_total{outcome="failure"}` and pushes to ntfy, which is what
  the old 48h-before smoke test was standing in for. If mail breaks — plan
  change, key rotation, DNS, anything — the alert fires within 15 minutes.
- Dead Cloudflare records left over from the old account and still to be
  cleaned up: `em8050`, `107605731`, `url7762`.

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

### Email identity is `(tenant, lower(email))` — never email alone

A person legitimately holds accounts in several tenants under one address, and
production already contains one. `/llms.txt` publishes it: *"The same address
may exist in another tenant."* Enforced by `users_tenant_email_unique` since
**V59**; before that nothing stopped two rows sharing an address inside a
tenant, because the application's pre-check is a check-then-insert and two
concurrent registrations both pass it.

**How to apply:** never add a global unique on `users.email` — it would fail to
apply against live data and, if forced, break a real user. Keep `lower()` in any
uniqueness or lookup logic; every lookup is already case-insensitive
(`findByTenant_SlugAndEmailIgnoreCase`), so a case-distinct duplicate would be
two rows the login path treats as one. A violation of that index is mapped back
to the documented `400 bad_request` rather than a generic 409, so a client sees
one answer regardless of whether the pre-check or the constraint won.

### Admin calls: one tenant selector, refuse don't fall back
Which tenant an admin call acts in has exactly **one** answer: the JWT's tenant,
unless `CrossTenantSelectorFilter` switches it on `X-WF-Tenant` (or the legacy alias
`X-Tenant-Slug`) — membership-checked, audited, and **refused** (404/403/400) when it
cannot be honoured. Never add a second path that changes `TenantContext` for admin
calls, and never fall back to the home tenant when a named tenant is unusable. A
request with *no* selector acts at home by design, so the server cannot catch a lost
selector — the portal must name the tenant.

**Why:** on 2026-09-11 a KeyCrypt OIDC client created from the `cwvermaak-tech` row
landed in `default` with a 200. The Tenants page drew one tenant's list under every
row and sent no selector; the backend had a second, unaudited super-admin override
that fell back silently. Fixed in F54 / `docs/cross-tenant-admin-spec.md` §11.

**How to apply:**
- Portal screens drawn under a specific tenant's row pass `forTenant(t.slug)`
  (`core/tenant-selector.ts`) on every call — list, create, update, delete. Don't
  load row-scoped lists once in `ngOnInit`.
- Admin responses carry `X-WF-Acting-Tenant`; the interceptor turns a mismatch into a
  409. Keep new admin endpoints under `/api/admin/**` so they get both.
- "Is super-admin" is `sa OR adm=SUPER_ADMIN`, and cross-tenant reach is the global
  `admin_membership` row. Anything that grants or removes super-admin goes through
  `GlobalSuperAdminMembership` so the two stay equal.
- Don't test cross-tenant writes against production tenants; staging uses `default`.

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
