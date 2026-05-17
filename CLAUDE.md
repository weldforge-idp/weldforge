# CLAUDE.md

Portable working memory for Claude Code, kept **inside the repo** so it travels
with a copy or `git clone` and loads automatically on any installation.

## Why this file exists

Claude Code's normal memory store lives at `~/.claude/projects/<path-slug>/memory/`.
It is machine-local and keyed by the project's absolute path, so it does **not**
survive copying or cloning the project to another machine. This file plus the
verbatim snapshot in [`docs/agent-memory/`](docs/agent-memory/) is the portable
equivalent: `CLAUDE.md` auto-loads on every installation and carries the index;
`docs/agent-memory/` holds the full notes.

`docs/agent-memory/` is the committed mirror; `~/.claude/projects/.../memory/` is
the live store on whichever machine is in use. **When memories change, update
both** so the snapshot stays current.

## Memory index

Read the matching file under `docs/agent-memory/` when its topic is relevant.

- **reference_infra.md** — repo `weldforge-idp/weldforge`, GKE cluster, kubectl context.
- **deployment_pipeline.md** — deploys run on GitHub Actions, not TeamCity; `TEAMCITY.md` / `deploy.sh` comments are stale.
- **github_account.md** — `christiaanwvermaak` is the correct GitHub user; the `gh` credential helper flips between accounts.
- **feedback_git_push_token_in_url.md** — the `gh` credential helper returns the wrong account's token; push with the `https://user:token@host` form.
- **feedback_auth_form_branding_in_docs.md** — every tutorial/integration guide must document how operators brand the login + password-reset forms.
- **feedback_angular_zoneless_pitfalls.md** — `computed()` over a non-signal field freezes; a template `!` on a lazy-init object throws at runtime and truncates change detection.
- **sendgrid_trial_deadline.md** — SendGrid free trial ends **2026-07-16**; downgrade to the free plan before then or transactional email silently stops.
- **platform_settings_wip.md** — PlatformSettings committed on `feature/write-buddy-integration@1a321df`, not on main; its V33 slot collides with host-routing's `V33__tenant_hosts.sql`.
- **dev_branch_behind.md** — `origin/dev` is well behind `main`; a fast-forward is ready, awaiting user go-ahead.
- **tenant_nesting_wip.md** — `feat/admin-rest-tenant-nesting@1ff7451`; 5 TS2554 errors in `service-accounts.component.ts`; thread `tenantId` via `TenantPickerService.outgoingTenantId()`.
- **portable_memory_snapshot.md** — this arrangement: memory mirrored to `docs/agent-memory/` + `CLAUDE.md`; keep both in sync.

## Re-seeding the live memory store on a new installation

Run from the project root (PowerShell) to restore the machine-local store from
this snapshot:

```powershell
$slug = (Get-Location).Path -replace '[:\\/]','-'
$dest = Join-Path $env:USERPROFILE ".claude\projects\$slug\memory"
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item docs\agent-memory\*.md $dest -Force
```

After that, Claude Code's memory tool reads the notes from the live store as
usual. Even without this step the knowledge is available — `CLAUDE.md` auto-loads
and points at `docs/agent-memory/`.

## Project orientation

See `README.md` and `LAUNCH.md` for the platform overview. WeldForge is a
multi-tenant SSO / IAM platform: `weldforge-auth` (Spring Boot, Java 25),
`weldforge-admin-portal` (Angular, zoneless), `weldforge-www` (marketing site),
and the Helm chart under `infrastructure/helm/weldforge`. Deploys go out via the
GitHub Actions workflow `.github/workflows/deploy-gcp.yml`.
