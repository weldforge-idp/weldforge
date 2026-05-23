---
name: PlatformSettings feature on feature/write-buddy-integration — not yet on main
description: PlatformSettings + MailService work was committed on its own branch (1a321df) but never merged; verify before assuming main has these classes
type: project
originSessionId: 9f38af7d-b118-4b7d-ab14-ea150e67a780
---

PlatformSettings + Mail feature lives on branch `feature/write-buddy-integration` at commit `1a321df` (`feat(platform-settings): DB-backed SMTP config + admin UI`). It is NOT merged to `main` — `git ls-tree main` shows no `platform-settings.service.ts`.

Files involved (per the original 2026-05-05 inventory):
- Backend: `PlatformSettings`, `PlatformSettingsDto`, `PlatformSettingsRepository`, `PlatformSettingsService`, `PlatformSettingsAdminController`, `MailService`
- Migration: `V33__platform_settings.sql` (will collide — see below)
- Frontend: `weldforge-admin-portal/src/app/core/services/platform-settings.service.ts`
- Modified collaborators: `pom.xml`, `EmailVerificationService`, `PasswordResetService`, their BDD steps, `TenantBrandingSteps`

**Migration-version collision (UPDATED 2026-05-23).** The earlier note said the V33 slot was contested between this branch and `feat/host-based-tenant-routing` (`V33__tenant_hosts.sql`); whichever merged first would win and the other would have to renumber. Neither merged: a third unrelated change landed `V33__oidc_public_clients_and_origins.sql` on main, and main has since reached **V40** (`V40__add_leap_tenant.sql`). Both stale-V33 branches now need to renumber to the next free slot (V41 at time of writing) when revived. Run `ls weldforge-auth/src/main/resources/db/migration/ | tail -5` before merging either branch.

**How to apply:**
- Before writing anything that depends on PlatformSettings classes, check current branch with `git ls-tree HEAD -r | grep PlatformSettings`. If absent, you're on a branch where it doesn't exist.
- If the user wants to merge `feature/write-buddy-integration` to main, renumber its `V33__platform_settings.sql` to the next free slot (check `ls weldforge-auth/src/main/resources/db/migration/` first).
- If the user has since merged or discarded this branch, remove this memory entry.
