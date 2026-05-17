---
name: PlatformSettings feature on feature/write-buddy-integration — not yet on main
description: PlatformSettings + MailService work was committed on its own branch (1a321df) but never merged; verify before assuming main has these classes
type: project
originSessionId: 9f38af7d-b118-4b7d-ab14-ea150e67a780
---

PlatformSettings + Mail feature lives on branch `feature/write-buddy-integration` at commit `1a321df` (`feat(platform-settings): DB-backed SMTP config + admin UI`). It is NOT merged to `main` — `git ls-tree main` shows no `platform-settings.service.ts` and no V33__platform_settings.sql (main's latest migration is V32).

Files involved (per the original 2026-05-05 inventory):
- Backend: `PlatformSettings`, `PlatformSettingsDto`, `PlatformSettingsRepository`, `PlatformSettingsService`, `PlatformSettingsAdminController`, `MailService`
- Migration: `V33__platform_settings.sql`
- Frontend: `weldforge-admin-portal/src/app/core/services/platform-settings.service.ts`
- Modified collaborators: `pom.xml`, `EmailVerificationService`, `PasswordResetService`, their BDD steps, `TenantBrandingSteps`

**Why this matters:** Two unrelated features have since claimed migration version V33 — `feat/host-based-tenant-routing` also introduced a `V33__tenant_hosts.sql`. Whichever lands on main first wins V33; the other needs to renumber.

**How to apply:**
- Before writing anything that depends on PlatformSettings classes, check current branch with `git ls-tree HEAD -r | grep PlatformSettings`. If absent, you're on a branch where it doesn't exist.
- If the user wants to merge `feature/write-buddy-integration` to main, expect a V33 collision with the host-routing migration and renumber to V34 (or whatever's next).
- If the user has since merged or discarded this branch, remove this memory entry.
