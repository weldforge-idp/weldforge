---
name: origin/dev branch behind main
description: dev branch has drifted ~25 commits behind main; fast-forward when user gives go-ahead
type: project
originSessionId: 9f38af7d-b118-4b7d-ab14-ea150e67a780
---

As of 2026-05-14, `origin/main` is at `bde8784` (PR #26) plus the unmerged WIP commit `1ff7451` on `feat/admin-rest-tenant-nesting`. `origin/dev` is **25 commits** behind `origin/main` — drift has grown from 1 commit on 2026-05-04 to 25 commits as the user shipped PRs #19–#26.

The user has flagged sync `dev` → `main` as a pending follow-up but kept deferring it because there's always more in-flight work. Don't auto-execute.

Concrete command when ready: `git push origin main:dev` (fast-forward — main is strictly ahead). If branch protection blocks the direct push, open a no-op PR.

**Why:** Future feature branches should branch off a current `dev`. Letting it drift further makes that more painful. Also: someone external looking at `dev` as the integration branch will see month-old state.

**How to apply:** Confirm with user before pushing — `dev` being out of date may still be intentional (e.g. waiting for a quiet window or a deliberate release marker).
