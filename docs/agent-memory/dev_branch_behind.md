---
name: origin/dev branch behind main
description: dev branch has drifted far behind main; fast-forward when user gives go-ahead
type: project
originSessionId: 9f38af7d-b118-4b7d-ab14-ea150e67a780
---

As of 2026-05-23, `origin/dev` is **61 commits behind `origin/main`** (PRs #27–#39 have all landed on main without dev being updated). The drift has compounded: 1 commit on 2026-05-04 → 25 on 2026-05-14 → 61 on 2026-05-23. Each session that ships another PR adds another commit to the gap.

The user has flagged sync `dev` → `main` as a pending follow-up but kept deferring it because there's always more in-flight work. **Don't auto-execute.** Confirm before pushing — `dev` may still be intentionally pinned (waiting for a release marker, a quiet window for an external observer, etc.). Re-check the count with `git rev-list --count origin/main ^origin/dev` before quoting it.

Concrete command when ready: `git push origin main:dev` (fast-forward — main is strictly ahead). If branch protection blocks the direct push, open a no-op PR.

**Why:** Future feature branches should branch off a current `dev`. Letting it drift further makes that more painful. Also: someone external looking at `dev` as the integration branch will see weeks-old state.
