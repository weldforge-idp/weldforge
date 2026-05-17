---
name: Deployment pipeline is GitHub Actions, not TeamCity
description: weldforge marketing site + services deploy via GitHub Actions; the TEAMCITY.md / deploy.sh comments referencing TeamCity are stale
type: project
originSessionId: 2c8ec944-2f7f-4c86-a922-6989bb89938b
---
Deployment for this repo runs on **GitHub Actions**, not TeamCity.

**Why:** The user explicitly corrected this on 2026-05-10 — "We are no longer using TeamCity. GitHub Actions takes care of deployment." Several files in tree still reference the old pipeline (e.g., `weldforge-www/TEAMCITY.md`, comments inside `weldforge-www/scripts/deploy.sh` that say "TeamCity uses for weldforge.org"). Those are stale and should not be cited as authoritative.

**How to apply:**
- When suggesting how to ship changes (especially marketing-site `.htaccess`, public/ assets, helm chart updates), point at the GitHub Actions workflow, not TeamCity.
- Do not tell the user "let TeamCity do it" or similar. That was my error on 2026-05-10 before correction.
- Before referencing any deploy mechanism, check `.github/workflows/` for the live workflow file rather than the stale `TEAMCITY.md` / deploy.sh comments.
- If the user wants those stale references cleaned up, the cleanup is a separate task they have not yet asked for — don't preempt it.
