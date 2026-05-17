---
name: Git push needs token-in-URL when multiple gh accounts are logged in
description: gh auth git-credential returns the wrong account's token; push with explicit URL form
type: feedback
originSessionId: 9f38af7d-b118-4b7d-ab14-ea150e67a780
---
When two GitHub accounts are logged in via `gh auth login`, `gh auth git-credential get` resolves to whichever account it picks first — not necessarily the active one. `git push` then fails with "Repository not found" (the misleading mask GitHub returns when the token cannot see a private repo).

Workaround that consistently works:

```
TOKEN=$(gh auth token --user christiaanwvermaak)
git push https://christiaanwvermaak:${TOKEN}@github.com/weldforge-idp/weldforge.git <branch>
```

Setting `git config credential.https://github.com.username christiaanwvermaak` was insufficient on its own.

**Why:** Discovered after multiple "Repository not found" failures during the tenant-branding PR push on 2026-05-04. Root cause: `gh auth git-credential get` returned `cwvermaak-codeinfinity`'s token even after `gh auth switch`.

**How to apply:** If a `git push` to a `weldforge-idp` repo returns "Repository not found", re-issue with the token-in-URL form rather than chasing the credential helper. Don't use `git config --global credential.helper=` overrides — they break other repos.
