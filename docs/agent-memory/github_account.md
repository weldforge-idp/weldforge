---
name: GitHub account for weldforge work
description: christiaanwvermaak is the right account for weldforge-idp/weldforge — the other gh-logged-in account cannot see this private repo
type: user
originSessionId: 9f38af7d-b118-4b7d-ab14-ea150e67a780
---
User: `christiaanwvermaak` <christiaan.vermaak@outlook.com>. Admin on the `weldforge-idp` GitHub org, which owns the private repo `weldforge-idp/weldforge`.

The other gh-logged-in account on this machine (`cwvermaak-codeinfinity`) is **not** a member of `weldforge-idp` and gets "Repository not found" when accessing the repo. `gh` periodically reverts the active account to `cwvermaak-codeinfinity` between shell invocations — re-run `gh auth switch --user christiaanwvermaak` if `gh` calls fail unexpectedly.

Local git author config is already set to `christiaanwvermaak <christiaan.vermaak@outlook.com>`.
