---
name: shared working tree means a shared git index
description: Several Claude sessions work in the infrastructure repo at once; a bare `git commit` sweeps their staged files even after a path-scoped `git add`
metadata:
  node_type: memory
  type: feedback
---

The infrastructure repo (`christiaanwvermaak/cwvermaak_infrastructure`, checked
out at `C:\dev\CWVermaak\Tech\infrastructure`) has **several Claude sessions
working in it simultaneously**. They share one working tree, and therefore one
**index**.

`git add <path>` followed by a bare `git commit` is *not* safe there. The add is
path-scoped; the commit is not — it commits whatever is staged, including files
another session staged seconds earlier. This happened twice on 2026-09-13: a
peer session's KeyCrypt manifest edits landed in a monitoring commit, and its
commit message was lost.

**How to apply:** use a pathspec commit.

```sh
git commit -- <path> [<path>...]
```

It reads those paths from the working tree and ignores the index entirely, so a
concurrent stage cannot ride along. One caveat: a pathspec commit only works on
**tracked** files, so a brand-new file still needs `git add <path>` first — then
commit with the pathspec.

**Why it matters beyond tidiness:** an earlier instance of this swept the
operator's SOPS-encrypted secret file into an unrelated commit. Encrypted, so no
exposure — but it was not mine to commit, and the provenance of someone else's
change was silently rewritten.

Related: [[github_account]] for which account pushes.
