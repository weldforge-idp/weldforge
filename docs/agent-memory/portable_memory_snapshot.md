---
name: portable-memory-snapshot
description: Project memory is mirrored into the repo at docs/agent-memory/ + CLAUDE.md so it survives a copy/clone to another machine
metadata: 
  node_type: memory
  type: reference
  originSessionId: e91dbe85-0918-4ed6-96ef-1ead548c4fc7
---

The machine-local Claude Code memory store (`~/.claude/projects/<path-slug>/memory/`) is path-keyed and does not travel with the project. A verbatim mirror is committed in the repo at `docs/agent-memory/`, and `CLAUDE.md` at the repo root bootstraps it — `CLAUDE.md` auto-loads on any installation, carries the memory index, and documents re-seeding.

**Why:** copying or cloning the project to another machine otherwise loses every memory; the in-repo mirror makes the knowledge portable.

**How to apply:** whenever memories change, also update the copy under `docs/agent-memory/` and the index in `CLAUDE.md` so the snapshot stays current. To re-seed a fresh installation's live store, copy `docs/agent-memory/*.md` into `~/.claude/projects/<slug>/memory/` (see the command in `CLAUDE.md`).
