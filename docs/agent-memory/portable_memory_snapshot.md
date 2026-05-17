---
name: portable-memory-snapshot
description: Project memory is mirrored into the repo — CLAUDE.md embeds the full notes and auto-loads; docs/agent-memory/ is the per-note mirror
metadata: 
  node_type: memory
  type: reference
  originSessionId: e91dbe85-0918-4ed6-96ef-1ead548c4fc7
---

The machine-local Claude Code memory store (`~/.claude/projects/<path-slug>/memory/`) is path-keyed and does not travel with the project. Two committed, portable copies exist:

- `CLAUDE.md` at the repo root **embeds the full text of every memory note** and auto-loads on any installation — the knowledge is in context with zero setup steps. This is the authoritative copy.
- `docs/agent-memory/` is a verbatim per-note mirror in the memory-tool on-disk format, used only to optionally re-seed the live store on a new machine.

**Why:** copying or cloning the project otherwise loses every memory; embedding the content in the auto-loaded `CLAUDE.md` makes it portable with no manual step.

**How to apply:** whenever memories change, update `CLAUDE.md` (authoritative) AND the matching file under `docs/agent-memory/` so all copies stay in sync. Re-seeding the live memory tool is optional — see the PowerShell command in `CLAUDE.md`.
