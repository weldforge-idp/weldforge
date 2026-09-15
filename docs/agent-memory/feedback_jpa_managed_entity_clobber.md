---
name: a dirty JPA entity silently overwrites other transactions
description: Mutating a managed entity flushes EVERY column from a load-time snapshot, so it can undo a concurrent write — this silently defeated refresh-token reuse containment
metadata:
  node_type: memory
  type: feedback
---

When a Hibernate-managed entity is mutated, the commit flush writes **every
column** from the snapshot taken when the row was loaded — not just the fields
that changed. Anything another transaction wrote to that row in between is
overwritten with the stale value.

**Why it matters here, concretely.** `RefreshTokenService.rotate` loaded the
token row, then called `setUsedAt` and `setReplacedBy` on it. A concurrent reuse
sweep that revoked the family in between was undone: the winner's commit wrote
back `revoked_at = null`. The containment ran, wrote an audit event asserting
success, and was then quietly reverted — the worst possible failure mode, since
the log says the control worked.

It predated the 2026-09-15 atomic-claim work by a long way and was invisible
until a concurrency test raced the two paths. Sequential tests cannot see it.

**How to apply.**

- In any path where another transaction may be revoking, expiring or otherwise
  mutating the same row, do **not** mutate the managed entity. Use a targeted
  `@Modifying` update that names only the column you mean to change — see
  `RefreshTokenRepository.claim` and `markReplacedBy`.
- Be suspicious of a bulk `@Modifying` update followed by further work on the
  same entity in one transaction: the update bypasses the persistence context,
  so the in-memory row is now stale, and any later dirty flush reverts it.
- `@DynamicUpdate` narrows the flush to changed columns and would also have
  prevented this, but it is a per-entity opt-in that is easy to forget on the
  next entity. Explicit targeted updates say what they mean.

**Related trap in the tests.** Mockito answers an unstubbed `int` with `0`.
Repository methods whose contract is "rows affected" therefore default to
"nobody won", which these services read — correctly — as "already spent". Every
mock of `RefreshTokenRepository` or `OAuthAuthorizationCodeRepository` must stub
`claim()`, or every rotation in that suite silently becomes a reuse detection.

See [[session_2026_09_14]] and `docs/security/review-2026-09-14.md`.
