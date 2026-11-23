# Login capacity for bursts (WF-20)

**Status:** plan, 2026-11-23. No code change — this records the numbers and the
decision to take *before* onboarding a large tenant.

Related: `docs/scaling.md` (infrastructure repo), and the scaling notes in
`CLAUDE.md` (ShedLock, the per-instance rate limiter).

---

## 1. The one number that matters

A login is **CPU-bound on BCrypt**, cost factor 12
(`PasswordEncoderConfig`, SEC-06). Everything else in the request — the user
lookup, the token mint — is noise beside it, and since WF-17 the request does
**not** hold a database connection while it hashes (WF-19 did the same for
registration), so the connection pool is not the limit. A single vCPU is.

Measured in production: **~345 ms per login**. One pod with one usable core
therefore serves

```
1 / 0.345 s  ≈  2.9 logins per second, sustained
```

and no faster, however large the pool or the heap — BCrypt at cost 12 simply
costs that much CPU, by design. Concurrency above one hash per core does not
raise throughput; it just queues, so p95 climbs under load rather than
capacity rising.

Current volume is **~12 logins in the past week** (single digits per day across
every tenant) — roughly five orders of magnitude below one pod's capacity. The
question is not today; it is the first large tenant.

## 2. What a "large tenant" costs

The spike that matters is the correlated one — a Monday-morning or
start-of-shift login rush, not the daily average. A rough sizing:

| Tenant active users | Fraction logging in within 10 min | Peak logins/sec | Pods needed at 2.9/s |
|---|---|---|---|
| 1,000 | 30% | 0.5 | 1 |
| 5,000 | 30% | 2.5 | 1 (no headroom) |
| 10,000 | 30% | 5.0 | 2 |
| 25,000 | 40% | 16.7 | 6 |

Formula: `peak_logins_per_sec = active_users × burst_fraction / burst_window_s`,
then `pods = ceil(peak_logins_per_sec / 2.9 × headroom)`, headroom ≈ 1.5.

These are order-of-magnitude; replace `burst_fraction` and `burst_window_s`
with the real tenant's pattern before committing pod counts.

## 3. Decision: scale by replicas, not by weakening BCrypt

Three levers, and only one is right:

- **Lower the BCrypt cost** — rejected. Cost 12 is the security floor
  (SEC-06); throughput is not a reason to make stolen hashes cheaper to crack.
- **Give each pod a full core** — necessary, not sufficient. Confirm the `api`
  container's CPU limit lets it burst to a whole core during a spike; a pod
  throttled to a fraction serves proportionally fewer than 2.9 logins/s. (CPU
  requests/limits live in the infra overlay, not here.)
- **Add replicas** — the right lever. Each added pod adds ~2.9 logins/s.
  Horizontal scaling is already safe: ShedLock leases the `@Scheduled` jobs so
  only one instance runs them (V58), and the request path is stateless.

### The caveat that has to be handled first

**The rate limiter is per-instance.** Each pod holds its own Bucket4j buckets
in memory, so with *N* replicas a single IP gets *N ×* the configured limit:
login 10 / 15 min becomes 10N, register 5 / 60 min becomes 5N, MFA-verify
15 / 15 min becomes 15N (`RateLimitProperties`). That is a correctness problem,
not a capacity one, and it must be settled before raising the replica count for
a tenant that relies on the limit:

- either **move the buckets to Redis** (one shared limit across pods), or
- **divide the configured limits by the replica count** and accept the
  coarseness.

Until then, two replicas already double every per-IP auth limit.

## 4. Operational

- **Watch** `sso_auth_login_total` (rate) and login p95. One pod is healthy to
  roughly 2.9 logins/s; alert as the sustained rate crosses ~2/s/pod, which is
  the point to add a replica (and to have settled §3's caveat).
- **HPA is deliberately off** (`docs/scaling.md`). If login spikes become
  regular, an HPA on CPU is the natural fit — but only after the rate-limiter
  buckets are shared, or every scale-up loosens the per-IP limits.
- **Onboarding a large tenant** is therefore a three-step checklist: size pods
  from §2, confirm the per-pod CPU limit allows a full core, and resolve the
  per-instance rate-limiter caveat (Redis or divided limits).

## 5. Not doing now, and why

No code changes. Volume is five orders of magnitude below capacity, so there is
nothing to tune yet; the value here is that the number (2.9 logins/s/core) and
the rate-limiter caveat are written down before a sales conversation turns into
a deploy. Revisit when a tenant of 5,000+ correlated users is actually in view.
