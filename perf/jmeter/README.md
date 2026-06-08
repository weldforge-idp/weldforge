# WeldForge — JMeter non-functional test suite

Load, performance, spike, and security test plans for the `weldforge-auth`
backend, plus a runner and a seed script.

> ⚠️ **Local only.** Every plan defaults to `http://localhost:8076` (the
> docker-compose app). **Never** point them at `sso.weldforge.org` or any
> shared host — load/spike/security traffic against production is an attack.
> `run.ps1` refuses any host matching `weldforge.org`.

## Prerequisites

1. **App running locally via Docker** (from `weldforge-auth/`):
   ```pwsh
   docker compose up -d --build        # app on :8076, Postgres on :5437
   curl http://localhost:8076/t/leap/.well-known/openid-configuration
   ```
   A fresh DB runs all Flyway migrations, so the `leap` (public demo) and
   `default` tenants exist with working signing keys.
2. **JMeter** at `C:\dev\tools\jmeter` (Java 25 already on PATH).
3. For the **auth-based** probes (login throughput, lockout, rate-limit on a
   real account), seed users first:
   ```pwsh
   ./seed.ps1 -Tenant leap
   ```

## Running

```pwsh
./run.ps1 -Plan 02-performance-baseline          # baseline first, always
./run.ps1 -Plan 01-load -P @{ threads = 100; duration = 300 }
./run.ps1 -Plan 03-spike -P @{ spike_threads = 500 }
./run.ps1 -Plan 04-security
```

Each run writes a timestamped folder under `results/` with the raw `.jtl` and a
full **HTML dashboard** (`report/index.html`). While a run is in flight, scrape
server-side metrics for the other half of the story:

```pwsh
curl http://localhost:8076/actuator/prometheus | Select-String 'http_server_requests|hikaricp|jvm_memory_used|process_cpu'
```

## The plans

| Plan | Type | Shape | Targets |
|---|---|---|---|
| `01-load.jmx` | **Load** | N users, ramp, hold (default 50 / 30s / 180s) | OIDC discovery, JWKS, SAML metadata (the issuer read paths) |
| `02-performance-baseline.jmx` | **Performance** | Light load (5 users) + per-endpoint latency SLAs (Duration Assertions) | health, discovery, JWKS, SAML metadata |
| `03-spike.jmx` | **Spike** | Steady baseline + a sudden burst (default 300 users in 5s) then recovery | JWKS (baseline), SAML metadata (spike — CPU-heavy XML signing) |
| `04-security.jmx` | **Security** | Single-threaded functional checks | authn-bypass, JWT tampering (tampered + `alg:none`), SQLi/XSS payloads, content-type guard (415), method-not-allowed (405), missing-params (400 not 500), user-enumeration resistance, security headers, rate-limit probe |

### Why these targets
The issuer **read** paths are unauthenticated, deterministic, and span the real
cost curve: discovery is cheap (URL assembly), JWKS is moderate (RSA→JWK
encode), and **SAML metadata is CPU-heavy (XML signing)** — the best single
endpoint for finding the CPU ceiling. The `04-security` plan exercises the
write/auth paths where the security controls live.

### Tunable properties (`-J` / `-P @{}`)
`host`, `port`, `scheme`, `tenant`, `threads`, `rampup`, `duration`,
`baseline_threads`, `spike_threads`, `spike_rampup`, `spike_duration`,
`spike_delay`, `total_duration`, and the `sla_*` thresholds in the baseline plan.

## Gotchas that will skew results if ignored

- **Rate limiting is ON by default** (`login` 10 / 15 min, `register` 5 / 60 min,
  per identity). A naive load test against `/api/auth/login` mostly measures the
  Bucket4j limiter (429s), not the app. For a *throughput* baseline of the auth
  path, restart the app with `APP_RATE_LIMIT_ENABLED=false`. For *security*
  testing, leave it on — the `04` plan's rate-limit probe expects 429s.
- **BCrypt cost 12** makes every real login/register ~hundreds of ms of CPU by
  design. That dominates auth-path latency — it's a feature, not a regression.
- **Account lockout** = 5 bad attempts / 15 min. The lockout and rate-limit
  probes will trip each other; run them deliberately, not back-to-back.
- **JWT access tokens live 5 min** locally (`JWT_EXPIRATION_MS`); long soak runs
  reusing one token will start getting 401s — re-login per iteration.

## Non-functional testing coverage — and what's NOT covered here

This suite covers **load, performance, spike, and security**. The other ISO/IEC
25010-style non-functional dimensions worth a plan (not in this suite) are:

- **Stress** — push past capacity to find the breaking point & failure mode.
- **Soak / endurance** — hours at steady load to surface memory leaks, DB
  connection-pool exhaustion (HikariCP), and signing-key cache growth.
- **Scalability** — does throughput scale with replicas / the GKE HPA?
- **Volume** — behaviour with large data: thousands of tenants, large JWKS,
  huge audit-log tables, big SCIM bulk operations.
- **Capacity / headroom** — max sustainable RPS at the latency SLA.
- **Resilience / failover / chaos** — pod kill, DB failover, and the
  Resilience4j circuit breakers (webhook/twilio/smtp/upstream-idp/crm) opening.
- **Recovery** — graceful-shutdown draining, restart, backup/restore (DR).
- **Configuration / compatibility** — protocol conformance: run an actual
  **OIDC/SAML conformance suite** against the hand-rolled issuer.
- **Observability validation** — confirm metrics/alerts actually fire under load.
- **Accessibility (a11y)** — for the admin portal / auth screens (WCAG).
- **Compliance / data-residency** — POPIA (africa-south1) / GDPR posture.

See the parent task notes for the recommended order (stress + soak next).
