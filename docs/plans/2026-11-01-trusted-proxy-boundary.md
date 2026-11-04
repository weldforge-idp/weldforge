# Trusted-proxy boundary for the client IP (B-AUTH-1)

**Status:** IMPLEMENTED 2026-11-01
**Backlog:** `docs/security/hardening-backlog.md` B-AUTH-1 (Medium)
**Scope:** `weldforge-auth` only. No infrastructure change is required for the fix
itself; one infrastructure *documentation* change is, because the app's current
safety depends on an edge default that nothing asserts.

---

## 1. What the backlog says, and what is actually true

B-AUTH-1 says the rate limiter keys on a spoofable `X-Forwarded-For`, so an
attacker rotating the header gets a fresh per-IP bucket on every request. The
first half of that was addressed in `78713e7`, which stopped parsing the header
in application code and used `request.getRemoteAddr()` instead, on the stated
grounds that `getRemoteAddr()` "is never client-spoofable".

**That reasoning is wrong as written, and the configuration undermines it.**
`getRemoteAddr()` returns whatever Tomcat's `RemoteIpValve` put there, and
`application.yml` configures the valve with:

```yaml
server.tomcat.remoteip.internal-proxies: ".*"
```

`.*` means *every* hop is a trusted internal proxy. `RemoteIpValve` walks
`X-Forwarded-For` right-to-left and stops at the first entry that is **not** a
trusted proxy; when every entry matches, the loop consumes the whole chain and
leaves `remoteIp` holding the **leftmost** entry — which is precisely the
attacker-controlled token the fix set out to stop using. So, as configured, the
"fix" and the bug resolve to the same value.

Four call sites inherit this: `RateLimitingFilter.clientIp`,
`AuditService` (the `ip_address` column), `AuthService` (the IP stored on
refresh-token rows) and `OidcAuthorizationController`. Three of them carry a
comment asserting the value is not spoofable.

## 2. What is NOT true: it is not exploitable today

Measured against staging on 2026-11-01 before writing this, because the
difference decides how the work is scoped.

Two failed logins were sent to `https://staging.weldforge.org/api/auth/login`,
one carrying `X-Forwarded-For: 203.0.113.77` (TEST-NET-3, unmistakable) and one
with no such header. Both recorded the **real** client address in
`audit_events.ip_address`:

```
196.39.112.56|auth.login.failed|2026-11-01 16:27:07  <- no XFF
196.39.112.56|auth.login.failed|2026-11-01 16:26:24  <- XFF: 203.0.113.77
```

The spoofed value never reached the application. The reason is at the edge:
Traefik runs with neither `forwardedHeaders.trustedIPs` nor
`forwardedHeaders.insecure` on any entrypoint (verified in the deployment's
args), and in that default state it **deletes** inbound `X-Forwarded-*` and
`X-Real-IP` headers from an untrusted peer before its own reverse proxy sets
`X-Forwarded-For` to the real connection address. The same probe also shows
`sso.weldforge.org` is not behind Cloudflare's proxy today — a Cloudflare edge
address would have appeared instead of a residential one.

So the spoof is closed, but it is closed **entirely outside the application**,
by a default that neither repository states or tests.

## 3. Why it is still worth fixing

The app's rate limiting, account lockout, audit trail and refresh-token
provenance all rest on one unasserted edge default. Three realistic, unrelated
changes reopen the hole with nothing in either repository objecting:

1. **Turning on Cloudflare proxying** for `sso.weldforge.org`. The zones are
   already on Cloudflare, and the natural follow-up is to set
   `forwardedHeaders.trustedIPs` to Cloudflare's ranges so the real client IP
   survives — at which point inbound chains are trusted and `.*` accepts the
   leftmost entry.
2. **Any second proxy hop** in front of or beside Traefik.
3. **Exposing the Service directly** (NodePort, port-forward, a mesh sidecar, or
   an in-cluster caller), where there is no edge to strip anything.

Each of those is a reasonable operational change made for an unrelated reason,
by someone who has no cue that it silently converts the rate limiter into a
no-op. That is what makes this worth closing in the app rather than noting.

## 4. The change

**4.1 Narrow the boundary.** Replace `internal-proxies: ".*"` with the actual
one-hop boundary — the private ranges that a pod peer can legitimately occupy —
exposed as `APP_TRUSTED_PROXIES` so an operator can widen it deliberately and
visibly rather than by inheriting a wildcard:

```yaml
internal-proxies: ${APP_TRUSTED_PROXIES:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1|0:0:0:0:0:0:0:1}
```

Traefik's pod sits in `10.42.0.0/24` on this cluster, so it stays trusted and
the scheme/host rewriting that the OIDC issuer depends on is unaffected. A
public address appearing in the chain is now treated as the client and the walk
stops there, so a spoofed prefix is ignored **in the app**, whatever the edge
does.

The existing comment block justifies `.*` with "the GKE Ingress chain hops
through Google's GFE then a NEG" — an environment this cluster left behind. It
is replaced with the k3s/Traefik boundary and a pointer to §3's three ways to
reopen it.

**4.2 Correct the three comments** that claim `getRemoteAddr()` is inherently
unspoofable, to say what is actually true: it is as trustworthy as
`internal-proxies` is narrow.

**4.3 Scheme and host must not regress.** This is the one way the change can
bite: if `internal-proxies` ever fails to match the real peer, the valve stops
rewriting, `request.getScheme()` reverts to `http` and the OIDC issuer,
`authorize`/`token` endpoints and discovery document start advertising
`http://<pod>`. Covered by a test and re-verified on staging before production.

## 5. Tests

| Case | Proves |
|---|---|
| Spoofed single-entry chain from an untrusted peer | A client-supplied `X-Forwarded-For` does not become the remote address |
| `spoofed, realclient` chain from a trusted pod peer | The walk stops at the rightmost non-proxy entry; the prefix is ignored |
| Chain of only private hops | Falls back without throwing |
| `X-Forwarded-Proto: https` from a trusted peer | `getScheme()` is still `https` — the issuer does not regress |
| Rate-limit bucket key under a rotating spoofed header | One bucket, not N — the actual B-AUTH-1 claim, asserted at the filter |
| Audit IP under a spoofed header | `ip_address` records the real peer |

The first four are valve-level and run against a real Tomcat connector in the
integration suite, because `internal-proxies` is connector configuration and a
mocked request cannot see it. The last two are unit tests at the filter and the
audit service.

## 6. Explicitly NOT in this sprint

**The in-memory bucket store.** B-AUTH-1 also asks for buckets to move to the
bucket4j-Redis store "the code already anticipates", because in-memory buckets
are per-instance. A Redis statefulset does exist in the cluster (`redis-0`), so
this is feasible — but `apps/weldforge/base/api-deployment.yaml` pins
`replicas: 1` and says so deliberately, with the per-instance buckets named as
one of the reasons. At one replica the shared store changes no behaviour, and
adding a Redis dependency to the auth service's request path to fix nothing
today is the wrong trade. It stays open in the backlog, as the thing that must
land **before** replicas are raised, not after.

**Per-user lockout keying** is unchanged; it is keyed on the user, not the IP,
and is the existing backstop.

---

## 7. Where the implementation departed from this spec

1. **The fix is narrower than "closed".** §4 implies a spoofed chain can no
   longer choose the client address. That is true for a chain with a real
   client appended — the shape the edge produces when it trusts an inbound
   header — but a **single-entry** chain from a peer inside the private ranges
   is still believed, because the valve cannot tell "a trusted proxy forwarded
   this" from "the peer made it up". Closing that means trusting only Traefik's
   pod address, which changes on every restart. Recorded as an accepted
   residual in the backlog entry rather than quietly implied away.

2. **The `.*` boundary was not the only wrong thing — three comments were.**
   `RateLimitingFilter` asserted outright that "getRemoteAddr() is never
   client-spoofable", and `AuditService`, `AuthService` and
   `OidcAuthorizationController` each said the value was not the spoofable raw
   header. Under `.*` it was exactly that. Each now points at the property that
   decides it, because the next person to touch this will read the comment, not
   the YAML.

3. **An executable rule replaced a documented one.** §5 planned behavioural
   tests only. Two guard tests were added beyond them: one asserting the
   configured boundary is not a wildcard, and one asserting no production file
   reads `X-Forwarded-For` directly — which covers all four call sites and any
   added later. The original defect was a call site parsing the header; a rule
   in a comment would not have caught its return.

4. **The Tomcat harness is shared, not duplicated.** The JUnit test and the
   Gherkin steps drive one `TrustedProxyHarness`, which reads the regex out of
   the shipped `application.yml` and resolves it the way Spring does. Pinning a
   copy of the regex in test code would have let the deployed value drift away
   from the tested one — the exact failure mode that let `.*` survive.

5. **A fix-number collision was found and corrected.** The key-ring sprint
   labelled itself F49, which Sprint 6 already owns (F49–F53). The highest in
   use was F57, so the key ring is **F58** and this work is **F59**.

6. **Nothing was added for the shared bucket store.** See §6; it stays open,
   gated on raising `replicas`.
