---
name: tenant-tech-metropolis-trio
description: Tech Metropolis is the most active WeldForge tenant; all three of its customer-facing apps share the `techmetropolis` tenant for cross-app SSO and verify HS512 tokens with a shared secret
metadata:
  node_type: memory
  type: reference
  originSessionId: pr-39
---

WeldForge serves several adopter tenants; the most active is the
`techmetropolis` tenant (id 6). **All three Tech Metropolis customer-facing
apps share this one tenant** so a user signed into any one of them is
signed into the others (cross-app SSO via the shared token). The
relevant repos live elsewhere; cross-app architecture is at
`christiaanwvermaak/tech-metropolis-docs`.

| Component | Repo | Talks to WeldForge how? |
|---|---|---|
| Safe Space backend | `christiaanwvermaak/safe_space_backend` | Legacy JSON proxy (`/api/auth/*` with `X-Tenant-Slug: techmetropolis`); HS512 token verification with shared HMAC. |
| Krusty backend | `christiaanwvermaak/krusty-api` | Same pattern as Safe Space. |
| Commons microservice | `christiaanwvermaak/tech-metropolis-commons-api` | Same — verifies tokens issued for the same tenant. |
| WeldForge tenant | tenant slug **`techmetropolis`** (id 6) | |

**Shared HMAC.** The platform-wide JWT secret (`app.jwt.secret` here) is
mirrored to each consumer's `WELDFORGE_JWT_SECRET` env via GCP Secret
Manager `wf-jwt-secret`. Rotating it requires rotating every consumer at
the same time, since they all verify with the same key. Treat
`wf-jwt-secret` rotation as a coordinated change, not a unilateral one.

**Known consumer-side bug to flag if touched.** Failed-login audit +
lockout-counter writes happen inside `AuthService.login`'s
`@Transactional`; the `BadCredentialsException` rolls them back. Result:
failed logins are not audited and account lockout never engages. The
intended fix is `REQUIRES_NEW` on the audit/lockout writes — out of
scope for `weldforge-auth` itself but planned. If you touch
`AuthService.login` for any other reason, this is the right time.

**How to apply:**
- Any change to `app.jwt.secret`, JWT algorithm (`HS512`), or the
  `tenant` / `tid` / `sub` claims must be coordinated with all three
  Tech Metropolis consumer repos.
- Any change to `/api/auth/login` request/response shape — particularly
  the `X-Tenant-Slug` header behaviour or the JSON body of
  `LoginRequestDto` / `AuthResponseDto` — likewise needs cross-repo
  coordination because the consumers proxy this surface.
- The per-tenant subdomain work shipped in #32–#37 (see
  `docs/auth-url-spec.md`) doesn't reach these consumers — they proxy
  `/api/auth/*` server-side and stamp `X-Tenant-Slug: techmetropolis`
  themselves, so they bypass the Host-header resolver. The TechMetropolis
  heads-up draft in `/tmp/wf-techmetropolis-update.md` is held until the
  wildcard DNS+TLS is live on `*.sso.weldforge.org` (runbook in
  `docs/runbooks/wildcard-tls-setup.md`).
