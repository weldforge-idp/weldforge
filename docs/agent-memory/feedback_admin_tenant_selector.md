---
name: Admin calls have one tenant selector, which refuses rather than falls back
description: only CrossTenantSelectorFilter changes an admin call's tenant; row-scoped portal screens must name their tenant per call; super-admin flags and the global membership stay equal
type: feedback
---
Which tenant an admin call acts in has exactly **one** answer: the JWT's tenant,
unless `CrossTenantSelectorFilter` switches it on `X-WF-Tenant` (or the legacy alias
`X-Tenant-Slug`) — membership-checked, audited, and **refused** (404/403/400) when it
cannot be honoured. Never add a second path that changes `TenantContext` for admin
calls, and never fall back to the home tenant when a named tenant is unusable. A
request with *no* selector acts at home by design, so the server cannot catch a lost
selector — the portal must name the tenant.

**Why:** on 2026-09-11 a KeyCrypt OIDC client created from the `cwvermaak-tech` row
landed in `default` with a 200. The Tenants page drew one tenant's list under every
row and sent no selector; the backend had a second, unaudited super-admin override
that fell back silently. Fixed in F54 / `docs/cross-tenant-admin-spec.md` §11.

**How to apply:**
- Portal screens drawn under a specific tenant's row pass `forTenant(t.slug)`
  (`core/tenant-selector.ts`) on every call — list, create, update, delete. Don't
  load row-scoped lists once in `ngOnInit`.
- Admin responses carry `X-WF-Acting-Tenant`; the interceptor turns a mismatch into a
  409. Keep new admin endpoints under `/api/admin/**` so they get both.
- "Is super-admin" is `sa OR adm=SUPER_ADMIN`, and cross-tenant reach is the global
  `admin_membership` row. Anything that grants or removes super-admin goes through
  `GlobalSuperAdminMembership` so the two stay equal.
- Don't test cross-tenant writes against production tenants; staging uses `default`.
