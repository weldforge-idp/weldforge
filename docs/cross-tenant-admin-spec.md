# Spec: Cross-Tenant Admin Membership & Global Scope

**Status:** Implemented (phases 1-3, 5) — 2026-05-17. Phase 4 (membership
management API + admin-portal UI) and phase 7 (drop legacy `users.admin_role` /
`is_super_admin`) remain. See §10.
**Author:** drafted 2026-05-15
**Affects:** `weldforge-auth` (backend), `weldforge-admin-portal`, agent/LLM docs

---

## 1. Context

WeldForge's admin authorization is currently **single-tenant per identity**. This
spec introduces a many-to-many *admin membership* model so one admin person can
administer several tenants, plus an explicit **global scope** for platform-wide
administration.

## 2. Current model and its limitation

> **Historical (resolved).** This section describes the pre-implementation state
> and motivates the design. The limitations below were addressed — see §10
> (Implementation notes). In the live code, `resolveCrossTenant`/`canCrossTenants`
> no longer exist; cross-tenant switching is done via `TenantAccessor.switchToTenant`
> driven by `CrossTenantSelectorFilter` (the `X-WF-Tenant` header), and admin-role
> assignment is tenant-scoped (see §6.4).

- `User` belongs to **exactly one** tenant (`users.tenant_id`, `NOT NULL`).
- `User.adminRole` (`AdminRole` enum: `NONE` / `READ_ONLY` / `TENANT_ADMIN` /
  `SUPER_ADMIN`) is a **single** role that applies only to that one tenant.
- `TenantContext` carries one resolved `(tenantId, adminRole)` per request.
- Service-account tokens (`wf_svc_*`) are bound to exactly one tenant.

**The limitation.** Admin-console *write* endpoints — `POST /api/admin/users/invite`,
`POST /api/admin/oidc/clients`, `POST /api/admin/service-accounts` — all resolve the
target tenant via `TenantAccessor.requireTenant()`, i.e. the **caller's own tenant**.
They never accept a target tenant.

Two consequences worth correcting:

1. `AdminRole.SUPER_ADMIN`'s Javadoc claims *"Unrestricted access across every
   tenant"* — this is **inaccurate**. A `SUPER_ADMIN` can list any tenant and
   create/delete tenants, but cannot create a user/client/service-account inside
   another tenant.
2. `TenantAccessor.resolveCrossTenant(Long)` and `AdminRole.canCrossTenants()` are
   the designed hooks for cross-tenant operations — but both are **dead code**,
   wired into nothing.

There is **no "global" tenant.** The slug `"default"` is only the fallback used by
`TenantResolverFilter` for public requests that carry no tenant; it grants no
cross-tenant authority.

## 3. Goals

1. An admin user can hold admin rights in **many tenants**, with a **different
   role per tenant** (and in some tenants, none).
2. A first-class **global scope**: an admin whose role applies to *every* tenant,
   present and future — for platform operators.
3. Cross-tenant authority is **explicit and audited**, never implied by a tenant's
   name. Tenant isolation remains the default and the security baseline.
4. Backward compatible: existing single-tenant admins keep working unchanged.

## 4. Proposed data model

A new link table separates **identity** (which tenant a user record lives in —
unchanged) from **admin reach** (which tenants a user may administer — new).

```sql
CREATE TABLE admin_membership (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- NULL tenant_id == GLOBAL scope: the role applies to every tenant.
    tenant_id   BIGINT REFERENCES tenant(id) ON DELETE CASCADE,
    admin_role  VARCHAR(32) NOT NULL,          -- READ_ONLY | TENANT_ADMIN | SUPER_ADMIN
    granted_by  BIGINT REFERENCES users(id),
    granted_at  TIMESTAMP NOT NULL DEFAULT now(),
    CONSTRAINT uq_admin_membership UNIQUE (user_id, tenant_id)
);
-- One global row per user; Postgres treats NULLs as distinct, so enforce with:
CREATE UNIQUE INDEX uq_admin_membership_global
    ON admin_membership (user_id) WHERE tenant_id IS NULL;
```

- A row with `tenant_id = NULL` is a **global membership** — its role applies to
  all tenants, including ones created later.
- A row with a concrete `tenant_id` is a **per-tenant membership**.
- `admin_role` reuses the existing `AdminRole` enum, minus `NONE` (absence of a row
  *is* `NONE`). `SUPER_ADMIN` is only meaningful on a global row.

`users.tenant_id` (home tenant) and `users.admin_role` are **not removed** by this
spec — see §8.

## 5. Authorization rules

For a request targeting tenant `T`, the caller's **effective role** is:

```
effectiveRole(user, T) = max(
    role of the user's membership for T        (if any),
    role of the user's GLOBAL membership        (if any)
)
```

with ordering `NONE < READ_ONLY < TENANT_ADMIN < SUPER_ADMIN`.

| Capability                                   | Required effective role on T |
|-----------------------------------------------|------------------------------|
| Read admin console for T                      | `READ_ONLY`                  |
| Create/update users, clients, etc. within T   | `TENANT_ADMIN`               |
| Create / delete tenants, assign memberships    | `SUPER_ADMIN` **global**     |

`SUPER_ADMIN` is **only** honoured on a global membership. A per-tenant
`SUPER_ADMIN` row is rejected at write time and treated as `TENANT_ADMIN` if
encountered.

## 6. API changes

### 6.1 Target-tenant selector

Admin write endpoints gain an **explicit, optional** target tenant: the request
header `X-WF-Tenant: <slug>`. Absent, the call acts in the caller's own (JWT)
tenant. Present, the tenant is resolved and `effectiveRole` is checked against
it; a selector that cannot be honoured is **refused** (404 unknown tenant, 403 no
membership) -- never quietly run in the home tenant instead. Every admin
response carries `X-WF-Acting-Tenant: <slug>` naming the tenant it ran in. See §11.

Affected: `POST /api/admin/users/invite`, `POST /api/admin/oidc/clients`,
`POST /api/admin/service-accounts`, and the other `/api/admin/**` writes.

### 6.2 Membership management endpoints (new)

```
GET    /api/admin/users/{id}/memberships          list a user's memberships
POST   /api/admin/users/{id}/memberships          grant   {tenantId|null, adminRole}
DELETE /api/admin/users/{id}/memberships/{mid}     revoke
```

Granting/revoking requires `SUPER_ADMIN` global scope. Granting a **global**
membership requires the caller to already hold one (no privilege escalation).

### 6.3 Token / context changes

- `TenantContext` keeps one *active* `(tenantId, adminRole)` per request — the
  resolved target — but the role is now derived from `effectiveRole`, not read
  straight off the token/user.
- `wf_svc_*` service accounts may also be granted a global membership; a global
  service account can target any tenant via `X-WF-Tenant`.
- Every cross-tenant switch is audited: `admin.cross_tenant.access` on success
  (actor, target tenant, the selector channel used), `admin.cross_tenant.denied`
  on refusal — see §7.

### 6.4 Admin-role assignment is tenant-scoped (shipped)

`POST /api/admin/users/{id}/admin-role` (SUPER_ADMIN-gated, `AdminService.setAdminRole`)
resolves the target user via `findByIdAndTenantId(userId, resolvedTenantId)`, where the
resolved tenant honours the `X-WF-Tenant` selector. A super-admin therefore cannot mutate
a role in tenant B without first performing the audited `X-WF-Tenant` switch to B — closing
a path that would otherwise grant cross-tenant role changes with **no**
`admin.cross_tenant.access` record (the prior implementation used an unscoped `findById`).
The mutation bumps `token_version` so the change takes effect on the target's next request,
and emits an `admin.role.assigned` audit event carrying the target tenant slug.
Since 2026-09-11 it also keeps the **global `SUPER_ADMIN` membership** in step
(`GlobalSuperAdminMembership.sync`): granting `SUPER_ADMIN` grants the row, any
other role revokes it — so a demoted super-admin loses cross-tenant reach at once.

## 7. Security considerations

- Tenant isolation stays the **default**: with no membership row, a caller reaches
  exactly one tenant. Cross-tenant reach is opt-in, per-row, and audited.
- No tenant is ever "magic". Removing the `"default"`-is-global mental model is a
  deliberate part of this spec.
- Global membership is the highest-value credential in the system — grant flow is
  `SUPER_ADMIN`-global-gated, self-escalation-proof, and audit-logged.
- The April 2026 security audit's tenant-isolation findings remain satisfied: every
  tenant-scoped query still filters by the *resolved* `tenantId` (including
  `setAdminRole`, hardened in 2026-06 — see §6.4).
- **Failed cross-tenant switch auditing (shipped).** `CrossTenantSelectorFilter` audits
  both outcomes: a successful switch emits `admin.cross_tenant.access` (SUCCESS), and a
  refused one emits `admin.cross_tenant.denied` (DENIED, with reason `unknown_tenant` for a
  404 probe, `no_membership` for a 403, `conflicting_selectors` for a 400). Cross-tenant
  access *attempts* are therefore visible to a SOC (`B-TEN-2`, fixed).
- **One selector, no silent fallback (2026-09-11).** `CrossTenantSelectorFilter` is the
  only code that changes an admin call's tenant. The former super-admin
  `X-Tenant-Slug` override in `JwtAuthenticationFilter` is gone — see §11.

## 8. Migration & backward compatibility

`V<next>__admin_membership.sql`:

1. Create the `admin_membership` table (§4).
2. For every `users` row with `admin_role <> 'NONE'` **and** `is_super_admin = false`
   → insert a per-tenant membership `(user_id, users.tenant_id, admin_role)`.
3. For every `users` row with `is_super_admin = true` (or `admin_role = 'SUPER_ADMIN'`)
   → insert a **global** membership `(user_id, NULL, 'SUPER_ADMIN')`.

`users.admin_role` / `users.is_super_admin` are kept for one release as
**read-only, derived** values (back-compat for any consumer) and removed in a
follow-up migration once all callers read from `admin_membership`.

## 9. Implementation phases (separate work — not in this spec)

1. Schema + `AdminMembership` entity + repository + migration.
2. `effectiveRole` resolution in `TenantAccessor`; wire `resolveCrossTenant`.
3. `X-WF-Tenant` selector on `/api/admin/**` writes.
4. Membership management endpoints + admin-portal UI.
5. Audit events; fix `AdminRole.SUPER_ADMIN` Javadoc; remove dead `canCrossTenants`.
6. Update agent/LLM docs (`agents.html`, `ai-manifest.json`, `llms.txt`).
7. Drop `users.admin_role` / `is_super_admin` in a later migration.

Each phase ships with Cucumber BDD scenarios per the repo convention.

## 10. Implementation notes (2026-05-17)

Phases 1-3 and 5 are implemented in `weldforge-auth`:

- **`V34__admin_membership.sql`** creates the table and seeds it per §8 —
  tenant-scoped admins get a per-tenant row, super admins a single global row.
- **`TenantAccessor.effectiveRole(targetTenantId)`** computes the max of the
  caller's home-tenant role and their membership rows, per §5 (a per-tenant
  `SUPER_ADMIN` row is downgraded to `TENANT_ADMIN`).
- **`X-WF-Tenant: <slug>`** — `CrossTenantSelectorFilter` resolves the header on
  `/api/admin/**`, rebinds `TenantContext` through `TenantAccessor.switchToTenant`,
  and emits an `admin.cross_tenant.access` audit event. The dead
  `resolveCrossTenant` is replaced by `switchToTenant`; the dead
  `AdminRole.canCrossTenants()` is removed; the `SUPER_ADMIN` Javadoc is corrected.

Two deviations from the draft, each resolving an internal gap:

- **Service accounts.** §4's table is `user_id`-keyed and cannot hold a
  service-account row, yet §6.3 wants service accounts to have global reach.
  Resolved without a schema change: a `SUPER_ADMIN` service-account token is a
  platform-operator credential and is treated as global; a `TENANT_ADMIN` /
  `READ_ONLY` service account stays confined to its home tenant. No
  service-account membership rows exist.
- **Phase 4 deferred.** The membership-management endpoints (§6.2) and admin-portal
  UI are not built yet; memberships are currently created only by the V34 seed.
  Granting a *new* cross-tenant membership to a human admin still needs phase 4.

## 11. Incident fix: one audited selector, refuse don't fall back (2026-09-11)

**What happened.** A super-admin created an OIDC client for `cwvermaak-tech` from
the portal's Tenants page; it landed in `default` (the home tenant) with a 200.
Two defects combined:

1. *Portal.* The Tenants page listed OIDC clients / SAML SPs **once**, for
   whatever tenant the request context resolved to, and drew that one list under
   every row. The row's create button ignored its row (`createOidcClient(_t)`),
   and the picker's selector came from a memoising `computed()` over a non-signal
   (`isSuperAdmin()` reads localStorage) that could stay `null` for the life of
   the page. The create went out with **no** tenant selector.
2. *Backend.* A missing selector is indistinguishable from "act at home", and there
   were two selector channels: this spec's `X-WF-Tenant` (membership-checked,
   audited) and a super-admin `X-Tenant-Slug` override in `JwtAuthenticationFilter`
   (eligibility from the `sa` claim, no audit, **silent fallback to the home tenant
   for an unknown slug**). Production's `admin_membership` table was also empty —
   the only super-admin was promoted after the V34 seed ran — so `X-WF-Tenant`
   refused them outright.

**Fix.**

- `JwtAuthenticationFilter` no longer changes tenant for anyone: the JWT's tenant
  is the request's tenant. The anti-spoofing invariant is unchanged —
  non-super-admins still cannot change tenant via headers.
- `CrossTenantSelectorFilter` is the single selector. It still reads `X-WF-Tenant`,
  and for authenticated `/api/admin/**` calls also honours `X-Tenant-Slug` as a
  **legacy alias** under exactly the same rules (membership check, audit, refusal),
  so older clients keep working and nothing takes the old silent path. Both headers
  present and disagreeing → 400 `tenant_selector_conflict`. Audit metadata records
  which channel (`selector`) was used.
- Refusals are problem documents: 404 `unknown_tenant`, 403 `tenant_access_denied`
  ("the request was NOT run in your home tenant instead"), each audited.
- Every successful admin response carries `X-WF-Acting-Tenant` (exposed via CORS).
  The portal interceptor turns a response from any tenant other than the one it
  named into a 409 `tenant_mismatch`, so a misdirected write can never render as
  a success.
- **One definition of super-admin.** A super-admin is `is_super_admin OR
  admin_role = SUPER_ADMIN` (the JWT `sa`/`adm` claims — what the portal gates the
  picker on), and cross-tenant reach is the global membership. They are kept equal:
  `V57__backfill_global_super_admin_membership.sql` back-fills the row for every
  flagged super-admin, and `SuperAdminBootstrap` and `setAdminRole` both go through
  `GlobalSuperAdminMembership`. V57 grants no authority the flags did not already
  claim; it makes the backend honour what the portal already showed.
- Portal: the Tenants page is row-scoped — OIDC clients and SAML SPs load when a
  row is expanded and every list/create/update/rotate/delete names that row's
  tenant (`forTenant(t.slug)` → `X-WF-Tenant`), regardless of the picker. The
  picker's `outgoingSlug` is a plain method. Non-admin `/api/**` calls no longer
  carry the picker at all. The OIDC form gained a `clientId` field and a
  public-client toggle.
- Admin OIDC client create / rotate-secret / delete are now audited
  (`oidc.client.create`, `oidc.client.rotate_secret`, `oidc.client.delete`).

Tests: `AdminTenantSelectorIntegrationTest` (Testcontainers, real filter chain —
unentitled 403 on both headers, `sa` flag alone refused, unknown tenant 404, an
entitled client lands in the target and `/authorize` agrees, role change moves
reach), `CrossTenantSelectorFilterTest`, `GlobalSuperAdminMembershipTest`, and the
portal's `tenant.interceptor.spec.ts`, `tenant-picker.service.spec.ts`,
`tenants.component.spec.ts`.
