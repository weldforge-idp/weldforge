# Spec: Cross-Tenant Admin Membership & Global Scope

**Status:** Draft / proposed — not yet implemented
**Author:** drafted 2026-05-15
**Affects:** `weldforge-auth` (backend), `weldforge-admin-portal`, agent/LLM docs

---

## 1. Context

WeldForge's admin authorization is currently **single-tenant per identity**. This
spec introduces a many-to-many *admin membership* model so one admin person can
administer several tenants, plus an explicit **global scope** for platform-wide
administration.

## 2. Current model and its limitation

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

Admin write endpoints gain an **explicit, optional** target tenant. Recommended:
a request header `X-WF-Tenant: <slug>` (falls back to the caller's own tenant when
absent). The chosen tenant is resolved, then `effectiveRole` is checked against it.
`TenantAccessor.resolveCrossTenant` is finally wired up to back this.

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
- Every cross-tenant action emits an audit event recording actor, target tenant,
  and the membership that authorised it.

## 7. Security considerations

- Tenant isolation stays the **default**: with no membership row, a caller reaches
  exactly one tenant. Cross-tenant reach is opt-in, per-row, and audited.
- No tenant is ever "magic". Removing the `"default"`-is-global mental model is a
  deliberate part of this spec.
- Global membership is the highest-value credential in the system — grant flow is
  `SUPER_ADMIN`-global-gated, self-escalation-proof, and audit-logged.
- The April 2026 security audit's tenant-isolation findings remain satisfied: every
  tenant-scoped query still filters by the *resolved* `tenantId`.

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
