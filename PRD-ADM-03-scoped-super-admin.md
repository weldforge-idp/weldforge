# PRD ADM-03 — Scoped super-admin

**Status:** proposed, not yet implemented
**Captured:** 2026-05-07
**Related:** ADM-02 (admin-console RBAC — `NONE` / `READ_ONLY` / `TENANT_ADMIN` / `SUPER_ADMIN`)

## Background

The current `AdminRole` enum has exactly two reach-levels:

- `TENANT_ADMIN` — write inside one tenant (the user's own).
- `SUPER_ADMIN` — write across **every** tenant, plus the cross-tenant
  capabilities (create/delete tenants, assign admin roles, list users
  globally, read every tenant's audit log).

There is no way to grant the `SUPER_ADMIN` capability set against a
**subset** of tenants. In multi-customer deployments this is a real gap:
delegated platform operators (e.g. a partner running operations for two
named tenants) need cross-tenant primitives but should not see every
other customer's data.

## Requirement

Allow a user with `admin_role = SUPER_ADMIN` to be optionally restricted
to a **named set of tenants**. Empty set = unrestricted (current
behaviour, back-compat).

### Functional requirements

1. **Scope storage.** A new join entity associates a SUPER_ADMIN user with
   zero or more tenants. Zero rows for a given user means "all tenants" —
   preserving current behaviour for every existing super-admin.
2. **Enforcement.** Every code path currently gated on
   `AdminRole.canCrossTenants()` must additionally check that the target
   tenant is in the caller's scope set (when the set is non-empty). Known
   call sites at time of writing:
   - `TenantController` (create / update / delete / list across tenants)
   - `AdminController` cross-tenant variants of user/role/app-client/
     service-account endpoints
   - `AuditController` when reading another tenant's audit log
   - `tenantAccessor.requireTenantAdmin()` and
     `tenantAccessor.requireTenant()` for impersonation flows
   - SCIM admin endpoints
   - PKI / SAML IdP / webhook admin endpoints
3. **Listing.** A scoped super-admin sees only their in-scope tenants in
   any "list all tenants" response. Out-of-scope tenants are filtered
   pre-serialisation, not just hidden in the UI.
4. **Self-management forbidden.** A scoped super-admin cannot widen their
   own scope, nor assign a wider scope to another user than they
   themselves hold. Only an unrestricted super-admin (empty scope) can
   create / widen scopes.
5. **Audit.** Adding or removing a tenant from a user's scope emits an
   `ADMIN_SCOPE_CHANGED` audit event with the before/after tenant id
   lists.
6. **Admin portal UI.** The user edit screen gains a "Tenant scope"
   section — visible only when `admin_role = SUPER_ADMIN` — with a
   multi-select tenant picker. "All tenants" is the default for new
   super-admins (preserves current behaviour).

### Non-functional requirements

- Migration must be **non-breaking**: every existing SUPER_ADMIN user
  remains effectively unrestricted (zero scope rows = "all tenants"). No
  operator action required at upgrade time.
- Scope enforcement adds at most one extra cheap query per admin
  request (small per-user set, indexable).

## Out of scope (for ADM-03)

- Scoping the other admin roles (`TENANT_ADMIN`, `READ_ONLY`) — they are
  already inherently single-tenant.
- Per-resource scopes (e.g. "this user can manage *only OIDC clients* in
  these tenants"). Path-scoped capability is a separate concept and
  belongs with the existing `AppClient.scopes` mechanism if extended to
  human users.
- Time-bounded scopes ("scope expires on 2026-12-31"). Useful but a
  separate increment.

## Schema sketch (illustrative, not committed)

```sql
CREATE TABLE user_admin_tenant_scopes (
    user_id    BIGINT  NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    tenant_id  BIGINT  NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, tenant_id)
);

CREATE INDEX idx_user_admin_tenant_scopes_user ON user_admin_tenant_scopes (user_id);
```

Semantics:

- Zero rows for `user_id` → unrestricted (legacy behaviour).
- ≥ 1 row → restricted to that exact set.
- Backfill is a no-op: zero rows is the implicit "all tenants" today.

## Open questions to resolve before implementing

1. **Tenant-creation permission.** Can a scoped super-admin create new
   tenants? If yes, the new tenant is presumably auto-added to their
   scope. If no, the "create tenant" button is hidden for them. Default
   recommendation: **no** — only unrestricted super-admins create
   tenants. Cleaner, easier to reason about.
2. **Tenant-deletion permission.** Same answer as above for symmetry.
3. **Cross-tenant audit search.** Filter the result set, or block the
   endpoint entirely when scope is non-empty? Recommendation: filter —
   the endpoint stays uniform, just returns less data.
4. **Scope inheritance for service accounts.** A
   `ServiceAccount.adminRole = SUPER_ADMIN` token is currently
   unrestricted. Does it inherit scope from the creator at issue time,
   or is scope a property of the service account itself? Recommendation:
   property of the service account — orthogonal to the human user that
   created it.

## Test obligations

- Unit: every `requireTenant*` / `canCrossTenants` enforcement path with
  scope = empty (legacy), scope = {targetTenant} (allowed), scope =
  {otherTenant} (denied with 403).
- Integration: cross-tenant list endpoints filter correctly.
- Migration: existing super-admins remain functional after upgrade with
  zero scope rows.
- Audit: `ADMIN_SCOPE_CHANGED` event shape stable.

## Sequencing note

This is **not** a hot fix — schema migration plus enforcement at every
admin call site plus admin-portal UI is realistically a small-feature-
sized piece of work, not an evening's patch. Implement on its own
branch with a single PR per layer (schema → service enforcement →
admin UI → docs / agents.html update).
