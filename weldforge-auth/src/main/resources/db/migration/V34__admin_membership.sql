-- V34: Cross-tenant admin membership — cross-tenant-admin-spec.md phases 1-3, 5.
--
-- Separates IDENTITY (which tenant a user record lives in — users.tenant_id,
-- unchanged) from ADMIN REACH (which tenants a user may administer — new).
-- A row with tenant_id = NULL is a GLOBAL membership: the role applies to
-- every tenant, present and future. Tenant isolation stays the default —
-- with no row, a caller reaches exactly their home tenant.
--
-- MERGE HAZARD: the V33/V34 slots are contended by unmerged feature branches;
-- renumber on merge if a collision occurs.

CREATE TABLE IF NOT EXISTS admin_membership (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- NULL tenant_id == GLOBAL scope: the role applies to every tenant.
    tenant_id   BIGINT REFERENCES tenants(id) ON DELETE CASCADE,
    admin_role  VARCHAR(32) NOT NULL,            -- READ_ONLY | TENANT_ADMIN | SUPER_ADMIN
    granted_by  BIGINT REFERENCES users(id),
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One per-tenant membership per (user, tenant).
CREATE UNIQUE INDEX IF NOT EXISTS uq_admin_membership_user_tenant
    ON admin_membership (user_id, tenant_id) WHERE tenant_id IS NOT NULL;

-- One global membership per user. Postgres treats NULLs as distinct, so the
-- composite index above does not constrain the global (tenant_id IS NULL) row.
CREATE UNIQUE INDEX IF NOT EXISTS uq_admin_membership_user_global
    ON admin_membership (user_id) WHERE tenant_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_admin_membership_user ON admin_membership (user_id);

-- Seed (spec section 8) — existing single-tenant admins keep working unchanged.
-- Tenant-scoped admins -> a per-tenant membership in their home tenant.
INSERT INTO admin_membership (user_id, tenant_id, admin_role)
SELECT id, tenant_id, admin_role
FROM users
WHERE admin_role <> 'NONE'
  AND admin_role <> 'SUPER_ADMIN'
  AND is_super_admin = false
ON CONFLICT DO NOTHING;

-- Super admins -> a single GLOBAL membership (platform-wide reach).
INSERT INTO admin_membership (user_id, tenant_id, admin_role)
SELECT id, NULL, 'SUPER_ADMIN'
FROM users
WHERE is_super_admin = true OR admin_role = 'SUPER_ADMIN'
ON CONFLICT DO NOTHING;
