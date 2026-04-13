-- ============================================================
-- V13: SCIM 2.0 Groups (RFC 7643 §4.2).
-- Distinct from the existing application Roles table — those
-- are internal RBAC primitives, while these are SCIM Groups
-- that upstream provisioners (Okta, Workday, Entra ID) push
-- to drive role / permission assignment.
--
-- Tenant-scoped via {tenant_id, name}; many-to-many to users
-- through the scim_group_members join table.
-- ============================================================

CREATE TABLE IF NOT EXISTS scim_groups (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The canonical name (matches RFC 7643 displayName attribute).
    name         VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),

    -- External id assigned by the upstream provisioner (Okta etc).
    external_id  VARCHAR(255),

    created_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS scim_groups_tenant_name_uq
    ON scim_groups (tenant_id, LOWER(name));

CREATE INDEX IF NOT EXISTS idx_scim_groups_tenant
    ON scim_groups (tenant_id);

CREATE INDEX IF NOT EXISTS idx_scim_groups_external_id
    ON scim_groups (tenant_id, external_id) WHERE external_id IS NOT NULL;


CREATE TABLE IF NOT EXISTS scim_group_members (
    group_id  BIGINT NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id   BIGINT NOT NULL REFERENCES users(id)       ON DELETE CASCADE,
    added_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_scim_group_members_user
    ON scim_group_members (user_id);
