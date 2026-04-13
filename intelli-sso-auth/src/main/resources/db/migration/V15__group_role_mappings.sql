-- ============================================================
-- V15: Group-to-Role bindings.
--
-- Connects SCIM Groups (pushed by upstream provisioners) to
-- application Roles, enabling automatic role assignment when
-- group membership changes. Priority determines which role
-- wins when a user belongs to multiple mapped groups (lowest
-- priority number = highest precedence).
-- ============================================================

CREATE TABLE IF NOT EXISTS group_role_mappings (
    id            BIGSERIAL    PRIMARY KEY,
    tenant_id     BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scim_group_id BIGINT       NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    role_id       BIGINT       NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    priority      INT          NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tenant_id, scim_group_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_grm_tenant ON group_role_mappings (tenant_id);
CREATE INDEX IF NOT EXISTS idx_grm_group  ON group_role_mappings (scim_group_id);
CREATE INDEX IF NOT EXISTS idx_grm_role   ON group_role_mappings (role_id);
