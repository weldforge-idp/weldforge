-- ============================================================
-- V24: Service accounts (PRD TOK-03).
--
-- A service account is a machine identity scoped to a tenant.
-- It authenticates via a prefixed, hashed token using the same
-- {prefix, hash} pattern as app_clients (TOK-01). Unlike app
-- clients, a service account can carry an admin_role so M2M
-- callers can be granted explicit RBAC capabilities without
-- reusing a human user's credentials.
--
-- The token column stores SHA-256(raw) only — the raw token is
-- revealed once on creation and never again.
-- ============================================================

CREATE TABLE IF NOT EXISTS service_accounts (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          VARCHAR(255) NOT NULL,
    description   TEXT,
    token_prefix  VARCHAR(32) NOT NULL,
    token_hash    VARCHAR(128) NOT NULL,
    admin_role    VARCHAR(32) NOT NULL DEFAULT 'NONE'
        CHECK (admin_role IN ('NONE','READ_ONLY','TENANT_ADMIN','SUPER_ADMIN')),
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at  TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS service_accounts_tenant_name_uq
    ON service_accounts (tenant_id, LOWER(name));

CREATE INDEX IF NOT EXISTS idx_service_accounts_token_hash
    ON service_accounts (token_hash);

CREATE INDEX IF NOT EXISTS idx_service_accounts_tenant
    ON service_accounts (tenant_id);
