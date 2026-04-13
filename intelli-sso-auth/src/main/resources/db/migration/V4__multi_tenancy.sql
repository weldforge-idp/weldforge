-- ============================================================
-- V4: Multi-tenancy foundation
-- Adds tenants, per-tenant social provider config, and
-- tenant scoping for users/roles/app_clients/environments.
-- ============================================================

-- Tenants ------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    id            BIGSERIAL PRIMARY KEY,
    slug          VARCHAR(64)  UNIQUE NOT NULL,
    name          VARCHAR(255) NOT NULL,
    display_name  VARCHAR(255),
    enabled       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT tenants_slug_format CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$')
);

-- Seed a default tenant so existing data keeps working.
INSERT INTO tenants (slug, name, display_name)
VALUES ('default', 'Default', 'Default Tenant')
ON CONFLICT (slug) DO NOTHING;

-- Per-tenant social provider config ---------------------------
CREATE TABLE IF NOT EXISTS tenant_social_providers (
    id                 BIGSERIAL PRIMARY KEY,
    tenant_id          BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider           VARCHAR(32)  NOT NULL,
    display_name       VARCHAR(128),
    client_id          VARCHAR(512) NOT NULL,
    client_secret_enc  TEXT         NOT NULL,
    scopes             VARCHAR(512),
    enabled            BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT tenant_social_providers_unique UNIQUE (tenant_id, provider)
);
CREATE INDEX IF NOT EXISTS idx_tsp_tenant_enabled
    ON tenant_social_providers (tenant_id) WHERE enabled = TRUE;

-- Tenant scoping on users -------------------------------------
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenants(id);

-- Backfill existing users onto the default tenant.
UPDATE users
SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default')
WHERE tenant_id IS NULL;

ALTER TABLE users ALTER COLUMN tenant_id SET NOT NULL;

-- Drop global-unique on email/username and replace with
-- tenant-scoped uniqueness so the same person can exist across
-- tenants.
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'users'::regclass
          AND contype = 'u'
          AND pg_get_constraintdef(oid) ~* '\(email\)|\(username\)'
    LOOP
        EXECUTE format('ALTER TABLE users DROP CONSTRAINT %I', r.conname);
    END LOOP;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS users_tenant_email_uq
    ON users (tenant_id, LOWER(email));
CREATE UNIQUE INDEX IF NOT EXISTS users_tenant_username_uq
    ON users (tenant_id, LOWER(username));
CREATE INDEX IF NOT EXISTS idx_users_tenant
    ON users (tenant_id);

-- Tenant scoping on roles/app_clients/environments ------------
-- Nullable for now to avoid breaking existing rows; backfill to
-- default tenant so future inserts can tighten.
ALTER TABLE roles         ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenants(id);
ALTER TABLE app_clients   ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenants(id);
ALTER TABLE environments  ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenants(id);

UPDATE roles         SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default') WHERE tenant_id IS NULL;
UPDATE app_clients   SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default') WHERE tenant_id IS NULL;
UPDATE environments  SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default') WHERE tenant_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_roles_tenant        ON roles        (tenant_id);
CREATE INDEX IF NOT EXISTS idx_app_clients_tenant  ON app_clients  (tenant_id);
CREATE INDEX IF NOT EXISTS idx_environments_tenant ON environments (tenant_id);
