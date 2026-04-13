-- ============================================================
-- V5: Tighten tenant scoping and add super-admin flag.
-- Follows V4 which added nullable tenant_id columns and
-- backfilled existing rows to the "default" tenant.
-- ============================================================

-- Roles: require tenant; replace global unique name with (tenant,name).
ALTER TABLE roles ALTER COLUMN tenant_id SET NOT NULL;

DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'roles'::regclass
          AND contype  = 'u'
          AND pg_get_constraintdef(oid) ~* '\(name\)'
    LOOP
        EXECUTE format('ALTER TABLE roles DROP CONSTRAINT %I', r.conname);
    END LOOP;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS roles_tenant_name_uq
    ON roles (tenant_id, LOWER(name));

-- Environments: require tenant; (tenant,name,project_name) unique.
ALTER TABLE environments ALTER COLUMN tenant_id SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS environments_tenant_name_uq
    ON environments (tenant_id, LOWER(name), COALESCE(LOWER(project_name), ''));

-- App clients: require tenant. api_key stays globally unique — it is a
-- secret credential and cross-tenant collisions would be a security risk.
ALTER TABLE app_clients ALTER COLUMN tenant_id SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS app_clients_tenant_name_uq
    ON app_clients (tenant_id, LOWER(client_name));

-- Users: super-admin flag. Super admins bypass tenant scoping on the
-- tenant-management endpoints only; every other API remains scoped to
-- their own JWT tenant.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS is_super_admin BOOLEAN NOT NULL DEFAULT FALSE;
