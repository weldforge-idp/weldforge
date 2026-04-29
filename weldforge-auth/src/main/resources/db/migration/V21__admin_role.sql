-- ============================================================
-- V21: Admin RBAC (PRD ADM-02).
--
-- Adds an explicit admin_role column to users. Values:
--
--   NONE         — regular user, no admin console access
--   READ_ONLY    — may read everything within their tenant
--   TENANT_ADMIN — may manage their own tenant (users, roles,
--                  OIDC clients, SAML providers, MFA policy,
--                  Twilio config, etc.) but cannot create or
--                  delete tenants
--   SUPER_ADMIN  — may cross tenant boundaries, create tenants,
--                  assign admin roles, and perform any action
--                  previously gated by the legacy is_super_admin
--                  boolean
--
-- Backfill: users where is_super_admin = TRUE become SUPER_ADMIN;
-- everyone else defaults to NONE. The is_super_admin column is
-- kept for backwards compatibility with code that still reads it
-- (the User entity now derives the boolean from the role).
-- ============================================================

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS admin_role VARCHAR(32) NOT NULL DEFAULT 'NONE';

ALTER TABLE users
    ADD CONSTRAINT users_admin_role_check
    CHECK (admin_role IN ('NONE', 'READ_ONLY', 'TENANT_ADMIN', 'SUPER_ADMIN'));

-- Backfill from the legacy boolean so existing super-admins keep working.
UPDATE users
SET admin_role = 'SUPER_ADMIN'
WHERE is_super_admin = TRUE AND admin_role = 'NONE';

CREATE INDEX IF NOT EXISTS idx_users_admin_role
    ON users (admin_role)
    WHERE admin_role <> 'NONE';
