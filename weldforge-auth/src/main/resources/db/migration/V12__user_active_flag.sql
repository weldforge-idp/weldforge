-- ============================================================
-- V12: SCIM-style "active" flag on users.
-- Lockout (V9) is a transient anti-bruteforce mechanism; the
-- active flag is a deliberate, possibly long-lived "this user
-- exists but cannot sign in" state, set by SCIM clients (Okta,
-- Workday, Entra ID) to deactivate accounts as people leave
-- the org.
--
-- Login refuses inactive accounts; SCIM clients can flip the
-- flag back to true to reinstate.
-- ============================================================

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE;

CREATE INDEX IF NOT EXISTS idx_users_tenant_active
    ON users (tenant_id, active);
