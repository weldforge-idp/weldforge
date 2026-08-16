-- LOCAL DEVELOPMENT ONLY — the Wellspring tenant and its bootstrap admin.
--
-- This file deliberately does NOT live in db/migration. It is only applied
-- when FLYWAY_LOCATIONS names db/localdev, which nothing committed does —
-- see the uncommitted docker-compose .env. A deployed WeldForge instance
-- therefore never provisions a Wellspring tenant; the real one will be
-- registered through the admin API against the live instance instead.
--
-- Repeatable (R__) rather than versioned, because seed data has no place in
-- the schema's version sequence. A versioned file here has to sort after every
-- real migration to avoid collisions, but once applied it becomes the highest
-- version in the database and Flyway then refuses every genuine migration
-- numbered below it — silently, on a local database only. Repeatable
-- migrations run after all versioned ones and re-run when their checksum
-- changes, which is exactly right for an idempotent seed.
--
-- It seeds a user as well as a tenant, because the users table ships empty
-- and nothing in the codebase can mint the first admin for a new tenant: the
-- invite endpoint writes into the *resolved* tenant and itself requires an
-- existing admin, so a fresh tenant is otherwise unreachable.
--
-- Password handling. The hash comes from the Flyway placeholder
-- `wellspring_admin_password_hash`, bound in application.yml to
-- WELLSPRING_ADMIN_PASSWORD_HASH and defaulting to empty. Empty resolves to
-- NULL, which is a *disabled* local password — the account exists but cannot
-- be signed into until someone goes through password recovery. Belt and
-- braces alongside the opt-in location above: even if this file were applied
-- somewhere unintended, it would not introduce a usable credential. The
-- value must be a bcrypt hash, not a plaintext password — AuthService
-- compares it with the configured PasswordEncoder.
--
-- Idempotent: every statement is ON CONFLICT DO NOTHING, and the user insert
-- is a SELECT over the tenant/role it depends on, so re-running is a no-op
-- and a partially-applied state self-heals.

INSERT INTO tenants (slug, name, display_name, contact_email)
VALUES ('wellspring', 'Wellspring', 'Wellspring', 'info@wellspring.org.za')
ON CONFLICT (slug) DO NOTHING;

-- App-level role that lands in the JWT `roles` claim. The Wellspring backend
-- and dashboard both gate their admin pages on SUPERADMIN (see
-- wellspring-backend/scripts/bootstrap-superadmin.sh), which is distinct from
-- WeldForge's own admin-console RBAC in users.admin_role below.
INSERT INTO roles (name, description, tenant_id)
SELECT 'SUPERADMIN',
       'Tenant-wide superadmin — manages messaging providers and other system settings',
       t.id
  FROM tenants t
 WHERE t.slug = 'wellspring'
ON CONFLICT (tenant_id, lower(name)) DO NOTHING;

-- Bootstrap admin. SUPER_ADMIN rather than TENANT_ADMIN: locally this account
-- has to be able to mint the service account the dashboard's Users page uses,
-- and Weldforge reserves that, invitations and admin-role changes for a real
-- super admin. The global admin_membership row below is what makes it real —
-- a per-tenant SUPER_ADMIN is downgraded to TENANT_ADMIN by
-- TenantAccessor.effectiveRole, so the row alone is what carries the authority.
--
-- admin_role is what actually drives authorization —
-- AuthService stamps the JWT `adm` claim from it and JwtAuthenticationFilter
-- prefers that claim over the legacy is_super_admin boolean, so setting the
-- boolean alone would leave the user with no admin rights at all.
-- This is a local-dev seed only, so platform-level authority is acceptable
-- here; a real deployment would provision a tenant admin instead.
INSERT INTO users (tenant_id, username, email, password, name,
                   provider, provider_id, role_id,
                   email_verified, admin_role, is_super_admin, active)
SELECT t.id,
       'info@wellspring.org.za',
       'info@wellspring.org.za',
       NULLIF('${wellspring_admin_password_hash}', ''),
       'Wellspring Admin',
       'LOCAL', 'local',
       r.id,
       true, 'SUPER_ADMIN', true, true
  FROM tenants t
  JOIN roles r
    ON r.tenant_id = t.id
   AND lower(r.name) = 'superadmin'
 WHERE t.slug = 'wellspring'
ON CONFLICT (tenant_id, lower(email)) DO NOTHING;

-- Global admin membership (tenant_id NULL) is what Weldforge treats as genuine
-- platform SUPER_ADMIN. Without it the account is downgraded to TENANT_ADMIN
-- whenever it acts on a tenant, and cannot mint a SUPER_ADMIN service account.
INSERT INTO admin_membership (user_id, tenant_id, admin_role)
SELECT u.id, NULL, 'SUPER_ADMIN'
  FROM users u
  JOIN tenants t ON t.id = u.tenant_id
 WHERE t.slug = 'wellspring'
   AND lower(u.email) = 'info@wellspring.org.za'
ON CONFLICT DO NOTHING;
