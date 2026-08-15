-- LOCAL DEVELOPMENT ONLY — the Wellspring tenant and its bootstrap admin.
--
-- This file deliberately does NOT live in db/migration. It is only applied
-- when FLYWAY_LOCATIONS names db/localdev, which nothing committed does —
-- see the uncommitted docker-compose .env. A deployed WeldForge instance
-- therefore never provisions a Wellspring tenant; the real one will be
-- registered through the admin API against the live instance instead.
--
-- Versioned V900 rather than V46 so it always sorts after the real schema
-- and never collides with, or forces out-of-order handling for, the next
-- genuine migration.
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

-- Bootstrap admin. admin_role is what actually drives authorization —
-- AuthService stamps the JWT `adm` claim from it and JwtAuthenticationFilter
-- prefers that claim over the legacy is_super_admin boolean, so setting the
-- boolean alone would leave the user with no admin rights at all.
-- TENANT_ADMIN (not SUPER_ADMIN) is the correct level: this account
-- administers the Wellspring tenant, not the WeldForge platform.
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
       true, 'TENANT_ADMIN', false, true
  FROM tenants t
  JOIN roles r
    ON r.tenant_id = t.id
   AND lower(r.name) = 'superadmin'
 WHERE t.slug = 'wellspring'
ON CONFLICT (tenant_id, lower(email)) DO NOTHING;
