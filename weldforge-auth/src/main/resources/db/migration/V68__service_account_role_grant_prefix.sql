-- A service account may be allowed to assign tenant roles under one name
-- prefix, and nothing else anywhere.
--
-- Until now the only credential that could assign a role was a service account
-- with adminRole TENANT_ADMIN, which can also delete users, reset MFA and edit
-- OIDC clients for the whole tenant. Handing that to a downstream application
-- so it can manage its own namespace of role names is a grant orders of
-- magnitude wider than the need; the alternative in use was an operator
-- creating roles by hand.
--
-- Nullable, and null on every existing row: no credential that exists today
-- gains any capability from this migration. The prefix is a capability in its
-- own right rather than an admin role -- an account carrying one is expected
-- to have adminRole NONE, and reaches exactly two endpoints.
--
-- Matching is case-insensitive, because role names are already unique without
-- regard to case (roles_tenant_name uniqueness via
-- existsByTenantIdAndNameIgnoreCase). A case-sensitive prefix filter would let
-- a role sit inside the namespace while being invisible to the API that owns
-- the namespace, and therefore impossible to remove through it.
--
-- See docs/product/scoped-role-grants.md.
ALTER TABLE service_accounts ADD COLUMN IF NOT EXISTS role_grant_prefix VARCHAR(64);

COMMENT ON COLUMN service_accounts.role_grant_prefix IS
    'Optional. Lets this account assign tenant roles whose names start with this prefix, case-insensitively, and nothing else. NULL or blank means no role-grant capability. Independent of admin_role.';
