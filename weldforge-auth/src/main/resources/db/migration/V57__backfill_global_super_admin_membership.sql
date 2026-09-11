-- Give every platform super-admin the GLOBAL admin_membership row that
-- cross-tenant-admin-spec.md §8 says they hold.
--
-- V34 seeded that row for the super-admins that existed when it ran. Anyone
-- promoted afterwards -- the SuperAdminBootstrap path, which is how a fresh
-- install gets its first admin -- set users.is_super_admin / admin_role and
-- never got one. Production on 2026-09-11 had a super-admin and zero
-- membership rows.
--
-- That mattered because there were two cross-tenant channels with two
-- different rules: the X-Tenant-Slug override honoured the JWT `sa` claim,
-- while X-WF-Tenant (CrossTenantSelectorFilter, audited) honours memberships.
-- The admin portal used the first; with this release every cross-tenant admin
-- call goes through the second, so a super-admin with no global row would be
-- refused everywhere but their home tenant.
--
-- This grants no new authority: the rows mirror the super-admin flag each user
-- already carries. granted_by stays NULL, the marker for seeded rows.

INSERT INTO admin_membership (user_id, tenant_id, admin_role, granted_by, granted_at)
SELECT u.id, NULL, 'SUPER_ADMIN', NULL, now()
  FROM users u
 WHERE (u.is_super_admin OR u.admin_role = 'SUPER_ADMIN')
   AND NOT EXISTS (
         SELECT 1 FROM admin_membership m
          WHERE m.user_id = u.id AND m.tenant_id IS NULL AND m.admin_role = 'SUPER_ADMIN');
