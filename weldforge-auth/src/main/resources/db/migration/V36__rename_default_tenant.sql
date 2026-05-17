-- Rename the bootstrap tenant.
--
-- The 'default' tenant shipped with the name "Default Tenant", which reads
-- awkwardly wherever the tenant label surfaces to end users -- most visibly
-- in transactional email subjects ("Reset your Default Tenant password").
-- Rename it to the platform name.
--
-- The slug stays 'default': it is immutable and is embedded in OAuth2
-- registration IDs, OIDC issuer URLs and tenant-routing paths.
UPDATE tenants
   SET name = 'WeldForge',
       display_name = 'WeldForge',
       updated_at = now()
 WHERE slug = 'default';
