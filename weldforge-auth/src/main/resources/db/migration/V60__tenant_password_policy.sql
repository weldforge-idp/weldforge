-- Per-tenant password policy overrides. See docs/password-policy-spec.md.
--
-- NULL means "inherit the deployment baseline" (app.security.password.*), and
-- is the correct value for every existing row, so there is no backfill.
--
-- Partial objects are the normal case: a tenant that only cares about length
-- stores {"minLength": 14} and inherits the rest key by key.
--
-- Overrides may only TIGHTEN relative to the baseline (spec §2). That is
-- enforced in the resolver rather than here, because it is a comparison
-- against runtime configuration that the database cannot see.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS password_policy jsonb;

COMMENT ON COLUMN tenants.password_policy IS
    'Per-tenant password rule overrides; NULL inherits app.security.password.*. Overrides may only tighten. See docs/password-policy-spec.md.';
