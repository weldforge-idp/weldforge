-- ============================================================================
-- V64: per-client branding for the login screen.
--
-- Branding is per TENANT today, but a tenant routinely hosts several
-- applications: cwvermaak-tech alone carries KeyCrypt, NoteForge and
-- Clepsydra. Someone signing in to Clepsydra sees the tenant's branding,
-- which is at best generic and at worst the wrong product's.
--
-- Deliberately the SAME SHAPE as tenants.branding -- same keys, same jsonb,
-- same consumer -- so the login screen gains no second vocabulary. The only
-- new idea is precedence.
--
-- MERGE, NOT REPLACE: a client's keys overlay the tenant's one at a time, so
-- a client can set a logo and inherit every colour. Replacing wholesale would
-- make the cheapest useful case -- "our logo, your colours" -- the most
-- expensive one, and would silently reset a tenant's palette the moment a
-- client set a single key.
--
-- NULL means "inherit entirely", which is every client that exists today.
-- ============================================================================

ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS branding JSONB;

COMMENT ON COLUMN oidc_clients.branding IS
    'Per-client login-screen branding. Same keys as tenants.branding; overlays it key by key. NULL inherits the tenant entirely.';
