-- ============================================================
-- V20: Per-tenant session lifetimes (PRD SSO-03).
--
-- Access and refresh TTLs were previously global (app.jwt.*). This
-- moves them into per-tenant columns so each tenant can configure
-- session duration between 1 minute and 30 days (PRD range).
--
-- NULL means "use the application default". A concrete value
-- overrides at mint time.
--
-- Also adds a JSONB bag for per-tenant custom JWT claims injected
-- into every access + ID token (PRD OA2-07).
-- ============================================================

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS access_ttl_ms  BIGINT,
    ADD COLUMN IF NOT EXISTS refresh_ttl_ms BIGINT,
    ADD COLUMN IF NOT EXISTS custom_claims  JSONB;

-- Sanity: per-PRD SSO-03, allowed range is 60_000 (1 min) to 2_592_000_000 (30 days).
ALTER TABLE tenants
    ADD CONSTRAINT tenants_access_ttl_range_check
        CHECK (access_ttl_ms IS NULL OR (access_ttl_ms >= 60000 AND access_ttl_ms <= 2592000000));

ALTER TABLE tenants
    ADD CONSTRAINT tenants_refresh_ttl_range_check
        CHECK (refresh_ttl_ms IS NULL OR (refresh_ttl_ms >= 60000 AND refresh_ttl_ms <= 2592000000));
