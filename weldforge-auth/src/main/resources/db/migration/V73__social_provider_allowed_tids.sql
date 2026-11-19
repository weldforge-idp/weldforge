-- ============================================================================
-- V73 -- Microsoft directory allow-list (Proboulos WF-4, security review
-- 2026-11-15).
--
-- A Microsoft provider registered against the multi-tenant /common endpoint
-- accepts a sign-in from ANY Entra ID directory: whoever creates a directory
-- can create accounts in a tenant whose sign-up is open. Microsoft's id token
-- names the directory in its tid claim, which is the organisation being
-- admitted, the way Google's hd is (see V71's required_hd).
--
-- NULL keeps today's behaviour for every existing row.
-- ============================================================================

ALTER TABLE tenant_social_providers
    ADD COLUMN IF NOT EXISTS allowed_tids VARCHAR(1024);

COMMENT ON COLUMN tenant_social_providers.allowed_tids IS
    'Space-separated Entra ID directory (tenant) ids accepted for a MICROSOFT provider. A sign-in whose tid claim is absent or not listed is refused before provisioning. NULL = any directory.';
