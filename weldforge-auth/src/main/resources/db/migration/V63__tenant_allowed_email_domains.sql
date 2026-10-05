-- ============================================================================
-- V63: restrict who may sign in to a tenant, by email domain.
--
-- A tenant federated to Google Workspace accepts anybody with a Google
-- account, not just the staff of the organisation it is federated to. Google
-- sends `hd` (hosted domain) for Workspace accounts and the address itself
-- always carries a domain; neither was checked, so the only thing standing
-- between a stranger's gmail.com account and a tenant was that they had to
-- know the sign-in URL.
--
-- NULL or empty means "no restriction", which is every existing tenant: this
-- changes nobody's behaviour until somebody sets it.
--
-- Space-separated, matching how redirect_uris, scopes and web_origins are
-- already stored on oidc_clients. One CSV convention in the schema, not two.
-- ============================================================================

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS allowed_email_domains TEXT;

COMMENT ON COLUMN tenants.allowed_email_domains IS
    'Space-separated email domains permitted to sign in. NULL/empty = unrestricted. Matched case-insensitively on the part after @, and against Google''s hd claim where present.';
