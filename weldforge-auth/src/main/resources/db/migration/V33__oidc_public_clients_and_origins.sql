-- V33: Public (PKCE-only) OIDC clients, web/CORS origins, post-logout URIs.
--
-- Enables browser SPAs and native apps (OAuth 2.1 Authorization Code + PKCE,
-- no client secret) to integrate with a tenant. web_origins additionally
-- feeds the per-tenant CORS allow-list for the tenant OIDC endpoints, so the
-- allow-list is data-driven off registered clients rather than hard-coded.
--
-- MERGE HAZARD: the V33 slot is also taken by unmerged feature branches
-- (tenant host-routing V33__tenant_hosts, platform-settings). Whichever
-- migration lands in main second must be renumbered before merge.

-- Browser origins (scheme://host[:port]) allowed to call this tenant's OIDC
-- endpoints cross-origin. Space/comma-separated; empty for non-browser clients.
ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS web_origins TEXT NOT NULL DEFAULT '';

-- OIDC RP-Initiated Logout post_logout_redirect_uri allow-list. Kept separate
-- from redirect_uris: the post-logout landing page is rarely the same URL as
-- the OAuth callback (e.g. https://app/  vs  https://app/callback).
ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS post_logout_redirect_uris TEXT NOT NULL DEFAULT '';

-- A public client authenticates at the token endpoint with PKCE alone and
-- holds no usable client secret (OAuth 2.1 section 2.1, RFC 8252). For these,
-- require_pkce is forced TRUE and no secret is ever returned.
ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS public_client BOOLEAN NOT NULL DEFAULT FALSE;

-- RFC 8414 token_endpoint_auth_method: 'client_secret_post' (confidential,
-- the historical default) or 'none' (public client).
ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS token_endpoint_auth_method VARCHAR(32) NOT NULL
        DEFAULT 'client_secret_post';
