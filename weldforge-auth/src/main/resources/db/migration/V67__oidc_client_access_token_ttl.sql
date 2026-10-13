-- Per-client access-token lifetime.
--
-- Until now the only lever was tenants.access_ttl_ms, which applies to every
-- client in the tenant including the admin portal's own sessions. A consumer
-- that wants ten-minute access tokens had no way to ask for them without
-- shortening everyone else's.
--
-- Nullable on purpose: NULL inherits the tenant's access TTL and then the
-- application default, exactly as refresh_token_ttl_s does beside it. Zero is
-- not the sentinel -- zero is a legitimate (if useless) lifetime, and reusing
-- it to mean "unset" is the mistake max_authentication_age_s already made.
--
-- A client may only SHORTEN its access tokens. The tenant's effective TTL is a
-- ceiling, refused above at registration and capped again at issuance. The
-- ceiling is not there to restrain admins -- a tenant admin who wants longer
-- can raise the tenant's own TTL. It is there because
-- OidcClientService.createForDynamicRegistration runs the same validation with
-- no admin session, so without it a self-registering client could grant itself
-- a thirty-day access token.
--
-- Additive: a new nullable column, no backfill, no existing row read or
-- written. Every client keeps inheriting exactly what it inherited before.
ALTER TABLE oidc_clients ADD COLUMN IF NOT EXISTS access_token_ttl_s INTEGER;

COMMENT ON COLUMN oidc_clients.access_token_ttl_s IS
    'Access-token lifetime in seconds. NULL inherits the tenant access TTL and then the application default. Capped at the tenant effective TTL at issuance and refused above it at registration: a client may shorten its own access tokens, never lengthen them.';
