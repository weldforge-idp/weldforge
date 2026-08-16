-- Bind refresh tokens to the OIDC client they were issued to.
--
-- The table already backs the session flow, where a token belongs to a user
-- and nothing else. An OIDC refresh token additionally belongs to a *client*:
-- RFC 6749 §6 and §10.4 require the authorization server to verify that the
-- refresh token was issued to the client presenting it, otherwise one relying
-- party could spend another's token and obtain access tokens in its name.
--
-- NULL means "not issued through OIDC" — every existing row, and every future
-- session-flow token. Those are only ever presented at /api/auth/refresh,
-- which does not accept a client, so the two flows cannot be crossed:
-- a session token has no client to match, and an OIDC token is rejected
-- unless the presented client matches exactly.

ALTER TABLE refresh_tokens
    ADD COLUMN client_id BIGINT REFERENCES oidc_clients(id) ON DELETE CASCADE;

-- Rotation and revocation look tokens up by hash, but revoking every token
-- for a client (deleting or disabling it) scans by client.
CREATE INDEX idx_refresh_tokens_client ON refresh_tokens (client_id)
    WHERE client_id IS NOT NULL;

COMMENT ON COLUMN refresh_tokens.client_id IS
    'OIDC client this token was issued to. NULL for session-flow tokens from '
    '/api/auth/login. A refresh token is only valid when presented by the '
    'client it was issued to.';
