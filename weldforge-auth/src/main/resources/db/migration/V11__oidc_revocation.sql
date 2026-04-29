-- ============================================================
-- V11: OIDC token revocation list.
-- Spring Authorization Server-style stateless JWTs cannot be
-- "unminted", so the introspection endpoint consults this table
-- to know which previously-issued tokens have been revoked. The
-- raw token is never stored — only the SHA-256 hash, so a DB
-- dump cannot be used to forge or replay anything.
-- ============================================================

CREATE TABLE IF NOT EXISTS revoked_oidc_tokens (
    id          BIGSERIAL PRIMARY KEY,

    -- SHA-256(token) base64url encoded. Globally unique because
    -- the underlying tokens are random JWTs.
    token_hash  VARCHAR(128) NOT NULL UNIQUE,

    tenant_id   BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id   BIGINT REFERENCES oidc_clients(id) ON DELETE SET NULL,

    -- The token's exp claim, copied so the cleanup job can prune
    -- rows whose underlying tokens have already expired naturally.
    expires_at  TIMESTAMPTZ  NOT NULL,
    revoked_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,

    revoked_reason VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS idx_revoked_oidc_tokens_tenant
    ON revoked_oidc_tokens (tenant_id);

CREATE INDEX IF NOT EXISTS idx_revoked_oidc_tokens_expires
    ON revoked_oidc_tokens (expires_at);
