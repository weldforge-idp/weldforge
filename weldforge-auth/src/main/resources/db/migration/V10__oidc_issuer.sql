-- ============================================================
-- V10: OIDC issuer.
-- WeldForge becomes an OIDC provider — every tenant has its
-- own RSA signing key, its own client registry, and its own
-- discovery document at /t/{slug}/.well-known/openid-configuration.
-- ============================================================

-- --- Per-tenant signing keys ---------------------------------
-- One active RS256 keypair per tenant. The private key is
-- AES-GCM encrypted via EncryptedStringConverter, the public
-- key is plaintext PEM and is exposed via the JWKS endpoint.
-- Rotated keys stay around so previously-issued tokens can
-- still be verified until they expire.
CREATE TABLE IF NOT EXISTS tenant_signing_keys (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Stable JWK key id used in the JWS header so verifiers can
    -- pick the right entry from the JWKS.
    kid             VARCHAR(64)  NOT NULL UNIQUE,

    algorithm       VARCHAR(16)  NOT NULL DEFAULT 'RS256',

    public_key_pem  TEXT         NOT NULL,
    private_key_enc TEXT         NOT NULL,

    active          BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rotated_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tenant_signing_keys_tenant_active
    ON tenant_signing_keys (tenant_id) WHERE active = TRUE;

-- --- OIDC clients --------------------------------------------
-- Each tenant manages its own list of relying parties. The
-- client_secret column is encrypted at rest; redirect URIs,
-- scopes and grant types are stored as comma-separated lists.
CREATE TABLE IF NOT EXISTS oidc_clients (
    id                BIGSERIAL PRIMARY KEY,
    tenant_id         BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    client_id         VARCHAR(128) NOT NULL,
    client_secret_enc TEXT         NOT NULL,

    name              VARCHAR(255),

    -- CSV columns intentionally — the data is small and a join
    -- table for ~3 redirect URIs would add complexity for no win.
    redirect_uris     TEXT         NOT NULL,
    scopes            TEXT         NOT NULL,
    grant_types       TEXT         NOT NULL,

    require_pkce      BOOLEAN      NOT NULL DEFAULT TRUE,

    created_at        TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT oidc_clients_unique UNIQUE (tenant_id, client_id)
);

CREATE INDEX IF NOT EXISTS idx_oidc_clients_tenant
    ON oidc_clients (tenant_id);

-- --- OAuth authorization codes -------------------------------
-- Short-lived (~5 min) handles created at the /authorize endpoint
-- and exchanged at /token. Stored as SHA-256 hashes so a database
-- dump cannot replay them.
CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    id                    BIGSERIAL PRIMARY KEY,
    code_hash             VARCHAR(128) NOT NULL UNIQUE,

    client_id             BIGINT       NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    tenant_id             BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id               BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    redirect_uri          VARCHAR(2048) NOT NULL,
    scopes                TEXT          NOT NULL,
    nonce                 VARCHAR(255),

    -- PKCE fields. challenge_method is S256 in practice; we record
    -- the chosen method so a future migration can support 'plain'
    -- without changing the schema.
    code_challenge        VARCHAR(255),
    code_challenge_method VARCHAR(16),

    expires_at            TIMESTAMPTZ NOT NULL,
    used_at               TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_expires
    ON oauth_authorization_codes (expires_at);
