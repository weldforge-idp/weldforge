-- ============================================================
-- V9: Security hardening — account lockout, session revocation,
-- and persisted refresh tokens with reuse detection.
-- ============================================================

-- --- User-level columns --------------------------------------

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS locked_until          TIMESTAMPTZ,
    -- Bumping this invalidates every outstanding access token for the user
    -- because access tokens carry a matching "ver" claim and the JWT filter
    -- rejects anything stale. Used by "log me out of all devices".
    ADD COLUMN IF NOT EXISTS token_version         INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_users_locked_until
    ON users (locked_until) WHERE locked_until IS NOT NULL;


-- --- Refresh tokens -------------------------------------------
-- Every refresh token belongs to a "family". When a token is used to
-- obtain a new access token it is atomically marked used and a successor
-- is issued. If an already-used token is presented again, it's treated
-- as a theft signal: every token in that family is revoked and a
-- high-severity audit event is emitted.
-- --------------------------------------------------------------

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id             BIGSERIAL PRIMARY KEY,
    user_id        BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id      BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- All tokens descended from the same initial login share a family_id.
    family_id      UUID         NOT NULL,

    -- Opaque random token identifier; the actual token string is hashed
    -- with SHA-256 into token_hash and never stored in the clear.
    token_hash     VARCHAR(128) NOT NULL UNIQUE,

    issued_at      TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at     TIMESTAMPTZ  NOT NULL,

    -- Set on first successful rotation — indicates the token has already
    -- been exchanged for a new one. A second presentation == reuse attack.
    used_at        TIMESTAMPTZ,

    -- Manual revocation (logout, admin reset, reuse detection). Once
    -- populated, the token is permanently unusable.
    revoked_at     TIMESTAMPTZ,
    revoked_reason VARCHAR(64),

    -- For auditability: link rotations together.
    replaced_by    BIGINT REFERENCES refresh_tokens(id),

    ip_address     VARCHAR(45),
    user_agent     VARCHAR(512)
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user
    ON refresh_tokens (user_id);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family
    ON refresh_tokens (family_id);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires
    ON refresh_tokens (expires_at);
