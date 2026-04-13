-- ============================================================
-- V7: Multi-factor authentication.
-- TOTP (RFC 6238), WebAuthn/FIDO2 credentials, and one-time
-- backup codes. All rows are implicitly tenant-scoped via the
-- owning user_id FK.
-- ============================================================

CREATE TABLE IF NOT EXISTS user_mfa_factors (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- TOTP | WEBAUTHN
    type            VARCHAR(16)  NOT NULL,

    -- Human-readable label the user chose at enrollment time.
    label           VARCHAR(128),

    -- TOTP: Base32 shared secret, AES-GCM encrypted via EncryptedStringConverter.
    totp_secret_enc TEXT,

    -- WebAuthn fields. Populated only for type = WEBAUTHN.
    credential_id   TEXT,
    public_key_cose TEXT,
    signature_count BIGINT       NOT NULL DEFAULT 0,
    aaguid          VARCHAR(64),
    user_handle     TEXT,

    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    -- Whether the factor completed its initial proof-of-possession. TOTP rows
    -- are created unverified and flip to true when the user types the first
    -- OTP; WebAuthn rows are created verified by the ceremony.
    verified        BOOLEAN      NOT NULL DEFAULT FALSE,

    created_at      TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at    TIMESTAMPTZ,

    CONSTRAINT user_mfa_factors_type_check
        CHECK (type IN ('TOTP', 'WEBAUTHN'))
);
CREATE INDEX IF NOT EXISTS idx_user_mfa_factors_user
    ON user_mfa_factors (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS user_mfa_factors_credential_id_uq
    ON user_mfa_factors (credential_id) WHERE credential_id IS NOT NULL;


CREATE TABLE IF NOT EXISTS user_backup_codes (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- BCrypt hash of the plaintext code. Codes themselves are shown to the
    -- user exactly once, at generation time.
    code_hash   VARCHAR(128) NOT NULL,

    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_user_backup_codes_user
    ON user_backup_codes (user_id);
CREATE INDEX IF NOT EXISTS idx_user_backup_codes_unused
    ON user_backup_codes (user_id) WHERE used_at IS NULL;
