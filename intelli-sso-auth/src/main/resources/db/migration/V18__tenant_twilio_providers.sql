-- ============================================================
-- V18: Per-tenant Twilio configuration + SMS OTP MFA factor.
--
-- Until now, Twilio credentials were read from global env vars
-- (TWILIO_ACCOUNT_SID / _AUTH_TOKEN / _PHONE_NUMBER). This moves
-- them into a per-tenant table managed by the admin portal so
-- each tenant can use its own Twilio subaccount + caller-id.
--
-- The auth token is AES-GCM encrypted at rest via the same
-- EncryptedStringConverter used by tenant_signing_keys and
-- oidc_clients.client_secret_enc.
--
-- This migration also extends user_mfa_factors to support the
-- SMS factor type and store the phone number + pending OTP code.
-- ============================================================

CREATE TABLE IF NOT EXISTS tenant_twilio_providers (
    id              BIGSERIAL    PRIMARY KEY,
    tenant_id       BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Twilio Account SID — AC... (public identifier, not sensitive).
    account_sid     VARCHAR(128) NOT NULL,

    -- Twilio Auth Token — AES-GCM encrypted via EncryptedStringConverter.
    auth_token_enc  TEXT         NOT NULL,

    -- E.164 phone number the tenant's SMS originates from.
    from_phone      VARCHAR(32)  NOT NULL,

    -- Optional per-tenant messaging service SID for sender pool routing.
    messaging_service_sid VARCHAR(128),

    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One Twilio config per tenant. If a tenant needs multiple senders they
-- can use a Twilio Messaging Service and reference its SID.
CREATE UNIQUE INDEX IF NOT EXISTS tenant_twilio_tenant_uq
    ON tenant_twilio_providers (tenant_id);


-- ------------------------------------------------------------
-- Extend user_mfa_factors for SMS OTP.
-- ------------------------------------------------------------

-- Allow SMS as a valid type. The existing CHECK constraint must be dropped
-- and recreated to widen the allowed set.
ALTER TABLE user_mfa_factors
    DROP CONSTRAINT IF EXISTS user_mfa_factors_type_check;

ALTER TABLE user_mfa_factors
    ADD CONSTRAINT user_mfa_factors_type_check
    CHECK (type IN ('TOTP', 'WEBAUTHN', 'SMS'));

-- E.164 phone number the code is sent to. Populated only for SMS rows.
ALTER TABLE user_mfa_factors
    ADD COLUMN IF NOT EXISTS phone_number VARCHAR(32);

-- BCrypt hash of the pending OTP code. Single-use; cleared after verify.
ALTER TABLE user_mfa_factors
    ADD COLUMN IF NOT EXISTS sms_code_hash VARCHAR(128);

-- Expiry time for the pending OTP.
ALTER TABLE user_mfa_factors
    ADD COLUMN IF NOT EXISTS sms_code_expires_at TIMESTAMPTZ;
