-- ============================================================
-- V19: MFA enforcement policies + per-application step-up.
--
-- PRD requirements:
--   MFA-03 — per-tenant MFA enforcement (optional / required /
--            risk-adaptive)
--   MFA-04 — per-application MFA step-up (force a fresh factor
--            check even within an active SSO session)
--   SSO-05 — MFA step-up for high-assurance applications
--
-- Design:
--   * One tenant_mfa_policies row per tenant. Missing row = OPTIONAL.
--   * OIDC clients get two new columns:
--       require_mfa                — force a verified factor for
--                                    every /authorize request
--       max_authentication_age_s   — maximum age of the SSO session
--                                    in seconds; older sessions must
--                                    re-authenticate the factor
-- ============================================================

CREATE TABLE IF NOT EXISTS tenant_mfa_policies (
    id                     BIGSERIAL    PRIMARY KEY,
    tenant_id              BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- OPTIONAL | REQUIRED | RISK_ADAPTIVE (RISK_ADAPTIVE deferred)
    enforcement            VARCHAR(32)  NOT NULL DEFAULT 'OPTIONAL',

    -- When enforcement = REQUIRED, give existing users this many days
    -- to enroll a factor before their logins start getting blocked.
    grace_period_days      INT          NOT NULL DEFAULT 7,

    -- Default max_authentication_age (seconds) used when an OIDC client
    -- doesn't override. 0 = no default step-up.
    default_stepup_max_age INT          NOT NULL DEFAULT 0,

    created_at             TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT tenant_mfa_policies_enforcement_check
        CHECK (enforcement IN ('OPTIONAL', 'REQUIRED', 'RISK_ADAPTIVE'))
);

CREATE UNIQUE INDEX IF NOT EXISTS tenant_mfa_policies_tenant_uq
    ON tenant_mfa_policies (tenant_id);


-- ------------------------------------------------------------
-- OIDC client step-up columns.
-- ------------------------------------------------------------

ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS require_mfa BOOLEAN NOT NULL DEFAULT FALSE;

-- 0 means "no step-up required beyond whatever the tenant policy sets".
ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS max_authentication_age_s INT NOT NULL DEFAULT 0;
