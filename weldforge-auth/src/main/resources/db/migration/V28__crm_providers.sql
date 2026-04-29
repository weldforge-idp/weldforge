-- ============================================================
-- V28: CRM identity provisioning (PRD §3.10 CRM-01..CRM-04).
--
-- tenant_crm_providers holds the per-tenant connector config:
-- which CRM, where to reach it, how to authenticate, how to map
-- WeldForge user attributes to the CRM's contact/lead fields,
-- and which attribute values to use as match keys for dedupe.
--
-- The api token is encrypted at rest via @Convert — same AES-GCM
-- path used for Twilio, LDAP, tenant SAML signing keys, etc.
--
-- crm_provisioning_log is an append-ish cache keyed on
-- (provider_id, user_id). Each row records the external CRM
-- record id we were given back on first provisioning, so a
-- subsequent login can upsert rather than creating a duplicate
-- record (CRM-04). Failures don't block login — they get
-- recorded so the admin UI can surface them later.
-- ============================================================

CREATE TABLE IF NOT EXISTS tenant_crm_providers (
    id               BIGSERIAL PRIMARY KEY,
    tenant_id        BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name             VARCHAR(255) NOT NULL,
    provider_type    VARCHAR(32) NOT NULL
        CHECK (provider_type IN ('SALESFORCE','HUBSPOT','DYNAMICS','PIPEDRIVE')),
    base_url         VARCHAR(1024) NOT NULL,
    api_token_enc    TEXT NOT NULL,
    field_mappings   JSONB NOT NULL,
    match_keys       JSONB,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    dedupe_enabled   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS tenant_crm_providers_tenant_name_uq
    ON tenant_crm_providers (tenant_id, LOWER(name));

CREATE INDEX IF NOT EXISTS idx_tenant_crm_providers_tenant
    ON tenant_crm_providers (tenant_id);

CREATE TABLE IF NOT EXISTS crm_provisioning_log (
    id               BIGSERIAL PRIMARY KEY,
    provider_id      BIGINT NOT NULL REFERENCES tenant_crm_providers(id) ON DELETE CASCADE,
    tenant_id        BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id          BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    external_id      VARCHAR(255),
    match_key_value  VARCHAR(512),
    status           VARCHAR(32) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING','SUCCESS','FAILED','SKIPPED')),
    last_error       TEXT,
    attempts         INT NOT NULL DEFAULT 0,
    last_event_type  VARCHAR(64),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS crm_provisioning_log_provider_user_uq
    ON crm_provisioning_log (provider_id, user_id);

CREATE INDEX IF NOT EXISTS idx_crm_provisioning_log_tenant
    ON crm_provisioning_log (tenant_id);

CREATE INDEX IF NOT EXISTS idx_crm_provisioning_log_match
    ON crm_provisioning_log (provider_id, match_key_value);
