-- ============================================================
-- V6: Per-tenant upstream SAML 2.0 Identity Provider config.
-- Registered rows are resolved at request time by the dynamic
-- DatabaseRelyingPartyRegistrationRepository keyed as
--   {tenantSlug}-saml-{providerKey}
-- e.g. "acme-saml-okta".
-- ============================================================

CREATE TABLE IF NOT EXISTS tenant_saml_providers (
    id                      BIGSERIAL PRIMARY KEY,
    tenant_id               BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- short key used in the registration id (kebab-case, alphanumerics)
    provider_key            VARCHAR(64)  NOT NULL,
    display_name            VARCHAR(128),

    -- IdP-side configuration ----------------------------------
    idp_entity_id           VARCHAR(1024) NOT NULL,
    idp_sso_url             VARCHAR(1024) NOT NULL,
    idp_slo_url             VARCHAR(1024),
    -- POST or REDIRECT
    sso_binding             VARCHAR(16)   NOT NULL DEFAULT 'POST',
    -- Full PEM-encoded signing certificate from the IdP's metadata
    idp_signing_certificate TEXT          NOT NULL,
    name_id_format          VARCHAR(64),

    -- Attribute name -> user field mapping --------------------
    email_attribute         VARCHAR(128)  NOT NULL DEFAULT 'email',
    name_attribute          VARCHAR(128)  NOT NULL DEFAULT 'name',

    -- Security posture ----------------------------------------
    want_assertions_signed  BOOLEAN       NOT NULL DEFAULT TRUE,
    want_authn_req_signed   BOOLEAN       NOT NULL DEFAULT FALSE,

    enabled                 BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at              TIMESTAMPTZ   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMPTZ   NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT tenant_saml_provider_key_format
        CHECK (provider_key ~ '^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$'),
    CONSTRAINT tenant_saml_providers_unique UNIQUE (tenant_id, provider_key)
);

CREATE INDEX IF NOT EXISTS idx_tsaml_tenant_enabled
    ON tenant_saml_providers (tenant_id) WHERE enabled = TRUE;
