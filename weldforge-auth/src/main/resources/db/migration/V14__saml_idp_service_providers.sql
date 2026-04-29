-- ============================================================
-- V14: SAML IdP mode — registered downstream Service Providers.
--
-- Each row represents an SP that this system can issue SAML
-- assertions to. Tenant-scoped via {tenant_id, entity_id};
-- attribute_mappings is a JSONB bag that lets admins remap
-- standard claim names per SP.
-- ============================================================

CREATE TABLE IF NOT EXISTS saml_service_providers (
    id                  BIGSERIAL    PRIMARY KEY,
    tenant_id           BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- SAML entity ID of the downstream SP.
    entity_id           VARCHAR(1024) NOT NULL,
    name                VARCHAR(255),

    -- Assertion Consumer Service URL.
    acs_url             VARCHAR(1024) NOT NULL,

    -- Single Logout Service URL (optional).
    slo_url             VARCHAR(1024),

    -- PEM-encoded X.509 certificate for SP request signature verification.
    sp_certificate      TEXT,

    -- NameID format to use in assertions for this SP.
    name_id_format      VARCHAR(128) NOT NULL
                        DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',

    -- Per-SP attribute name remapping, e.g.
    -- {"email":"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"}
    attribute_mappings  JSONB,

    enabled             BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS saml_sp_tenant_entity_uq
    ON saml_service_providers (tenant_id, entity_id);

CREATE INDEX IF NOT EXISTS idx_saml_sp_tenant
    ON saml_service_providers (tenant_id);
