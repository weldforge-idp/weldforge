-- ============================================================
-- V26: Per-tenant LDAP / Active Directory upstream providers
--      (PRD DIR-01, DIR-02).
--
-- A tenant may register zero or more LDAP providers. When a
-- user attempts password authentication, AuthService consults
-- the enabled LDAP providers before falling back to the local
-- users table. This keeps a break-glass local admin usable
-- while letting enterprise tenants point WeldForge at their
-- existing directory.
--
-- Fields mirror the Spring LDAP / JNDI configuration surface:
--   url                  — ldap:// or ldaps:// (port optional)
--   bind_dn              — service account used to search for
--                          the user's DN; nullable for anonymous
--                          bind directories
--   bind_password_enc    — AES-GCM encrypted via @Convert(Encrypted…)
--   user_base_dn         — subtree to search for users
--   user_search_filter   — {0} is replaced by the submitted
--                          username; for AD the common filter is
--                          (|(userPrincipalName={0})(sAMAccountName={0}))
--   email/name/username  — attribute names to lift into the
--                          canonical user model after a successful
--                          bind
-- ============================================================

CREATE TABLE IF NOT EXISTS tenant_ldap_providers (
    id                   BIGSERIAL PRIMARY KEY,
    tenant_id            BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                 VARCHAR(255) NOT NULL,
    provider_type        VARCHAR(32) NOT NULL DEFAULT 'LDAP'
        CHECK (provider_type IN ('LDAP','ACTIVE_DIRECTORY')),
    url                  VARCHAR(1024) NOT NULL,
    bind_dn              VARCHAR(512),
    bind_password_enc    TEXT,
    user_base_dn         VARCHAR(512) NOT NULL,
    user_search_filter   VARCHAR(512) NOT NULL DEFAULT '(uid={0})',
    email_attribute      VARCHAR(64) NOT NULL DEFAULT 'mail',
    name_attribute       VARCHAR(64) NOT NULL DEFAULT 'cn',
    username_attribute   VARCHAR(64) NOT NULL DEFAULT 'uid',
    start_tls            BOOLEAN NOT NULL DEFAULT FALSE,
    connect_timeout_ms   INT NOT NULL DEFAULT 5000,
    read_timeout_ms      INT NOT NULL DEFAULT 10000,
    enabled              BOOLEAN NOT NULL DEFAULT TRUE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS tenant_ldap_providers_tenant_name_uq
    ON tenant_ldap_providers (tenant_id, LOWER(name));

CREATE INDEX IF NOT EXISTS idx_tenant_ldap_providers_tenant
    ON tenant_ldap_providers (tenant_id);
