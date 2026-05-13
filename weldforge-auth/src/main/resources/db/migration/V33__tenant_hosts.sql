-- Maps a public hostname (e.g. idp.writebuddy.org) to an existing tenant so
-- OIDC / SAML endpoints can be served under a customer-owned domain. When a
-- request arrives on a mapped host, HostAliasFilter rewrites it internally
-- to /t/{slug}/... and marks the request so OidcDiscoveryControllerHelper
-- builds a clean issuer URL without the /t/{slug} suffix.

CREATE TABLE tenant_hosts (
    host        VARCHAR(253) PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at  TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenant_hosts_tenant_id ON tenant_hosts(tenant_id);
