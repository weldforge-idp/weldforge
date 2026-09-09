-- Remember that a user consented, so `prompt` can be answered (CONF-2.3).
--
-- The consent screen was rendered on EVERY authorization request, and no record
-- of the decision was kept. Two consequences:
--
--   1. `prompt=none` could not be honoured. A relying party doing a silent
--      session check -- the standard way to refresh a session without
--      interrupting the user -- got a full consent page rendered into a hidden
--      iframe instead of `interaction_required`. The parameter exists to
--      prevent exactly that.
--   2. Users re-consented on every single login, which trains people to click
--      through the one screen that asks them to think.
--
-- A grant is (user, client, scopes). Scope is part of the key, not an attribute
-- of it: consenting to `openid email` must NOT silently authorise a later
-- request for `openid email admin:write`. Storing the granted set and comparing
-- against the requested one is what keeps the second prompt appearing when it
-- should.
--
-- Scopes are stored sorted and space-separated so the comparison is order-
-- insensitive without needing a query-time sort.
--
-- No expiry column. A consent that silently lapsed would produce a surprise
-- prompt mid-integration with no way for the relying party to distinguish it
-- from a revocation; if a lifetime is ever wanted it should be a deliberate
-- per-tenant policy rather than a column default nobody chose.

CREATE TABLE oidc_consent_grants (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id   BIGINT      NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    scopes      TEXT        NOT NULL,
    granted_at  TIMESTAMP   NOT NULL,
    CONSTRAINT uq_consent_user_client UNIQUE (user_id, client_id)
);

CREATE INDEX idx_consent_grants_tenant ON oidc_consent_grants (tenant_id);

COMMENT ON TABLE oidc_consent_grants IS
    'Records that a user consented to a client for a specific scope set, so '
    'prompt=none can be answered and users are not re-prompted on every login. '
    'One row per user+client: a new scope set replaces the old one, and a '
    'request for scopes wider than the stored set prompts again.';

COMMENT ON COLUMN oidc_consent_grants.scopes IS
    'Sorted, space-separated granted scopes. Sorted at write time so the '
    'comparison against a request is order-insensitive without a query-time sort.';
