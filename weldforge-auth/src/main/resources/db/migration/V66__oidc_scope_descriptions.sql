-- Scopes a person can read before agreeing to them.
--
-- Scope names are free strings today and the consent screen prints them raw,
-- so a person approving `board.view` is approving a string. For a go-between
-- acting on someone's behalf the consent screen is the ONLY place that
-- permission is explained, which makes "card.decide" the whole of what they
-- were told.
--
-- Per tenant, not per client: a scope means the same thing everywhere inside a
-- tenant, and a tenant routinely hosts several clients. Registering the
-- meaning once is what keeps two clients from explaining the same permission
-- two different ways.
--
-- Descriptions are keyed by language tag -- {"en": "...", "de": "..."} -- so a
-- consent screen can answer in the language the browser asked for. English is
-- the fallback; a scope with no description at all falls back to its own name,
-- which is exactly today's behaviour, so an unregistered scope is no worse off
-- than it is now.

CREATE TABLE IF NOT EXISTS oidc_scopes (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          VARCHAR(128) NOT NULL,
    descriptions  JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMP   NOT NULL DEFAULT now(),
    updated_at    TIMESTAMP   NOT NULL DEFAULT now()
);

-- One meaning per name per tenant. Two rows for the same scope would make
-- which description a person sees a matter of row order.
CREATE UNIQUE INDEX IF NOT EXISTS oidc_scopes_tenant_name_uq
    ON oidc_scopes (tenant_id, name);

COMMENT ON TABLE oidc_scopes IS
    'Per-tenant OIDC scope registry: the words shown on the consent screen and '
    'the names advertised in scopes_supported.';

COMMENT ON COLUMN oidc_scopes.descriptions IS
    'Language tag to description, e.g. {"en": "See your board", "de": "Ihr Board sehen"}. '
    'English is the fallback; the scope name itself is the last resort.';
