-- ============================================================
-- V22: Federation rules engine (PRD FED-02, FED-04).
--
-- matching_rules: ordered list of rules describing how an
-- incoming federated identity (SAML assertion, OAuth2 userinfo)
-- is resolved to a local user. Each rule has a strategy
-- ("exact_email", "normalised_email", "phone", "external_id")
-- and a source claim path. Rules are evaluated in order; first
-- match wins.
--
-- claim_transforms: ordered list of attribute-mapping rules
-- with JSONPath expressions, an optional condition (also
-- JSONPath), and a target user field. Lets tenants rewrite
-- provider-specific claim shapes into the shape our user
-- model expects (e.g. flatten nested IdP attributes, pick
-- the first of many emails, derive username from upn, etc.).
--
-- Both columns are nullable: tenants that don't configure
-- rules continue to use the hard-coded defaults.
-- ============================================================

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS matching_rules   JSONB,
    ADD COLUMN IF NOT EXISTS claim_transforms JSONB;
