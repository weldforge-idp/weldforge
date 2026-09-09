-- SAML assertion fidelity (Sprint 5: CONF-5.1, 5.3, 5.4, 5.5).
--
-- Four columns and one table, grouped because they are one story: what the IdP
-- asserts about itself and about the user should be true, and where fixing that
-- changes bytes an SP already parses, the SP opts in rather than being
-- surprised.

-- ---------------------------------------------------------------------------
-- CONF-5.4: a real X.509 certificate per signing key.
--
-- Three things disagreed. The XML signature carried a bare <ds:KeyValue> (raw
-- modulus and exponent); the published metadata advertised an
-- <ds:X509Certificate> whose contents were actually a raw SubjectPublicKeyInfo
-- and not a certificate at all; and the assertion Issuer ({slug}-idp) was not
-- the metadata entityID. Each breaks a different SP implementation, which is
-- why this went unnoticed: whichever one a tenant used, the others were
-- somebody else's problem.
--
-- Minted lazily for existing keys on first use, so no backfill is needed and
-- rotation produces one automatically.
ALTER TABLE tenant_signing_keys
    ADD COLUMN certificate_pem TEXT;

COMMENT ON COLUMN tenant_signing_keys.certificate_pem IS
    'Self-signed X.509 certificate wrapping this key, used in SAML signature '
    'KeyInfo and published metadata. NULL until first minted; generated lazily '
    'so existing keys need no backfill.';

-- ---------------------------------------------------------------------------
-- CONF-5.1: let an SP pin the authentication context it already expects.
--
-- AuthnContextClassRef has been a hardcoded PasswordProtectedTransport on every
-- assertion, so a user who authenticated with a security key was described to
-- the SP as having typed a password. It now reflects the session's actual
-- factors -- but an SP configured to accept ONLY the old literal would break on
-- the day a user enables MFA, and that failure would look like an IdP outage
-- rather than a policy mismatch. Pinning is the escape hatch for those SPs.
ALTER TABLE saml_service_providers
    ADD COLUMN authn_context_override VARCHAR(255);

COMMENT ON COLUMN saml_service_providers.authn_context_override IS
    'When set, every assertion to this SP uses this AuthnContextClassRef '
    'verbatim instead of one derived from the session. For SPs that match on a '
    'fixed value and would otherwise break when a user enables MFA.';

-- ---------------------------------------------------------------------------
-- CONF-5.4 (issuer half): opt in to the entityID as Issuer.
--
-- Deliberately per-SP and defaulting to the legacy value. Changing the Issuer
-- is the single most breaking thing in this migration: an SP matches inbound
-- assertions against a configured issuer string, so flipping it globally would
-- reject every assertion until each SP was reconfigured, and there is no way
-- from here to know which have been.
ALTER TABLE saml_service_providers
    ADD COLUMN use_entity_id_as_issuer BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN saml_service_providers.use_entity_id_as_issuer IS
    'When true the assertion Issuer is the metadata entityID, which is what a '
    'conformant SP expects. Defaults false to preserve the legacy '
    '{slug}-idp value: changing it without the SP reconfiguring first rejects '
    'every assertion.';

-- ---------------------------------------------------------------------------
-- CONF-5.5: a tenant-level default that metadata can state honestly.
--
-- IdP metadata hardcoded WantAuthnRequestsSigned="false" while enforcement was
-- already per-SP. That is worse than cosmetic: a conformant SP reads the
-- metadata, concludes it need not sign, and then breaks the moment
-- want_authn_request_signed is turned on for it. The metadata should describe
-- the tenant's intent so the SP signs BEFORE enforcement starts.
ALTER TABLE tenants
    ADD COLUMN saml_want_authn_requests_signed BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN tenants.saml_want_authn_requests_signed IS
    'Advertised in this tenant''s IdP metadata as WantAuthnRequestsSigned. '
    'Enforcement stays per-SP; this is the tenant''s stated intent, so an SP '
    'can start signing before enforcement is switched on for it.';

-- ---------------------------------------------------------------------------
-- CONF-5.3: AuthnRequest replay protection.
--
-- A captured AuthnRequest could be replayed to mint a second assertion. The
-- mitigations were real but incidental -- an authenticated browser session is
-- still required, and ACS and Audience come from stored SP config rather than
-- the request -- and none of them is the control.
--
-- Retention is bounded by expires_at rather than kept forever: a request older
-- than its window is refused on freshness grounds anyway, so the row stops
-- carrying information. Same shape as consumed_mfa_challenge in V43.
CREATE TABLE saml_request_replay (
    request_id  VARCHAR(255) PRIMARY KEY,
    tenant_id   BIGINT    NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sp_entity_id VARCHAR(512),
    seen_at     TIMESTAMP NOT NULL,
    expires_at  TIMESTAMP NOT NULL
);

CREATE INDEX idx_saml_replay_expires ON saml_request_replay (expires_at);

COMMENT ON TABLE saml_request_replay IS
    'AuthnRequest IDs already processed, so a captured request cannot be '
    'replayed to mint a second assertion. Pruned once expired.';
