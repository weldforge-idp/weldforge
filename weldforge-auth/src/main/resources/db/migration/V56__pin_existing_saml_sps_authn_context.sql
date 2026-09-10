-- Pin every SAML SP that predates CONF-5.1 to the legacy authentication
-- context, as the outward-facing change register promised.
--
-- V55 made AuthnContextClassRef derive from how the user actually signed in,
-- and made that the default for every SP at once. The register in
-- docs/product/standards-conformance-backlog.md §6 said the opposite for SPs
-- that already existed: "Per-SP opt-in, current value the default for
-- existing SPs", with 30 days' notice. An SP that accepts only the old
-- literal breaks the day one of its users signs in with a security key, and
-- to that SP it looks like an IdP outage rather than a policy change.
--
-- So every SP registered before this migration keeps receiving
-- PasswordProtectedTransport, exactly as before V55, until an admin clears the
-- pin (PUT /api/admin/saml/service-providers/{id} with
-- "authnContextOverride": "") once that SP's owners are ready. SPs
-- registered from now on get the truthful value unless they ask otherwise.
--
-- An override that is already set was chosen deliberately and is left alone.

UPDATE saml_service_providers
   SET authn_context_override = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
 WHERE authn_context_override IS NULL;
