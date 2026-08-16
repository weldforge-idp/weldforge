-- B-SAML-1(a): per-SP enforcement of signed AuthnRequests.
--
-- When true, the IdP verifies the XML signature on inbound AuthnRequest /
-- LogoutRequest messages from this SP against its registered certificate and
-- rejects unsigned or invalid ones. Defaults to false so existing SPs are
-- unaffected until an operator opts in.
ALTER TABLE saml_service_providers
    ADD COLUMN want_authn_request_signed BOOLEAN NOT NULL DEFAULT FALSE;
