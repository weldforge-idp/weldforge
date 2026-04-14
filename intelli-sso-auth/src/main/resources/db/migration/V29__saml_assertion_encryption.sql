-- ============================================================
-- V29: SAML assertion encryption (PRD SAM-04).
--
-- Per-SP opt-in: when encrypt_assertions = TRUE and the SP
-- has a certificate on sp_certificate, the IdP wraps the
-- signed <Assertion> element in <EncryptedAssertion> using
-- AES-256-CBC for the content key and RSA-OAEP for the key
-- wrap. The SP cert column already exists (V14); we only
-- need the new flag.
-- ============================================================

ALTER TABLE saml_service_providers
    ADD COLUMN IF NOT EXISTS encrypt_assertions BOOLEAN NOT NULL DEFAULT FALSE;
