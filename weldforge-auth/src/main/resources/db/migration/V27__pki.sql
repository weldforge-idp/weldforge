-- ============================================================
-- V27: X.509 PKI module (PRD §3.6, X50-01..X50-05).
--
-- Each tenant owns one root CA row. Private keys never leave
-- the DB in the clear — they go through the AES-GCM
-- @Convert(EncryptedStringConverter) pattern (same one used
-- for Twilio auth tokens, LDAP bind passwords, tenant SAML
-- signing keys).
--
-- Issued end-entity certs live in issued_certificates. The
-- serial_number is drawn from a 128-bit random so it is
-- unique across all tenants — mirrors the collision-free
-- serial policy the Let's Encrypt reference PKIs use.
--
-- Revocation is append-only: we flip status + stamp
-- revoked_at / revocation_reason but never delete the row so
-- the CRL can re-list the entry until the cert's natural
-- expiry time.
-- ============================================================

CREATE TABLE IF NOT EXISTS tenant_certificate_authorities (
    id                BIGSERIAL PRIMARY KEY,
    tenant_id         BIGINT NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
    subject_dn        VARCHAR(1024) NOT NULL,
    certificate_pem   TEXT NOT NULL,
    private_key_enc   TEXT NOT NULL,
    key_algorithm     VARCHAR(32) NOT NULL DEFAULT 'RSA',
    key_size          INT NOT NULL DEFAULT 4096,
    signature_alg     VARCHAR(64) NOT NULL DEFAULT 'SHA256withRSA',
    crl_number        BIGINT NOT NULL DEFAULT 1,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at        TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS issued_certificates (
    id                   BIGSERIAL PRIMARY KEY,
    tenant_id            BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ca_id                BIGINT NOT NULL REFERENCES tenant_certificate_authorities(id) ON DELETE CASCADE,
    serial_number        VARCHAR(64) NOT NULL UNIQUE,
    subject_dn           VARCHAR(1024) NOT NULL,
    sans                 TEXT,
    certificate_pem      TEXT NOT NULL,
    fingerprint_sha256   VARCHAR(128) NOT NULL,
    status               VARCHAR(32) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE','REVOKED','SUSPENDED','EXPIRED')),
    revocation_reason    VARCHAR(64),
    revoked_at           TIMESTAMPTZ,
    issued_at            TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at           TIMESTAMPTZ NOT NULL,
    user_id              BIGINT REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_issued_certs_tenant
    ON issued_certificates (tenant_id);
CREATE INDEX IF NOT EXISTS idx_issued_certs_serial
    ON issued_certificates (serial_number);
CREATE INDEX IF NOT EXISTS idx_issued_certs_fingerprint
    ON issued_certificates (fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_issued_certs_expiring
    ON issued_certificates (status, expires_at);
