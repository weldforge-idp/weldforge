-- Tenant identity-proofing — V1.
--
-- The per-tenant subdomain feature (docs/auth-url-spec.md) makes
-- {slug}.sso.weldforge.org a phishing vector: a malicious operator
-- could register a tenant named "acme-bank-secure" and impersonate
-- the real acme to that tenant's users.
--
-- V1 closes the gap with three additive columns + a SUPER_ADMIN-only
-- verify flow:
--
--   contact_email           who the platform contacts about the tenant.
--                           Stored at create-time; today only informational,
--                           V2 will use it as the target of an email-based
--                           verification challenge.
--
--   verified_at             null = unverified (default). Set when a
--                           SUPER_ADMIN explicitly marks the tenant as
--                           identity-proofed (manual review today; V2 may
--                           auto-flip on successful email challenge).
--
--   verified_by_user_id     audit trail — who flipped the bit.
--                           ON DELETE SET NULL keeps the column even after
--                           the verifier's user row is gone.
--
-- The public branding endpoint exposes a derived boolean `verified`
-- (verified_at != null). The Angular auth-shell shows an "Unverified
-- tenant" warning badge when this is false, so end users can spot a
-- look-alike tenant before they type credentials.
--
-- All existing tenants land with verified_at = null. An operator should
-- mark legitimate, customer-facing tenants verified explicitly via
-- POST /api/admin/tenants/{id}/verify.
ALTER TABLE tenants
    ADD COLUMN contact_email       VARCHAR(255),
    ADD COLUMN verified_at         TIMESTAMP NULL,
    ADD COLUMN verified_by_user_id BIGINT NULL
        REFERENCES users(id) ON DELETE SET NULL;

-- Partial index for the verify-status query path on the branding
-- endpoint — every public auth-shell render fetches branding, so the
-- `verified_at IS NULL` filter is hot.
CREATE INDEX idx_tenants_verified_status
        ON tenants ((verified_at IS NULL));
