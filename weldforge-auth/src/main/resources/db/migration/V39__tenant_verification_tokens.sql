-- Tenant identity-proofing V2a — email-based verification challenge.
--
-- The V38 migration added the verified_at bit and the SUPER_ADMIN-only
-- /verify endpoint. That works but doesn't prove the tenant actually
-- controls its claimed contact_email — a super-admin just has to take
-- the requester's word for it.
--
-- V2a issues a one-time token to the contact_email and flips
-- verified_at only when the recipient clicks through. This proves
-- email-control: a malicious operator claiming to be Acme can't
-- collect the verification email unless they actually own Acme's
-- inbox.
--
-- (V2b will gate this on the contact_email DOMAIN matching the
-- tenant's registered OIDC webOrigins, closing the "use a free
-- gmail" cheat. V2c adds watchword auto-flagging at slug creation.)
CREATE TABLE tenant_verification_tokens (
    id                  BIGSERIAL    PRIMARY KEY,

    tenant_id           BIGINT       NOT NULL
        REFERENCES tenants(id) ON DELETE CASCADE,

    -- SHA-256 of the raw token. The raw token only lives in the email
    -- body and is never persisted — mirroring the password-reset and
    -- email-verification token tables.
    token_hash          VARCHAR(64)  NOT NULL UNIQUE,

    -- Snapshot of contact_email at the time the challenge was minted.
    -- An operator who changes contact_email mid-challenge gets a fresh
    -- token to the new address — the in-flight token still points at
    -- the previous address it was actually sent to, for audit clarity.
    contact_email       VARCHAR(255) NOT NULL,

    expires_at          TIMESTAMP    NOT NULL,
    used_at             TIMESTAMP    NULL,
    created_at          TIMESTAMP    NOT NULL DEFAULT now(),

    -- Audit trail — who initiated the challenge. Nullable for
    -- system-driven flows (e.g. auto-issued on tenant creation in V2b).
    created_by_user_id  BIGINT       NULL
        REFERENCES users(id) ON DELETE SET NULL
);

-- Lookup pattern at consume time is "find by token_hash" — already
-- covered by the UNIQUE constraint. For pending-challenge inspection
-- ("does tenant X have an active challenge in flight?") we want a
-- tenant_id index restricted to unused rows.
CREATE INDEX idx_tenant_verification_tokens_active
    ON tenant_verification_tokens (tenant_id, expires_at)
    WHERE used_at IS NULL;
