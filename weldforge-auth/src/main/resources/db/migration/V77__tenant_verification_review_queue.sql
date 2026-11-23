-- Identity-proofing V2b: domain-gate the email verification challenge.
--
-- The V2a email challenge is auto-issued to a tenant's contact_email. V2b
-- refuses to auto-issue it when the contact_email's domain does not match one
-- of the tenant's registered OIDC webOrigins (a free-mail or mismatched
-- contact is exactly how a lookalike tenant would "verify" itself). Such a
-- request falls through to a SUPER_ADMIN review queue instead of silently
-- sending the challenge.
--
-- Two columns carry that queue on the tenant itself: a flag the super-admin
-- lists on, and the human-readable reason the gate declined (shown in the
-- queue). A super-admin approving the review clears the flag and issues the
-- challenge, bypassing the gate because a human has now vouched for it.
ALTER TABLE tenants ADD COLUMN verification_review_required BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tenants ADD COLUMN verification_review_reason   VARCHAR(255);

-- The queue is listed by super-admins; a partial index keeps that scan cheap
-- as the tenant table grows (only flagged rows are indexed).
CREATE INDEX idx_tenants_verification_review
    ON tenants (id)
    WHERE verification_review_required = TRUE;
