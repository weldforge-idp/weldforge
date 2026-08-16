-- B-MFA-2: single-use MFA challenge tokens.
--
-- The mfa_challenge JWT was valid for its full 5-minute window and could be
-- replayed to complete login more than once. Each challenge now carries a jti;
-- on the first successful MFA completion the jti is recorded here, and any
-- later attempt to reuse the same challenge token is rejected.
--
-- Rows are only relevant until the token expires (~5 min); a scheduled job
-- prunes expired rows.
CREATE TABLE consumed_mfa_challenge (
    jti         VARCHAR(64) PRIMARY KEY,
    expires_at  TIMESTAMP   NOT NULL,
    consumed_at TIMESTAMP   NOT NULL DEFAULT now()
);

CREATE INDEX idx_consumed_mfa_challenge_expires ON consumed_mfa_challenge (expires_at);
