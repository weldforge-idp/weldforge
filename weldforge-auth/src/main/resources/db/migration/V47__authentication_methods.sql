-- Carry the authentication methods (RFC 8176 `amr`) from the login that
-- established the session through to the OIDC tokens minted from it.
--
-- `amr` records *how* the user proved who they are: a password alone, or a
-- password plus a one-time code, or a WebAuthn assertion. Relying parties gate
-- on it — a secrets store may release a value only to a session established
-- with a phishing-resistant factor. That is a different question from which
-- factors the user has enrolled, so the claim cannot be recomputed at token
-- time from the user row: enrolment is what they *could* have used, `amr` is
-- what they *did* use. It has to travel with the grant.
--
-- The authorization code is the hop between the two: it is minted from an
-- authenticated session and redeemed later at the token endpoint, where no
-- session cookie is present. The refresh token is the same problem stretched
-- over a longer window — a refreshed access token describes the original
-- authentication event, so the methods ride along with the family.
--
-- Space-separated, the same encoding `amr` uses on the wire. NULL means the
-- grant predates this column; tokens minted from those carry no `amr` claim
-- at all, which is the honest reading — we do not know how that session was
-- established, and asserting a factor we cannot evidence is worse than
-- omitting the claim. They self-heal on the next login.

ALTER TABLE oauth_authorization_codes
    ADD COLUMN amr VARCHAR(255);

ALTER TABLE refresh_tokens
    ADD COLUMN amr VARCHAR(255);

COMMENT ON COLUMN oauth_authorization_codes.amr IS
    'Space-separated RFC 8176 authentication methods from the login that '
    'authorised this code. Copied onto the access and ID tokens at exchange. '
    'NULL for codes issued before the column existed.';

COMMENT ON COLUMN refresh_tokens.amr IS
    'Space-separated RFC 8176 authentication methods from the login that '
    'created this token family, so a refreshed access token still describes '
    'the original authentication event. NULL for pre-existing tokens.';
