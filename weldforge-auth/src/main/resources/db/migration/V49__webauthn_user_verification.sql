-- Record whether a WebAuthn credential was enrolled under a user-verification
-- requirement, so UV can be demanded of new credentials without breaking the
-- ones already in the field (CONF-3.2).
--
-- A credential used as a SECOND factor should verify the user -- a PIN, a
-- fingerprint, something beyond mere possession -- or the "second factor" is
-- only "the key is plugged in". Both ceremonies asked for PREFERRED, which an
-- authenticator is free to ignore, so a credential may or may not actually do
-- it and the server never recorded which.
--
-- Flipping the assertion ceremony to REQUIRED globally would lock out every
-- credential enrolled on an authenticator with no UV capability. So the
-- requirement is recorded per credential at ENROLMENT, where the choice is
-- being made, and the assertion ceremony asks for REQUIRED only when every one
-- of that user's credentials was enrolled under it.
--
-- DEFAULT FALSE is the honest value for existing rows: they were enrolled under
-- PREFERRED and we have no evidence about what the authenticator actually did.
-- New enrolments set it true. The population therefore self-heals as users
-- re-enrol, and `mfa.webauthn.legacy_uv` counts assertions still relying on a
-- grandfathered credential so the fallback can be retired on evidence.

ALTER TABLE user_mfa_factors
    ADD COLUMN uv_required BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN user_mfa_factors.uv_required IS
    'WebAuthn only: true when this credential was enrolled under a REQUIRED '
    'user-verification policy. The assertion ceremony demands UV only when all '
    'of a user''s credentials carry it, so grandfathered credentials keep '
    'working. FALSE for credentials enrolled before this column existed.';
