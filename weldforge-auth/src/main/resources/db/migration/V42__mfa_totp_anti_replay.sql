-- B-MFA-1: TOTP anti-replay (RFC 6238).
--
-- A valid TOTP code is accepted for its whole ±1-step (~90s) validity window,
-- so the same code could be replayed multiple times until it naturally
-- expires. Track the last accepted time-step per factor and reject any code
-- whose step is <= the last accepted one.
--
-- Nullable: existing factors have no recorded step yet; the first successful
-- verification after this migration sets it.
ALTER TABLE user_mfa_factors ADD COLUMN last_totp_step BIGINT;
