-- Return-to-caller after a password reset.
--
-- When a reset is started from inside an app/OIDC flow we want the user, once
-- they have set a new password, returned to the sign-in screen with the
-- original OIDC continuation preserved (they then sign in and are bounced back
-- to the calling app). The return target cannot travel in the emailed link
-- (that would be an open-redirect vector), so it is captured at
-- forgot-password time, validated same-origin, and stored against the token.

-- Per-tenant on/off switch. ON: honour the return target and send the user
-- back into the flow. OFF: the reset ends on the standalone confirmation
-- screen. Defaults ON so existing tenants get the improved behaviour.
ALTER TABLE tenants
    ADD COLUMN return_to_caller_enabled boolean NOT NULL DEFAULT true;

-- The validated, same-origin (base64url-encoded) return target. NULL when the
-- reset was not started from within an app flow, or when the tenant has
-- return-to-caller disabled, or when the supplied target failed validation.
ALTER TABLE password_reset_tokens
    ADD COLUMN return_to text;
