-- Per-tenant feature toggles + custom branding for the login screen.
--
-- registration_enabled / password_recovery_enabled gate /api/auth/register
-- and /api/auth/forgot-password — disabled flag means those endpoints return
-- 404, the Angular login UI hides the corresponding link, and the Cucumber
-- BDD feature `tenant_branding.feature` documents the visible behaviour.
--
-- email_verification_required: when true (default), self-registered users
-- must click a verification link before they can sign in.
--
-- branding: free-form JSONB. The Angular SPA reads keys like:
--   logoUrl, primaryColor, primaryDark, accentColor, surfaceColor,
--   inkColor, displayFont, bodyFont, tagline, signInLabel, customCssUrl
-- and applies them as CSS-variable overrides at runtime. Unknown keys are
-- ignored, so adding new tokens later is non-breaking.

ALTER TABLE tenants
    ADD COLUMN registration_enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN password_recovery_enabled   BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN email_verification_required BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN branding                    JSONB;
