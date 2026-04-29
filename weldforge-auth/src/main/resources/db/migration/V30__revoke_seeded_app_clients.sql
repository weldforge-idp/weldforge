-- ============================================================
-- V30: Revoke the app-client credentials seeded by V2.
--      (SECURITY_AUDIT_2026-04-15.md — CRITICAL-1)
--
-- V2__seed_app_clients.sql historically inserted two rows with
-- hardcoded plaintext API keys:
--
--   frontend-admin-portal  x-app-auth-1234567890abcdef
--   mobile-backend         x-app-auth-mobile-9876543210fedcba
--
-- The first was also embedded in the deployed admin SPA JS
-- bundle and therefore anonymously readable by any visitor to
-- admin.weldforge.org. Both keys were accepted by
-- AppAuthorizationFilter (via either the plaintext fallback or
-- the hash backfilled by V23).
--
-- This migration nulls every credential column on both rows
-- and disables them so neither lookup path in the filter can
-- authenticate them. The rows themselves are kept (not DELETE)
-- so any existing foreign key references (there shouldn't be
-- any, but defence in depth) don't break.
--
-- The WHERE clause matches by:
--   - legacy plaintext column api_key,
--   - hashed column api_key_hash (computed inline with pgcrypto),
--   - and the original client_name as a backstop.
-- Any one match is sufficient; an attacker-controlled row that
-- chose the same client_name but a different hash would be
-- unaffected, but that's fine because in that case the hash
-- wouldn't match the leaked key so it's a different credential.
-- ============================================================

UPDATE app_clients
SET enabled         = FALSE,
    api_key         = NULL,
    api_key_hash    = NULL,
    api_key_prefix  = NULL
WHERE api_key IN (
          'x-app-auth-1234567890abcdef',
          'x-app-auth-mobile-9876543210fedcba'
      )
   OR api_key_hash = ENCODE(DIGEST('x-app-auth-1234567890abcdef',        'sha256'), 'hex')
   OR api_key_hash = ENCODE(DIGEST('x-app-auth-mobile-9876543210fedcba', 'sha256'), 'hex')
   OR client_name  IN ('frontend-admin-portal', 'mobile-backend');
