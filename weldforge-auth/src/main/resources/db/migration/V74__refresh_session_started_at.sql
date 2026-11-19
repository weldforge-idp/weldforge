-- ============================================================================
-- V74 -- an absolute limit on a session (Proboulos WF-2, security review
-- 2026-11-15).
--
-- Rotation set each successor's expiry to now + lifetime, so a refresh family
-- used at least once per lifetime never ended. Each row now records when the
-- sign-in that created its family happened; rotation copies it forward and no
-- successor expires after it plus app.security.refresh-token.absolute-lifetime-days.
--
-- Existing families are backfilled from their earliest row, which is the
-- closest record of the sign-in that remains. A family older than the absolute
-- limit therefore ends at its next refresh: that is the point of the change.
-- ============================================================================

ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS session_started_at TIMESTAMP;

UPDATE refresh_tokens r
   SET session_started_at = f.started
  FROM (SELECT family_id, MIN(issued_at) AS started
          FROM refresh_tokens
         GROUP BY family_id) f
 WHERE r.family_id = f.family_id
   AND r.session_started_at IS NULL;

ALTER TABLE refresh_tokens
    ALTER COLUMN session_started_at SET NOT NULL;

COMMENT ON COLUMN refresh_tokens.session_started_at IS
    'When the sign-in that created this family happened. Copied forward on rotation; no token in the family expires after it plus the absolute session lifetime.';
