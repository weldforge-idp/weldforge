-- A verification or password-reset token proves control of the mailbox it was
-- SENT to, not of whatever address the account holds when it is redeemed.
-- Without the address on the token, changing the account's email and then
-- redeeming a token mailed to the old one marked the NEW address verified
-- (security review 2026-11-15). Redemption now refuses a token whose address
-- does not match the account's, and a token with no address at all.
ALTER TABLE email_verification_tokens ADD COLUMN email VARCHAR(255);
ALTER TABLE password_reset_tokens     ADD COLUMN email VARCHAR(255);

-- Outstanding tokens are bound to the address the account holds now, so
-- links already in people's inboxes (including 7-day invites) keep working.
-- The one case this cannot repair is a token whose account changed its
-- address BEFORE this migration ran: its original address is not recorded
-- anywhere. Those expire on their own within days.
UPDATE email_verification_tokens t SET email = u.email
  FROM users u WHERE u.id = t.user_id AND t.used = false;
UPDATE password_reset_tokens t SET email = u.email
  FROM users u WHERE u.id = t.user_id AND t.used = false;
