-- Link an authorization code to the refresh-token family it produced, so a
-- replayed code can revoke what the first, legitimate exchange handed out
-- (CONF-1.2, RFC 6749 §4.1.2).
--
-- Rejecting the replay is only the visible half of the rule. The other half is
-- what the replay MEANS: the code reached someone who was not supposed to have
-- it. Whether the attacker won the race or lost it, the tokens minted from that
-- code are now suspect -- and if they lost, the victim keeps a live session and
-- gets no signal at all, because from their side the login simply worked.
--
-- The codebase already treats a family as the unit of revocation for exactly
-- this class of event: RefreshTokenService kills the whole family on reuse
-- detection. A replayed code is the same signal one hop earlier, so it gets the
-- same response. This column is the missing link between the two -- at replay
-- time the code row is all we have, and it did not record what it produced.
--
-- Nullable, and deliberately so. A code may legitimately have no family: the
-- client was not registered for refresh_token, or the exchange never happened,
-- or the row predates this column. Those cases revoke nothing extra and are not
-- errors. No foreign key either -- refresh-token families are pruned on their
-- own schedule, and a constraint would either block that pruning or cascade
-- deletes back onto the audit trail this column exists to support.

ALTER TABLE oauth_authorization_codes
    ADD COLUMN issued_family_id UUID;

COMMENT ON COLUMN oauth_authorization_codes.issued_family_id IS
    'The refresh-token family minted when this code was exchanged. On replay '
    'the family is revoked, so a leaked code cannot leave a live session '
    'behind (RFC 6749 section 4.1.2). NULL when the client holds no '
    'refresh_token grant, when the code was never exchanged, or for rows '
    'predating this column.';
