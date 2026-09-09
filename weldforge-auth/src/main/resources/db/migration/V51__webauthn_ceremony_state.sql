-- Move WebAuthn ceremony state out of the application process (CONF-3.1).
--
-- A WebAuthn ceremony is two requests. The first mints a random challenge and
-- the server must remember it; the second presents the authenticator's response
-- and the server checks it against what it issued. That memory lived in two
-- ConcurrentHashMaps on whichever instance served the first request.
--
-- On a single replica that mostly works, and the class javadoc said as much.
-- Two things make it worth fixing anyway:
--
--   1. ROLLING UPDATES ALREADY BREAK IT. The deployments run maxUnavailable: 0
--      with maxSurge: 1, so two pods exist during every rollout and the
--      ingress load-balances across both. A ceremony spanning a deploy fails
--      with "Unknown or expired WebAuthn registration challenge" -- and a user
--      who sees that while enrolling a security key reasonably concludes their
--      key is broken.
--   2. IT IS THE ONLY THING BLOCKING A SECOND REPLICA. Everything else in this
--      service is stateless by construction: no HttpSession, and the OIDC
--      consent screen round-trips its entire state through signed hidden
--      fields rather than server-side storage. This is the last exception.
--
-- The maps were also unbounded and never evicted, so an abandoned ceremony --
-- a user who closes the tab at the browser prompt, which is common -- leaked
-- until the next restart. A row with an expiry and a prune job fixes that too.
--
-- Keyed by the challenge token the client already round-trips, so no new
-- identifier crosses the wire. The options blob is the library's own JSON, held
-- opaque on purpose: parsing and rebuilding it would risk a semantic difference
-- between what was issued and what is verified, and that difference is exactly
-- what a challenge is supposed to prevent.

CREATE TABLE webauthn_ceremony (
    challenge_token VARCHAR(128) PRIMARY KEY,
    user_id         BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ceremony_type   VARCHAR(16)  NOT NULL,
    options_json    TEXT         NOT NULL,
    created_at      TIMESTAMP    NOT NULL,
    expires_at      TIMESTAMP    NOT NULL,
    CONSTRAINT webauthn_ceremony_type CHECK (ceremony_type IN ('REGISTRATION', 'ASSERTION'))
);

-- The prune job deletes by expiry, and it is the only query that is not a
-- primary-key lookup.
CREATE INDEX idx_webauthn_ceremony_expires ON webauthn_ceremony (expires_at);

COMMENT ON TABLE webauthn_ceremony IS
    'In-flight WebAuthn registration and assertion ceremonies. Replaces the '
    'per-process maps that failed across a rolling update and blocked running '
    'more than one replica. Rows are single-use and pruned once expired.';

COMMENT ON COLUMN webauthn_ceremony.options_json IS
    'The Yubico library''s own serialised ceremony options, held opaque. '
    'Re-parsing and rebuilding them could introduce a difference between what '
    'was issued and what is verified, which is what the challenge exists to '
    'prevent.';
