-- B-OIDC-7: stop storing OIDC client secrets reversibly.
--
-- client_secret_enc holds the secret under EncryptedStringConverter, i.e.
-- recoverable by anyone with the database and app.crypto.secret. The secret is
-- only ever compared, never re-displayed (shown once on create/rotate, exactly
-- like the RFC 7592 registration access token on this same table, which is
-- already a SHA-256 hash), so reversibility buys nothing and costs the property
-- its neighbour was deliberately given.
--
-- Migrate-on-rotation, not a backfill: a hash cannot be derived from an
-- encrypted value without decrypting it, and doing that in a migration would
-- put every plaintext secret through the app's crypto on the DB box for no
-- lasting gain. Instead, new and rotated clients store client_secret_hash and
-- leave client_secret_enc null; existing clients keep verifying against the
-- encrypted form until they next rotate. sso.oidc.client_secret.legacy_verify
-- counts the stragglers so an operator can see who has not moved yet.
ALTER TABLE oidc_clients ADD COLUMN client_secret_hash VARCHAR(64);

-- Hash-only clients store no encrypted secret, so the column can no longer be
-- NOT NULL. A client authenticates when exactly one of the two is set and
-- matches; a public client sets neither.
ALTER TABLE oidc_clients ALTER COLUMN client_secret_enc DROP NOT NULL;
