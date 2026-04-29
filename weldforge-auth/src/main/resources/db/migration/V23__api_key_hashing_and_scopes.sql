-- ============================================================
-- V23: Hashed API keys + scoping (PRD TOK-01, TOK-02).
--
-- Previously app_clients.api_key stored the literal key. That's
-- unacceptable: anyone with read access to the DB row could
-- replay the key. Post-migration:
--
--   - api_key_prefix  holds the first 12 chars of the key
--     (e.g. "wf_live_a1b2"), used for UI display and audit.
--   - api_key_hash    holds SHA-256(raw key), hex-encoded. The
--     authentication filter hashes the incoming header and
--     compares against this column. The raw key is never stored
--     on disk after creation.
--   - scopes          is an ordered JSONB array of
--     {"path": "...", "methods": [...]} entries. When non-empty
--     the filter only allows requests matching at least one
--     entry. NULL / empty means "no restriction" (legacy).
--
-- The legacy api_key column is kept so in-flight keys keep
-- working — existing rows get backfilled into prefix+hash and
-- api_key is zeroed on first admin edit. New rows always set
-- api_key to NULL.
-- ============================================================

-- pgcrypto for digest(). Harmless if already present.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE app_clients
    ADD COLUMN IF NOT EXISTS api_key_prefix VARCHAR(32),
    ADD COLUMN IF NOT EXISTS api_key_hash   VARCHAR(128),
    ADD COLUMN IF NOT EXISTS scopes         JSONB;

-- Backfill: compute prefix + SHA-256 from any plaintext key
-- still sitting in api_key. Older rows will be authenticatable
-- by both paths until the next rotation.
UPDATE app_clients
SET api_key_prefix = LEFT(api_key, 12),
    api_key_hash   = ENCODE(DIGEST(api_key, 'sha256'), 'hex')
WHERE api_key IS NOT NULL
  AND api_key_hash IS NULL;

-- Relax the NOT NULL on api_key so new rows can store hash-only.
ALTER TABLE app_clients ALTER COLUMN api_key DROP NOT NULL;

CREATE INDEX IF NOT EXISTS idx_app_clients_api_key_hash
    ON app_clients (api_key_hash);

CREATE INDEX IF NOT EXISTS idx_app_clients_api_key_prefix
    ON app_clients (api_key_prefix);
