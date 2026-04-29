-- ============================================================
-- V25: Webhook subscriptions + deliveries (PRD API-05, API-06, SSO-09).
--
-- Each tenant may register zero or more HTTP endpoints to
-- receive lifecycle events. Subscriptions filter by an ordered
-- list of event-type globs (e.g. ["user.*","auth.login.*"]).
-- NULL/empty means "all events".
--
-- Every dispatch creates a webhook_deliveries row so we can
-- retry with backoff, observe failure state, and dead-letter
-- after max_attempts. The delivery row is the source of truth
-- for retry scheduling — a background job scans it by
-- next_attempt_at.
--
-- The secret is stored encrypted-at-rest via the existing
-- @Convert(EncryptedStringConverter) pattern used by other
-- sensitive columns (Twilio auth tokens, SAML signing keys).
-- ============================================================

CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          VARCHAR(255) NOT NULL,
    target_url    VARCHAR(2048) NOT NULL,
    secret_enc    TEXT NOT NULL,
    event_filters JSONB,
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    max_attempts  INT NOT NULL DEFAULT 6,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS webhook_subscriptions_tenant_name_uq
    ON webhook_subscriptions (tenant_id, LOWER(name));

CREATE INDEX IF NOT EXISTS idx_webhook_subscriptions_tenant
    ON webhook_subscriptions (tenant_id);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id               BIGSERIAL PRIMARY KEY,
    subscription_id  BIGINT NOT NULL REFERENCES webhook_subscriptions(id) ON DELETE CASCADE,
    tenant_id        BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type       VARCHAR(128) NOT NULL,
    event_id         VARCHAR(64) NOT NULL,
    payload_json     TEXT NOT NULL,
    signature        VARCHAR(128) NOT NULL,
    status           VARCHAR(32) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING','SUCCESS','FAILED','DEAD_LETTER')),
    attempt_count    INT NOT NULL DEFAULT 0,
    last_response_code INT,
    last_error       TEXT,
    next_attempt_at  TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivered_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_retry
    ON webhook_deliveries (status, next_attempt_at);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_subscription
    ON webhook_deliveries (subscription_id, created_at DESC);
