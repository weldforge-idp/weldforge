-- ============================================================
-- V31: Platform + tenant billing (payment gateway abstraction)
--
-- Supports two scopes on the same table:
--   - PLATFORM: gateways WeldForge uses to bill its own
--     subscribers (Cloud Starter / Team / Business etc.)
--   - TENANT:   gateways a tenant owns credentials for, used
--     when the tenant bills its own end-users via the broker
--     endpoints.
--
-- The core invariant enforced here:
--   *** No tenant row is created before payment clears. ***
--
-- Onboarding flow:
--   pending_orders(CREATED → CHECKOUT_STARTED) ──┐
--       slug is reserved, 10-minute TTL          │
--                                                ▼
--       Stripe / Paddle / PayFast webhook → PAID
--       TenantProvisioningService.run()     → PROVISIONED
--       (failure → PROVISIONING_FAILED with 24h retry budget
--        → REFUNDED if budget exhausted)
-- ============================================================

-- ---- payment_gateways ---------------------------------------

CREATE TABLE payment_gateways (
    id                     BIGSERIAL PRIMARY KEY,
    scope                  VARCHAR(16)  NOT NULL
        CHECK (scope IN ('PLATFORM','TENANT')),
    tenant_id              BIGINT REFERENCES tenants(id) ON DELETE CASCADE,
    provider               VARCHAR(32)  NOT NULL,
        -- STRIPE | PADDLE | PAYFAST | YOCO | PEACH
    display_name           VARCHAR(128) NOT NULL,
    enabled                BOOLEAN      NOT NULL DEFAULT TRUE,
    priority               INT          NOT NULL DEFAULT 0,
        -- tie-break when two gateways quote the same fee; higher wins
    supported_currencies   JSONB        NOT NULL,
        -- JSON array of ISO 4217 uppercase: ["USD","EUR","ZAR"]
    supported_countries    JSONB,
        -- JSON array of ISO 3166-1 alpha-2 uppercase; NULL = any country
    config                 JSONB        NOT NULL DEFAULT '{}'::jsonb,
        -- non-secret provider config: webhook base URL override, API version, …
    credentials_encrypted  TEXT         NOT NULL,
        -- AES-GCM-256 ciphertext; key lives in k8s Secret payment-master-key
    fee_structure          JSONB        NOT NULL,
        -- { "percent": 2.9, "fixed_cents": 30,
        --   "intl_percent": 3.9, "intl_fixed_cents": 30,
        --   "conversion_percent": 0.5 }
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pg_scope_tenant_coherent
        CHECK ( (scope = 'PLATFORM' AND tenant_id IS NULL)
             OR (scope = 'TENANT'   AND tenant_id IS NOT NULL) )
);

CREATE UNIQUE INDEX payment_gateways_platform_unique
    ON payment_gateways (provider, display_name)
    WHERE scope = 'PLATFORM';

CREATE UNIQUE INDEX payment_gateways_tenant_unique
    ON payment_gateways (tenant_id, provider, display_name)
    WHERE scope = 'TENANT';

CREATE INDEX idx_payment_gateways_tenant
    ON payment_gateways (tenant_id)
    WHERE tenant_id IS NOT NULL;

CREATE INDEX idx_payment_gateways_enabled
    ON payment_gateways (scope, enabled);

-- ---- pending_orders -----------------------------------------

CREATE TABLE pending_orders (
    id                        BIGSERIAL   PRIMARY KEY,
    order_token               VARCHAR(64) NOT NULL UNIQUE,
        -- random; carried as Stripe client_reference_id for webhook match
    tier                      VARCHAR(32) NOT NULL,
    organisation              VARCHAR(255) NOT NULL,
    contact_name              VARCHAR(255) NOT NULL,
    contact_email             VARCHAR(320) NOT NULL,
    requested_tenant_slug     VARCHAR(64),
    region                    VARCHAR(32),
    billing_cycle             VARCHAR(16) NOT NULL
        CHECK (billing_cycle IN ('MONTHLY','ANNUAL')),
    currency                  VARCHAR(3)  NOT NULL,
    amount_cents              BIGINT      NOT NULL CHECK (amount_cents >= 0),
    selected_gateway_id       BIGINT REFERENCES payment_gateways(id) ON DELETE SET NULL,
    gateway_session_id        VARCHAR(255),
    gateway_customer_id       VARCHAR(255),
    status                    VARCHAR(32) NOT NULL DEFAULT 'CREATED'
        CHECK (status IN ('CREATED','CHECKOUT_STARTED','PAID',
                          'PROVISIONED','PROVISIONING_FAILED',
                          'CANCELLED','EXPIRED','REFUNDED')),
    provisioning_attempts     INT         NOT NULL DEFAULT 0,
    last_provisioning_error   VARCHAR(1024),
    provisioned_tenant_id     BIGINT REFERENCES tenants(id) ON DELETE SET NULL,
    metadata                  JSONB DEFAULT '{}'::jsonb,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    slug_reservation_expires  TIMESTAMPTZ NOT NULL,
    paid_at                   TIMESTAMPTZ,
    provisioned_at            TIMESTAMPTZ,
    CONSTRAINT pending_orders_slug_format
        CHECK (requested_tenant_slug IS NULL
               OR requested_tenant_slug ~ '^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$')
);

-- 10-minute slug reservation: partial unique index covers only the
-- "active" states. Terminal states (PROVISIONED, CANCELLED, EXPIRED,
-- REFUNDED) drop out of the index and free the slug for re-use.
-- PROVISIONING_FAILED stays in the index during the 24-hour retry
-- budget, then OrderExpiryScheduler transitions it to REFUNDED.
CREATE UNIQUE INDEX pending_orders_active_slug_reservation
    ON pending_orders (requested_tenant_slug)
    WHERE requested_tenant_slug IS NOT NULL
      AND status IN ('CREATED','CHECKOUT_STARTED','PAID','PROVISIONING_FAILED');

CREATE INDEX idx_pending_orders_status ON pending_orders (status);

CREATE INDEX idx_pending_orders_slug_exp
    ON pending_orders (slug_reservation_expires)
    WHERE status IN ('CREATED','CHECKOUT_STARTED');

CREATE INDEX idx_pending_orders_gateway_session
    ON pending_orders (gateway_session_id)
    WHERE gateway_session_id IS NOT NULL;

-- ---- subscriptions ------------------------------------------

CREATE TABLE subscriptions (
    id                       BIGSERIAL PRIMARY KEY,
    tenant_id                BIGINT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    tier                     VARCHAR(32) NOT NULL,
    status                   VARCHAR(16) NOT NULL
        CHECK (status IN ('ACTIVE','PAST_DUE','CANCELLED','ENDED')),
    billing_cycle            VARCHAR(16) NOT NULL
        CHECK (billing_cycle IN ('MONTHLY','ANNUAL')),
    currency                 VARCHAR(3)  NOT NULL,
    amount_cents             BIGINT      NOT NULL,
    gateway_id               BIGINT REFERENCES payment_gateways(id) ON DELETE SET NULL,
    gateway_customer_id      VARCHAR(255),
    gateway_subscription_id  VARCHAR(255),
    current_period_start     TIMESTAMPTZ NOT NULL,
    current_period_end       TIMESTAMPTZ NOT NULL,
    cancel_at_period_end     BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_subscriptions_tenant ON subscriptions (tenant_id);
CREATE INDEX idx_subscriptions_status ON subscriptions (status);

-- ---- billing_transactions -----------------------------------
-- Idempotency key: (gateway_id, gateway_transaction_id). Stripe
-- retries webhook delivery up to 3 days; the unique index below
-- is what makes the PAID-event handler safe to retry without
-- double-provisioning.

CREATE TABLE billing_transactions (
    id                       BIGSERIAL PRIMARY KEY,
    subscription_id          BIGINT REFERENCES subscriptions(id)  ON DELETE SET NULL,
    pending_order_id         BIGINT REFERENCES pending_orders(id) ON DELETE SET NULL,
    gateway_id               BIGINT REFERENCES payment_gateways(id) ON DELETE SET NULL,
    gateway_transaction_id   VARCHAR(255) NOT NULL,
    amount_cents             BIGINT       NOT NULL,
    currency                 VARCHAR(3)   NOT NULL,
    fee_cents                BIGINT,
    status                   VARCHAR(16)  NOT NULL
        CHECK (status IN ('PENDING','SUCCEEDED','FAILED','REFUNDED','DISPUTED')),
    failure_reason           VARCHAR(1024),
    card_country             VARCHAR(2),
    bin                      VARCHAR(8),
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at             TIMESTAMPTZ
);

CREATE UNIQUE INDEX billing_transactions_gtx_unique
    ON billing_transactions (gateway_id, gateway_transaction_id);

CREATE INDEX idx_billing_transactions_subscription
    ON billing_transactions (subscription_id)
    WHERE subscription_id IS NOT NULL;

CREATE INDEX idx_billing_transactions_pending_order
    ON billing_transactions (pending_order_id)
    WHERE pending_order_id IS NOT NULL;

CREATE INDEX idx_billing_transactions_status
    ON billing_transactions (status);
