-- ============================================================
-- V8: Append-only audit log.
-- Every security-relevant action writes one row here, tagged
-- with the tenant the event was scoped to plus the actor who
-- performed it. Rows are never updated or deleted by the app.
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_events (
    id                   BIGSERIAL PRIMARY KEY,

    -- Nullable: login-failed events may not yet know a tenant,
    -- and a handful of super-admin actions span tenants.
    tenant_id            BIGINT REFERENCES tenants(id) ON DELETE SET NULL,

    actor_user_id        BIGINT REFERENCES users(id)   ON DELETE SET NULL,
    actor_email          VARCHAR(255),
    actor_is_super_admin BOOLEAN NOT NULL DEFAULT FALSE,

    -- Event taxonomy lives in AuditEventTypes constants so that
    -- adding a new event does not require a migration.
    event_type           VARCHAR(64)  NOT NULL,

    target_type          VARCHAR(64),
    target_id            VARCHAR(255),

    -- SUCCESS | FAILURE | DENIED
    outcome              VARCHAR(16)  NOT NULL DEFAULT 'SUCCESS',

    metadata             JSONB,

    ip_address           VARCHAR(45),
    user_agent           VARCHAR(512),

    created_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_time
    ON audit_events (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_actor_time
    ON audit_events (actor_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_event_type
    ON audit_events (event_type);

CREATE INDEX IF NOT EXISTS idx_audit_events_target
    ON audit_events (target_type, target_id);
