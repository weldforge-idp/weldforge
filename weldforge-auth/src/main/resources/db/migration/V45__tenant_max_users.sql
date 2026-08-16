-- Per-tenant seat cap.
--
-- NULL means "no limit", which is deliberately the default: every tenant
-- that exists today keeps unlimited seats and needs no backfill. Only
-- tenants provisioned onto a capped plan (the free tier, 25 users) carry
-- a value.
--
-- Enforcement lives in TenantSeatService, called from every user-creation
-- path. The CHECK below only guards against a nonsensical stored value.

ALTER TABLE tenants
    ADD COLUMN max_users INTEGER;

ALTER TABLE tenants
    ADD CONSTRAINT tenants_max_users_positive
        CHECK (max_users IS NULL OR max_users > 0);

COMMENT ON COLUMN tenants.max_users IS
    'Maximum active users for this tenant. NULL = unlimited. Counts users with active = true only, so deactivating a user frees a seat.';
