-- Slug holdback registry — prevents immediate reuse of a deleted
-- tenant's slug, closing the identity-confusion window where a stolen
-- pre-deletion session and a freshly-issued post-recreation token
-- could collide on the same {slug}.{base-domain} subdomain.
--
-- See docs/auth-url-spec.md §"Tenant deletion revokes all sessions".
--
-- Lifecycle: TenantService.deleteTenant inserts one row per delete.
-- TenantService.requireSlug rejects any slug whose holdback row was
-- released within the configured window (wf.public.slug-holdback-days,
-- default 90). After the window expires the slug becomes reusable;
-- expired rows can be purged by a future cleanup job — for now they
-- remain as an audit trail and a UNIQUE constraint anchors the
-- "slug was used" history.
--
-- The `tenants.slug` UNIQUE constraint covers the case where the slug
-- is still in use; this table covers the case where it has been freed.
CREATE TABLE tenant_slug_holdback (
    id              BIGSERIAL    PRIMARY KEY,
    slug            VARCHAR(64)  NOT NULL,
    released_at     TIMESTAMP    NOT NULL DEFAULT now(),
    released_reason VARCHAR(64)  NOT NULL,
    released_by_user_id BIGINT   NULL
        REFERENCES users(id) ON DELETE SET NULL
);

-- Lookup pattern: "is slug X currently in holdback?" → ORDER BY released_at DESC LIMIT 1.
-- A partial index keyed by slug keeps the lookup constant-time even as the
-- table grows. Not UNIQUE on slug — the same slug may be released, reused,
-- and released again over time; each delete writes a fresh row.
CREATE INDEX idx_tenant_slug_holdback_slug
        ON tenant_slug_holdback (slug, released_at DESC);
