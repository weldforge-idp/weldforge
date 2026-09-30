-- Per-client refresh-token lifetime.
--
-- Until now the only knobs were the application default
-- (app.security.refresh-token-expiration-ms, 7 days) and a per-tenant
-- override (tenants.refresh_ttl_ms). Neither can express "this one native
-- app needs a 14-day offline window" without moving every other client on
-- the same tenant with it.
--
-- NULL means "inherit", which is what every existing row gets. Resolution
-- order is client -> tenant -> application default.
alter table oidc_clients
    add column if not exists refresh_token_ttl_s integer;

comment on column oidc_clients.refresh_token_ttl_s is
    'Refresh-token lifetime in seconds for this client. NULL inherits the tenant override, then the application default.';
