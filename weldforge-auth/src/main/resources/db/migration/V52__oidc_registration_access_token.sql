-- Give dynamically-registered clients a credential for managing their own
-- registration (CONF-4.3, RFC 7592).
--
-- The registration endpoint has been returning a `registration_client_uri` to
-- every client since it was written. RFC 7591 section 3.2.1 says that URI is
-- where the client reads and updates its own metadata -- but no endpoint was
-- ever built behind it, so the value was a 404 handed out as part of a success
-- response. A client library that follows it, as several do on startup to
-- confirm registration took, sees its registration as broken.
--
-- The token is stored HASHED, for the same reason refresh tokens are: it is a
-- bearer credential that grants control of a client registration, and a
-- database dump should not be enough to take one over. The client sees the raw
-- value exactly once, in the registration response.
--
-- Nullable: clients created through the admin API rather than dynamic
-- registration have no registration access token and no need for one -- they
-- are managed by an authenticated admin through a different surface. A NULL
-- here means "not self-manageable", which the management endpoints treat as
-- 403 rather than as a missing credential to be created on demand.

ALTER TABLE oidc_clients
    ADD COLUMN registration_access_token_hash VARCHAR(64);

COMMENT ON COLUMN oidc_clients.registration_access_token_hash IS
    'SHA-256 of the RFC 7592 registration access token, which authorises a '
    'dynamically-registered client to read, update or delete its OWN '
    'registration. NULL for clients created through the admin API, which are '
    'managed by an authenticated admin instead and are not self-manageable.';
