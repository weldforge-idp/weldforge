-- RFC 8707 Resource Indicators.
--
-- A client may ask for a token bound to a named resource rather than to
-- itself. Two columns, both additive and both inert until a client is given a
-- resource to ask for:
--
--   oidc_clients.resources            the allow-list, CSV, empty by default
--   oauth_authorization_codes.resource the resource bound at /authorize
--
-- Empty allow-list means the client may not use the parameter at all, which is
-- every client that exists today. That is deliberate: `aud` is currently the
-- client id for every token, and at least one live integration depends on it
-- (the intellisuite tenant's intelli-accounting client). Resource indicators
-- have to be strictly opt-in per request or they are a breaking change.

ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS resources TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN oidc_clients.resources IS
    'RFC 8707 allow-list: resource URIs this client may name in a `resource` '
    'parameter, CSV. Empty means the parameter is refused with invalid_target.';

-- Nullable, because the overwhelming majority of codes carry no resource and
-- a default would be indistinguishable from "asked for the empty resource".
ALTER TABLE oauth_authorization_codes
    ADD COLUMN IF NOT EXISTS resource VARCHAR(2048);

COMMENT ON COLUMN oauth_authorization_codes.resource IS
    'RFC 8707 resource bound at /authorize. The token request must name the '
    'same value or it is refused -- the audience of the issued token cannot be '
    'changed between the two legs of the flow.';
