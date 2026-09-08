-- Carry the scopes the resource owner actually granted through to every token
-- refreshed from that grant (CONF-1.1, RFC 6749 §6).
--
-- The refresh branch of the token endpoint re-derived scope from the CLIENT'S
-- REGISTRATION rather than from the grant. A user who consented to
-- "openid email" got the client's entire registered scope set back on the first
-- refresh -- silently, permanently, and with no consent screen in between. RFC
-- 6749 §6 is explicit that the scope of a refreshed token MUST NOT include any
-- scope not originally granted.
--
-- This is the same shape of problem `amr` had in V47, and it takes the same
-- shape of answer. The grant is established at /authorize, where the user is
-- present; it is spent at /token, where they are not. Anything the token must
-- assert about that moment has to travel with the grant rather than be
-- recomputed later from configuration. Registration says what the client MAY
-- ask for; only the grant says what the user AGREED to.
--
-- Space-separated, the same encoding `scope` uses on the wire, matching the
-- existing `oauth_authorization_codes.scopes` column.
--
-- NULL means the family predates this column. Those fall back to the client's
-- registration -- the behaviour being fixed -- because the alternative is
-- breaking every live session at deploy. `OidcAuthorizationController` counts
-- those refreshes on `sso.oidc.refresh.legacy_scope` so the fallback can be
-- retired on evidence rather than hope: when the counter reads zero for longer
-- than the refresh TTL, no legacy family is left and the fallback can go.

ALTER TABLE refresh_tokens
    ADD COLUMN granted_scopes TEXT;

COMMENT ON COLUMN refresh_tokens.granted_scopes IS
    'Space-separated scopes the resource owner granted when this family was '
    'created. Replayed onto every access and ID token minted by rotating it, '
    'so a refresh cannot widen scope beyond the original consent (RFC 6749 '
    'section 6). NULL for families issued before the column existed; those '
    'fall back to the client registration and are counted on the '
    'sso.oidc.refresh.legacy_scope meter.';
