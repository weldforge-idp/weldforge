-- Carry the instant the user actually authenticated through to the ID token
-- (CONF-2.2, OIDC Core section 2).
--
-- `auth_time` is REQUIRED in the ID token whenever the request carried
-- `max_age`, and RECOMMENDED otherwise. It answers a question the other claims
-- cannot: `iat` says when the TOKEN was minted, which a refresh moves forward
-- indefinitely, while `auth_time` says when the PERSON last proved who they
-- are. A relying party protecting a sensitive operation gates on the second and
-- would be misled by the first.
--
-- Same shape as `amr` in V47 and `granted_scopes` in V48, and for the same
-- reason: the fact is established at /authorize where the session exists, and
-- consumed at /token where it does not. It has to travel with the grant rather
-- than be recomputed later -- and unlike those two there is no safe fallback,
-- because a guessed authentication time is worse than an absent one.
--
-- NULL means the grant predates this column. Tokens minted from those omit the
-- claim entirely, which is the honest reading: we do not know when that session
-- was established. They self-heal on the next login.

ALTER TABLE oauth_authorization_codes
    ADD COLUMN auth_time TIMESTAMP;

ALTER TABLE refresh_tokens
    ADD COLUMN auth_time TIMESTAMP;

COMMENT ON COLUMN oauth_authorization_codes.auth_time IS
    'When the user authenticated for the session that authorised this code. '
    'Emitted as the OIDC auth_time claim. NULL for codes predating the column.';

COMMENT ON COLUMN refresh_tokens.auth_time IS
    'When the user authenticated for the login that created this family, so a '
    'refreshed ID token still reports the original authentication rather than '
    'the refresh. NULL for families predating the column.';
