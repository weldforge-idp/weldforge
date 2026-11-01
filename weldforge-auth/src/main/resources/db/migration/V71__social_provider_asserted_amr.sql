-- ============================================================================
-- V71: let a tenant assert an authentication strength for an upstream provider.
--
-- Google returns no `amr` claim. Its ID token says nothing about HOW the
-- person authenticated, so WeldForge cannot verify that Google performed MFA;
-- it can only be configured to assert it. A relying party that gates on a
-- phishing-resistant factor -- KeyCrypt refuses any session whose amr is
-- disjoint from {hwk,swk} -- therefore refuses every federated session,
-- because issueFederatedSession mints them with an empty amr on purpose.
--
-- That refusal is correct until somebody makes a trust decision. These two
-- columns are where the decision is recorded, per provider, so it is an
-- explicit and auditable configuration rather than a relaxed check.
--
-- asserted_amr is space-separated, matching how amr travels in a JWT and how
-- allowed_email_domains, redirect_uris, scopes and web_origins are already
-- stored. One CSV convention in the schema, not two.
--
-- required_hd is the thing that makes the assertion worth anything. Two-factor
-- is a property of a Google ACCOUNT, not of the Google provider: asserting
-- hwk for a provider asserts it for everyone who signs in through it,
-- including an account with only a password, and WeldForge would never know.
-- Google sends `hd` only for Workspace accounts, naming the hosted domain --
-- and 2FA can be enforced for that domain in Workspace admin, where the user
-- cannot switch it off. So an assertion of hwk/swk is refused by the API
-- unless required_hd is set, and a sign-in with no hd (a personal account) is
-- refused before provisioning.
--
-- Note this is NOT tenants.allowed_email_domains (V63). That list permits a
-- sign-in when hd is ABSENT, which is right for an email allow-list and for
-- providers that never send hd, but is exactly the gap here: a consumer Google
-- account registered on a corporate-looking address carries no hd and would
-- pass. required_hd demands presence AND a match.
--
-- Both NULL means "assert nothing", which is every existing row: this changes
-- no tenant's behaviour until somebody sets a value.
-- ============================================================================

ALTER TABLE tenant_social_providers
    ADD COLUMN IF NOT EXISTS asserted_amr VARCHAR(128),
    ADD COLUMN IF NOT EXISTS required_hd  VARCHAR(255);

COMMENT ON COLUMN tenant_social_providers.asserted_amr IS
    'Space-separated RFC 8176 methods ASSERTED (not verified) for sessions from this provider. NULL/empty = assert nothing, and the session carries no amr claim. Never contains pwd: no password is presented to this server.';

COMMENT ON COLUMN tenant_social_providers.required_hd IS
    'Space-separated hosted domains (Google''s hd claim) required for this provider. A sign-in whose hd is absent or unmatched is refused before provisioning. Mandatory when asserted_amr claims hwk or swk.';
