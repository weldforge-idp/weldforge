-- A self-registered account gets the name it signed up with as its display name.
--
-- The sign-up form asks for a name, but registration stored it only as the
-- username; users.name stayed null. users.name is what relying parties are sent
-- (the name claim in tokens, and userinfo), so every self-registered account
-- reached them with no name, and apps fell back to the email address.
--
-- Registration now stores both. This fills in the accounts made before that.
-- Only self-registrations are touched: provider LOCAL with provider_id 'local'
-- is set by AuthService.register and nowhere else. An admin-invited user has
-- provider_id = email and a username that is the email address; social, SAML,
-- LDAP and SCIM users carry their own name. A name already set is never
-- overwritten. The value was checked by validateDisplayName at sign-up and fits:
-- both columns are VARCHAR(255).
UPDATE users
   SET name = TRIM(username)
 WHERE name IS NULL
   AND provider = 'LOCAL'
   AND provider_id = 'local'
   AND username IS NOT NULL
   AND TRIM(username) <> '';
