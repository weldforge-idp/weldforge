-- One account per email address, per tenant. Enforced by the database.
--
-- Until now nothing stopped two rows sharing an email inside one tenant. The
-- application checks before inserting, but a check-then-insert is a race: two
-- concurrent registrations for the same address both pass the check and both
-- write. The same shape of bug as the single-use token race fixed in
-- B-OIDC-6/B-AUTH-6 -- a predicate evaluated in application code against a
-- stale snapshot is not a constraint.
--
-- WHY (tenant_id, lower(email)) AND NOT email ALONE
--
-- This is a multi-tenant identity provider. One person legitimately holds
-- accounts in several tenants with the same address, and the published contract
-- says so: /llms.txt documents `400 bad_request -- Email already in use FOR
-- THIS TENANT. The same address may exist in another tenant.`
--
-- That is not theoretical. At the time of writing, production has exactly one
-- address registered in two different tenants. A global unique index on email
-- would fail this migration outright and, if forced, would break that user.
--
-- lower(email) because every lookup is case-insensitive
-- (findByTenant_SlugAndEmailIgnoreCase). Without it, Alice@example.com and
-- alice@example.com would be two accounts that the login path treats as one --
-- a duplicate the constraint would have permitted and the application would
-- then resolve arbitrarily.
--
-- A unique INDEX rather than a unique CONSTRAINT: Postgres constraints cannot
-- be defined over an expression, and the case-insensitivity has to live in the
-- index. It enforces identically.
--
-- NOT CONCURRENTLY, deliberately: Flyway runs each migration in a transaction
-- and CREATE INDEX CONCURRENTLY cannot. On this data it is instantaneous. A
-- deployment large enough for the brief write lock to matter should build the
-- index by hand first, then apply this as a no-op via IF NOT EXISTS.
CREATE UNIQUE INDEX IF NOT EXISTS users_tenant_email_unique
    ON users (tenant_id, lower(email));

COMMENT ON INDEX users_tenant_email_unique IS
    'One account per email per tenant. Deliberately scoped to the tenant: the same address may hold accounts in several tenants, which is a supported and documented case.';
