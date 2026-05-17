Feature: Cross-tenant admin membership management
  A global super admin grants and revokes admin memberships that give users
  admin reach into tenants. Granting is gated on global SUPER_ADMIN scope so
  the API cannot be used to escalate privilege. cross-tenant-admin-spec.md §6.2.

  Background:
    Given a target user "ops@acme.test" for membership management

  Scenario: A global super admin grants a per-tenant membership
    Given the caller is a global super admin
    When the caller grants "ops@acme.test" role TENANT_ADMIN on tenant "beta"
    Then the membership grant succeeds
    And "ops@acme.test" has 1 admin membership

  Scenario: A global super admin grants a global membership
    Given the caller is a global super admin
    When the caller grants "ops@acme.test" role READ_ONLY globally
    Then the membership grant succeeds

  Scenario: A per-tenant SUPER_ADMIN grant is rejected
    Given the caller is a global super admin
    When the caller grants "ops@acme.test" role SUPER_ADMIN on tenant "beta"
    Then the membership grant is rejected as a bad request

  Scenario: A tenant-scoped admin cannot manage memberships
    Given the caller is only a tenant admin
    When the caller grants "ops@acme.test" role TENANT_ADMIN on tenant "beta"
    Then the membership grant is denied

  Scenario: A membership is revoked
    Given the caller is a global super admin
    And "ops@acme.test" already has a TENANT_ADMIN membership on tenant "beta"
    When the caller revokes that membership
    Then "ops@acme.test" has 0 admin memberships
