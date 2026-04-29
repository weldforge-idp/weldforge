Feature: Tenant isolation
  Tenant A must never see or mutate data that belongs to Tenant B.
  Every admin read and write is scoped through the caller's tenant id.

  Background:
    Given tenants "acme" and "globex" exist
    And "acme" has user "alice@acme.test"
    And "globex" has user "eve@globex.test"

  Scenario: A tenant admin listing users only sees their own tenant
    Given I am authenticated as "alice@acme.test"
    When I list users via the admin API
    Then the result contains "alice@acme.test"
    And the result does not contain "eve@globex.test"

  Scenario: A tenant admin cannot delete a user in another tenant
    Given I am authenticated as "alice@acme.test"
    When I try to delete the user "eve@globex.test"
    Then the operation is rejected as "not found"

  Scenario: A tenant admin cannot reset MFA for a user in another tenant
    Given I am authenticated as "alice@acme.test"
    When I try to reset MFA for the user "eve@globex.test"
    Then the operation is rejected as "not found"
    And no MFA factors are removed
