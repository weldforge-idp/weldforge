Feature: Per-tenant branding & login feature toggles
  As a Weldforge tenant or platform admin
  I want each tenant to have its own login look-and-feel and feature toggles
  So that the login screen can be Wellspring-branded with registration off,
  while the default Weldforge tenant keeps the stock dark theme with all
  features on.

  Background:
    Given a tenant "acme" exists for branding with display name "Acme Inc"

  Scenario: Public branding endpoint returns sensible defaults for a fresh tenant
    When the public branding endpoint is queried for tenant "acme"
    Then the branding response status is 200
    And the branding response field "registrationEnabled" equals true
    And the branding response field "passwordRecoveryEnabled" equals true

  Scenario: Admin sets a custom branding payload, public endpoint reflects it
    Given an admin sets the branding for tenant "acme" to:
      | primaryColor | #2E7D5F                       |
      | logoUrl      | https://example.test/logo.svg |
      | tagline      | Welcome, refreshed.           |
    When the public branding endpoint is queried for tenant "acme"
    Then the branding response payload contains "primaryColor" with value "#2E7D5F"
    And the branding response payload contains "logoUrl" with value "https://example.test/logo.svg"
    And the branding response payload contains "tagline" with value "Welcome, refreshed."

  Scenario: Disabling registration is visible on the public endpoint
    Given an admin disables registration for tenant "acme"
    When the public branding endpoint is queried for tenant "acme"
    Then the branding response field "registrationEnabled" equals false

  Scenario: Disabling password recovery is visible on the public endpoint
    Given an admin disables password recovery for tenant "acme"
    When the public branding endpoint is queried for tenant "acme"
    Then the branding response field "passwordRecoveryEnabled" equals false

  Scenario: Public branding endpoint returns 404 for an unknown tenant
    When the public branding endpoint is queried for tenant "doesnotexist"
    Then the branding response status is 404

  Scenario: Disabling registration makes /auth/register return 404
    Given an admin disables registration for tenant "acme"
    When a user tries to register on tenant "acme"
    Then the register response status is 404

  Scenario: Disabling password recovery makes /auth/forgot-password return 404
    Given an admin disables password recovery for tenant "acme"
    When the forgot-password endpoint is called for tenant "acme"
    Then the forgot-password response status is 404

  Scenario: With password recovery enabled /auth/forgot-password silently succeeds
    When the forgot-password endpoint is called for tenant "acme"
    Then the forgot-password response status is 200
