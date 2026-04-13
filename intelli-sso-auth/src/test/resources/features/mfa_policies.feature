Feature: MFA enforcement policies and OIDC step-up
  The tenant MFA policy and per-application step-up settings control
  when users are forced to complete MFA — either on login (MFA-03) or
  on access to high-assurance applications (MFA-04 / SSO-05).

  Background:
    Given tenant "acme" exists for MFA policy tests
    And user "alice@acme.test" exists in tenant "acme" for MFA policy tests

  Scenario: Default policy is OPTIONAL — no enrollment required
    When admin reads the MFA policy for tenant "acme"
    Then the effective enforcement is "OPTIONAL"

  Scenario: REQUIRED policy blocks login for users without a factor
    Given the MFA policy for tenant "acme" is set to REQUIRED with grace period 0 days
    And alice has no MFA factors
    And alice was created 10 days ago
    When alice logs in with the correct password
    Then the login response indicates MFA enrollment is required
    And a "mfa.enrollment_required" audit event is recorded for policy tests

  Scenario: REQUIRED policy respects the grace period for new users
    Given the MFA policy for tenant "acme" is set to REQUIRED with grace period 30 days
    And alice has no MFA factors
    And alice was created 5 days ago
    When alice logs in with the correct password
    Then alice receives a regular access token

  Scenario: OIDC client with require_mfa rejects users with no verified factor
    Given an OIDC client "acme-high-sec" is registered for tenant "acme" with require_mfa true
    And alice has no MFA factors
    When alice requests an authorization code for client "acme-high-sec"
    Then the request is rejected with MFA step-up required
    And a "mfa.stepup_required" audit event is recorded for policy tests

  Scenario: OIDC client with require_mfa accepts users with a verified factor
    Given an OIDC client "acme-high-sec" is registered for tenant "acme" with require_mfa true
    And alice has a verified TOTP factor
    When alice requests an authorization code for client "acme-high-sec"
    Then an authorization code is issued
