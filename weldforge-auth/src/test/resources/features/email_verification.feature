Feature: Email verification
  Background:
    Given tenant "acme" exists for email verification
    And user "alice@acme.test" exists unverified for email verification

  Scenario: Verify email with valid token
    When a verification token is generated for "alice@acme.test"
    And the verification token is submitted
    Then the email is marked as verified
    And a "auth.email.verified" audit event is recorded for email verification

  Scenario: Expired verification token is rejected
    When a verification token is generated for "alice@acme.test"
    And the verification token is expired
    When the expired verification token is submitted
    Then the verification is rejected
