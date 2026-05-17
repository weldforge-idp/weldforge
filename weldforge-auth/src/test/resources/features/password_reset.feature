Feature: Password reset
  Background:
    Given tenant "acme" exists for password reset
    And user "alice@acme.test" exists with password "OldP@ssw0rd1" for password reset

  Scenario: Request and complete a password reset
    When a password reset is requested for "alice@acme.test"
    Then a reset token is generated
    When the reset token is used with new password "NewS3cure!Pass"
    Then the password is changed successfully
    And a "auth.password_reset.completed" audit event is recorded for password reset

  Scenario: Completing a reset terminates every existing session
    When a password reset is requested for "alice@acme.test"
    Then a reset token is generated
    When the reset token is used with new password "NewS3cure!Pass"
    Then the password is changed successfully
    And every active session for the user is terminated

  Scenario: Expired token is rejected
    When a password reset is requested for "alice@acme.test"
    And the token is expired
    When the expired token is used with new password "NewS3cure!Pass"
    Then the reset is rejected

  Scenario: Requesting reset for unknown email succeeds silently
    When a password reset is requested for "unknown@acme.test"
    Then no error is returned
