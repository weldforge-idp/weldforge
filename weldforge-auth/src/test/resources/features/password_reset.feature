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

  Scenario: An admin issues an out-of-band reset for an existing user
    When an admin issues a password reset for "alice@acme.test"
    Then a reset token is returned to the admin
    And a reset token is generated

  Scenario: Completing a reset clears a login lockout
    Given "alice@acme.test" is locked out after failed logins
    When a password reset is requested for "alice@acme.test"
    Then a reset token is generated
    When the reset token is used with new password "NewS3cure!Pass"
    Then the password is changed successfully
    And the login lockout for "alice@acme.test" is cleared

  Scenario: A password the policy refuses leaves the emailed link usable
    # Sprint 6 (CONF-7.1): the hosted reset page now shows the policy's
    # reasons, and the user retries on the same link -- so a refused password
    # must not consume it.
    When a password reset is requested for "alice@acme.test"
    And the reset token is used with new password "short"
    Then the reset is refused by the password policy
    And the reset link is still usable
    When the same reset token is used again with new password "NewS3cure!Pass"
    Then the password is changed successfully

  Scenario: Expired token is rejected
    When a password reset is requested for "alice@acme.test"
    And the token is expired
    When the expired token is used with new password "NewS3cure!Pass"
    Then the reset is rejected

  Scenario: Requesting reset for unknown email succeeds silently
    When a password reset is requested for "unknown@acme.test"
    Then no error is returned
