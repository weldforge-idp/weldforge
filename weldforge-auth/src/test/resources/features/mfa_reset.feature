Feature: MFA reset
  Users must be able to recover cleanly when they lose access to their
  second factor, without that recovery path becoming the cheapest way to
  take MFA off somebody else's account.

  The rule these scenarios hold the code to: an account cannot go from
  MFA-protected to unprotected unless the password and a current factor
  proof arrive in the same request (B-AUTH-5, F60). A backup code counts
  as proof, because the user who needs a reset is usually the user whose
  authenticator is gone. Lost everything is an admin reset, by a human.

  Background:
    Given user "alice@acme.test" has an enrolled TOTP factor

  Scenario: Self-service reset refuses the wrong password
    Given I am "alice@acme.test"
    When I request a self-service MFA reset with the wrong password
    Then the reset is refused with "bad credentials"
    And my TOTP factor is still present
    And the audit log contains a "auth.mfa_reset.denied" event for "alice@acme.test"

  Scenario: The correct password alone no longer turns MFA off
    Given I am "alice@acme.test"
    When I request a self-service MFA reset with the correct password and nothing else
    Then the reset is refused with "bad credentials"
    And my TOTP factor is still present
    And the audit log contains a "mfa.self_reset.denied" event for "alice@acme.test"

  Scenario: Self-service reset succeeds on the password plus a valid code
    Given I am "alice@acme.test"
    When I request a self-service MFA reset with the correct password and a valid code
    Then the reset succeeds and reports 1 factor removed
    And the audit log contains a "mfa.self_reset" event for "alice@acme.test"

  Scenario: A backup code is proof enough when the authenticator is gone
    Given I am "alice@acme.test"
    When I request a self-service MFA reset with the correct password and a backup code
    Then the reset succeeds and reports 1 factor removed
    And the audit log contains a "mfa.self_reset" event for "alice@acme.test"

  Scenario: The delete route cannot be used to strip the last factor
    Given I am "alice@acme.test"
    When I try to delete my only verified factor directly
    Then the removal is refused because it is my last factor

  Scenario: Backing out of a half-finished enrollment still works
    Given I am "alice@acme.test"
    And I have started enrolling a second factor but not finished it
    When I cancel that enrollment
    Then the enrollment is cancelled and my verified factor is untouched

  Scenario: Admin reset wipes the target's factors and audits the admin
    Given an admin "admin@acme.test" in the same tenant
    When the admin resets MFA for "alice@acme.test"
    Then alice's TOTP factor is gone
    And the audit log contains a "mfa.admin_reset" event recorded by "admin@acme.test"
