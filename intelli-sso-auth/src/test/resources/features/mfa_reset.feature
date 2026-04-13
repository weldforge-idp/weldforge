Feature: MFA reset
  Users must be able to recover cleanly when they lose access to their
  second factor. Self-service reset re-verifies the password (so a
  stolen access token cannot strip factors). Admin reset is tenant-
  scoped and always audit logged.

  Background:
    Given user "alice@acme.test" has an enrolled TOTP factor

  Scenario: Self-service reset requires re-entering the password
    Given I am "alice@acme.test"
    When I request a self-service MFA reset with the wrong password
    Then the reset is refused with "bad credentials"
    And my TOTP factor is still present

  Scenario: Self-service reset succeeds and wipes factors + backup codes
    Given I am "alice@acme.test"
    When I request a self-service MFA reset with the correct password
    Then the reset succeeds and reports 1 factor removed
    And the audit log contains a "mfa.self_reset" event for "alice@acme.test"

  Scenario: Admin reset wipes the target's factors and audits the admin
    Given an admin "admin@acme.test" in the same tenant
    When the admin resets MFA for "alice@acme.test"
    Then alice's TOTP factor is gone
    And the audit log contains a "mfa.admin_reset" event recorded by "admin@acme.test"
