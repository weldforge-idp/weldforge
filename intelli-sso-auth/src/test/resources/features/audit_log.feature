Feature: Audit log
  Security-relevant actions are recorded as audit events so they can be
  surfaced in the UI, exported, or fed to a SIEM.

  Scenario: Failed logins are audited with the attempted identifier
    When a login attempt with "alice@acme.test" and a wrong password is made
    Then the audit log contains a "auth.login.failed" event
    And the event's outcome is "FAILURE"
    And the event metadata mentions "bad_password"

  Scenario: Backup code regeneration is audited
    Given user "alice@acme.test" is signed in
    When alice regenerates her backup codes
    Then the audit log contains a "mfa.backup_codes.regenerated" event
    And the event outcome is "SUCCESS"
