Feature: Account lockout
  After too many consecutive failed logins, an account is locked so
  attackers can't keep grinding through credentials. The lock window
  auto-expires, and successful logins reset the counter.

  Background:
    Given lockout is configured with 3 attempts and a 10 minute window
    And user "alice@acme.test" exists with a fresh counter

  Scenario: Two bad attempts still allow a correct login
    When alice enters the wrong password 2 times
    Then the account is not locked
    When alice enters the correct password
    Then the login succeeds
    And the failed attempt counter is reset

  Scenario: Three consecutive failures lock the account and audit the lockout
    When alice enters the wrong password 3 times
    Then the account is locked
    And an "auth.account.locked" audit event is recorded for alice

  Scenario: A locked account refuses even the correct password during the window
    Given alice is locked until the future
    When alice enters the correct password
    Then the attempt is rejected as locked
    And an "auth.login.while_locked" audit event is recorded for alice
