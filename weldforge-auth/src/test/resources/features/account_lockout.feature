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

  # B-AUTH-6 (F61). Until F61 a wrong CURRENT password at
  # /api/auth/change-password was audited and nothing else: no lockout, no rate
  # limit. A caller holding a stolen access token could therefore test password
  # guesses at full speed, and the counter that protects /api/auth/login never
  # saw any of it. These scenarios assert the invariant rather than the
  # plumbing: the endpoint cannot be asked an unlimited number of questions,
  # and it cannot be asked any of them silently.

  Scenario: A wrong current password at the change-password endpoint now counts toward the lock
    When alice tries to change her password with the wrong current password 2 times
    Then the account is not locked
    And the failed attempt counter reads 2
    And an "auth.password.change_failed" audit event is recorded for alice

  Scenario: Enough wrong current passwords lock the account, and the last attempt says so
    When alice tries to change her password with the wrong current password 3 times
    Then the account is locked
    And the last change attempt was refused as locked
    And an "auth.account.locked" audit event is recorded for alice

  Scenario: A locked account is refused before the current password is compared
    Given alice is locked until the future
    When alice tries to change her password with the correct current password
    Then the last change attempt was refused as locked
    And the current password was never compared

  Scenario: A correct current password on a locked account is still refused
    Given alice is locked until the future
    When alice tries to change her password with the correct current password
    Then the password is unchanged

  Scenario: A successful change clears earlier fumbles
    When alice tries to change her password with the wrong current password 2 times
    And alice changes her password with the correct current password
    Then the password change succeeds
    And the failed attempt counter is reset
