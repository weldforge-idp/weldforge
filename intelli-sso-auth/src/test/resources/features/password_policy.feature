Feature: Password policy
  Passwords chosen during registration must meet the configured rules.
  Every failing rule is reported in a single response so the user can
  fix them all at once instead of playing whack-a-mole.

  Scenario: A strong password meets every rule
    Given the default password policy
    When I validate "Correct-Horse-9"
    Then the password is accepted

  Scenario: A weak password surfaces every broken rule in one go
    Given the default password policy
    When I validate "alllowercase"
    Then the password is rejected
    And the rejection mentions "at least one uppercase letter"
    And the rejection mentions "at least one digit"
    And the rejection mentions "at least one symbol (non-alphanumeric character)"

  Scenario: Too short passwords are rejected with a clear reason
    Given the default password policy
    When I validate "Ab1!"
    Then the password is rejected
    And the rejection mentions "at least 10 characters"
