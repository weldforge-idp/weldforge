Feature: Password policy
  Passwords chosen during registration must meet the configured rules.
  Every failing rule is reported in a single response so the user can
  fix them all at once instead of playing whack-a-mole.

  The defaults follow NIST SP 800-63B section 5.1.1.2 (CONF-7.1): a length
  floor and screening against breached passwords, and no composition rules.
  Composition rules are what produce "Password1!" -- every class satisfied,
  and in every breach list.

  Scenario: A long passphrase with no symbols is accepted
    Given the default password policy
    When I validate "correct horse battery staple"
    Then the password is accepted

  Scenario: A mixed-class password of sufficient length is still accepted
    Given the default password policy
    When I validate "Correct-Horse-9x"
    Then the password is accepted

  Scenario: A breached password is refused
    Given the default password policy
    When a user registers with a password present in the breach corpus
    Then the password is rejected
    And the rejection mentions "data breach"
    And the password is never transmitted in full to any third party

  Scenario: Deployments may re-enable composition rules
    Given the deployment sets app.security.password.require-symbol=true
    When I validate "correct horse battery staple"
    Then the password is rejected
    And the rejection mentions "at least one symbol (non-alphanumeric character)"

  Scenario: Too short passwords are rejected with a clear reason
    Given the default password policy
    When I validate "Ab1!"
    Then the password is rejected
    And the rejection mentions "at least 12 characters"

  # --- Per-tenant overrides (docs/password-policy-spec.md) ------------
  #
  # A tenant may tighten the deployment's rules. It may never loosen them:
  # the people affected are the tenant's end users, who never chose the
  # policy, and the operator is answerable for them.

  Scenario: A tenant may require more than the deployment does
    Given the default password policy
    And the tenant "acme-corp" requires at least 20 characters
    When I validate "correct horse battery staple" for that tenant
    Then the password is accepted

  Scenario: A password good enough for the deployment can fail a stricter tenant
    Given the default password policy
    And the tenant "acme-corp" requires at least 20 characters
    When I validate "Correct-Horse-9x" for that tenant
    Then the password is rejected
    And the rejection mentions "at least 20 characters"

  Scenario: The same password still succeeds for a tenant that inherits
    Given the default password policy
    And the tenant "relaxed-co" has no password policy of its own
    When I validate "Correct-Horse-9x" for that tenant
    Then the password is accepted

  Scenario: A tenant may add a composition rule the deployment does not require
    Given the default password policy
    And the tenant "acme-corp" requires a symbol
    When I validate "correct horse battery staple" for that tenant
    Then the password is rejected
    And the rejection mentions "at least one symbol (non-alphanumeric character)"

  Scenario: A tenant cannot weaken the deployment's length floor
    Given the default password policy
    And the tenant "acme-corp" requires at least 4 characters
    When I validate "Ab1!" for that tenant
    Then the password is rejected
    And the rejection mentions "at least 12 characters"

  Scenario: A tenant cannot switch off a composition rule the deployment requires
    Given the deployment sets app.security.password.require-symbol=true
    And the tenant "acme-corp" does not require a symbol
    When I validate "correct horse battery staple" for that tenant
    Then the password is rejected
    And the rejection mentions "at least one symbol (non-alphanumeric character)"
