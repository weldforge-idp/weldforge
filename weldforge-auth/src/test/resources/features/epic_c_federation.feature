Feature: Federation rules engine — matching + claim transforms (PRD FED-02, FED-04)
  Tenants can configure how incoming federated identities are resolved
  to local users, and how provider-specific claim shapes are rewritten
  before provisioning.

  Background:
    Given tenant "fedco" exists for federation tests
    And user "alice@fedco.test" exists in tenant "fedco" for federation tests

  Scenario: No rules configured — matcher returns empty (caller falls back)
    Given tenant "fedco" has no federation matching rules
    When the federation engine matches claims for "fedco":
      | email | alice@fedco.test |
    Then the federation engine returns no match

  Scenario: Exact-email rule matches the local user
    Given tenant "fedco" has matching rule strategy "exact_email" on claim "email"
    When the federation engine matches claims for "fedco":
      | email | alice@fedco.test |
    Then the federation engine returns user "alice@fedco.test"

  Scenario: Normalised-email rule collapses +tag and dots for gmail
    Given user "carol@gmail.com" exists in tenant "fedco" for federation tests
    And tenant "fedco" has matching rule strategy "normalised_email" on claim "mail"
    When the federation engine matches claims for "fedco":
      | mail | C.A.R.O.L+work@gmail.com |
    Then the federation engine returns user "carol@gmail.com"

  Scenario: External-id rule matches by provider-issued subject
    Given user "bob@fedco.test" exists in tenant "fedco" with providerId "okta-123" for federation tests
    And tenant "fedco" has matching rule strategy "external_id" on claim "sub"
    When the federation engine matches claims for "fedco":
      | sub | okta-123 |
    Then the federation engine returns user "bob@fedco.test"

  Scenario: Rules are evaluated in order — first hit wins
    Given user "dan@fedco.test" exists in tenant "fedco" with providerId "ext-9" for federation tests
    And tenant "fedco" has matching rules:
      | external_id | sub   |
      | exact_email | email |
    When the federation engine matches claims for "fedco":
      | sub   | ext-9             |
      | email | alice@fedco.test  |
    Then the federation engine returns user "dan@fedco.test"

  Scenario: Claim transform picks primary email via JSONPath
    Given tenant "fedco" has claim transform target "email" path "$.emails[0].value"
    When the federation engine transforms claims for "fedco":
      | raw | {"emails":[{"value":"picked@fedco.test","primary":true}]} |
    Then the transformed claim "email" is "picked@fedco.test"

  Scenario: Claim transform skipped when condition is false
    Given tenant "fedco" has claim transform target "email" path "$.upn" when "$.active"
    When the federation engine transforms claims for "fedco":
      | raw | {"upn":"skip@fedco.test","active":false} |
    Then the transformed claim "email" is absent

  # ----------------------------------------------------------------------
  # Trusted social sign-in: an asserted amr (V71)
  #
  # Google returns no `amr` claim at all, so WeldForge cannot verify that an
  # upstream performed MFA -- it can only be configured to assert it. These
  # scenarios pin what a tenant is allowed to assert, and the one condition
  # that makes the assertion worth anything.
  # ----------------------------------------------------------------------

  Scenario: Asserting nothing is valid, and is every provider configured so far
    When the asserted amr "" with required hosted domain "" is validated
    Then the asserted amr configuration is accepted

  Scenario: A password may not be asserted — none was presented to this server
    When the asserted amr "pwd" with required hosted domain "" is validated
    Then the asserted amr configuration is refused because of "pwd"

  Scenario: An unregistered value is refused rather than stored and never matched
    When the asserted amr "federated" with required hosted domain "example.com" is validated
    Then the asserted amr configuration is refused because of "not assertable"

  Scenario: A phishing-resistant assertion without a hosted-domain gate is refused
    When the asserted amr "hwk" with required hosted domain "" is validated
    Then the asserted amr configuration is refused because of "requiredHd"

  Scenario: A phishing-resistant assertion with a hosted-domain gate is accepted
    When the asserted amr "hwk mfa" with required hosted domain "acme.test" is validated
    Then the asserted amr configuration is accepted

  Scenario: A one-time-password assertion needs no hosted-domain gate
    When the asserted amr "otp mfa" with required hosted domain "" is validated
    Then the asserted amr configuration is accepted

  Scenario: A Workspace account in the required domain satisfies the gate
    When a sign-in with hosted domain "acme.test" is checked against required "acme.test"
    Then the hosted-domain gate is satisfied

  Scenario: An account from another organisation does not satisfy the gate
    When a sign-in with hosted domain "someone-else.test" is checked against required "acme.test"
    Then the hosted-domain gate is not satisfied

  Scenario: A personal account — no hosted domain at all — does not satisfy the gate
    When a sign-in with no hosted domain is checked against required "acme.test"
    Then the hosted-domain gate is not satisfied
