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
