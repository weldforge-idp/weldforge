Feature: CRM identity provisioning — push on login, field mappings, dedupe (PRD §3.10 CRM-01..CRM-04)
  Tenants can register CRM connectors that receive a contact record
  every time a user authenticates. The outgoing payload respects the
  provider's field mappings and match keys, so duplicate records are
  avoided on second login.

  Background:
    Given tenant "acme" exists for CRM tests
    And user "alice@acme.test" with name "Alice A." exists in tenant "acme" for CRM tests

  Scenario: Login triggers a CRM upsert with mapped fields
    Given tenant "acme" has a "SALESFORCE" CRM provider "sf" at "https://acme.my.salesforce.com" with mappings:
      | email | Email     |
      | name  | FirstName |
    When crm provisioning fires for "alice@acme.test" on event "auth.login.success"
    Then the CRM client was called once for provider "sf"
    And the outgoing payload has field "Email" equal to "alice@acme.test"
    And the outgoing payload has field "FirstName" equal to "Alice A."
    And the provisioning log row has status "SUCCESS"
    And the provisioning log row has a non-null external id

  Scenario: Second login reuses the stored external id (CRM-04 dedupe)
    Given tenant "acme" has a "SALESFORCE" CRM provider "sf" at "https://acme.my.salesforce.com" with mappings:
      | email | Email |
    When crm provisioning fires for "alice@acme.test" on event "auth.login.success"
    And crm provisioning fires for "alice@acme.test" on event "auth.login.success"
    Then the CRM client was called twice for provider "sf"
    And the second call was an update against the existing external id

  Scenario: Disabled provider is skipped
    Given tenant "acme" has a disabled "HUBSPOT" CRM provider "hs" at "https://api.hubapi.com"
    When crm provisioning fires for "alice@acme.test" on event "auth.login.success"
    Then no CRM client calls were made

  Scenario: Multiple providers — each receives its own push
    Given tenant "acme" has a "SALESFORCE" CRM provider "sf" at "https://acme.my.salesforce.com" with mappings:
      | email | Email |
    And tenant "acme" has a "HUBSPOT" CRM provider "hs" at "https://api.hubapi.com" with mappings:
      | email | email |
    When crm provisioning fires for "alice@acme.test" on event "auth.login.success"
    Then the CRM client was called once for provider "sf"
    And the CRM client was called once for provider "hs"

  Scenario: CRM client failure marks the log FAILED but does not throw
    Given tenant "acme" has a "SALESFORCE" CRM provider "sf" at "https://acme.my.salesforce.com" with mappings:
      | email | Email |
    And the CRM client will fail for provider "sf" with "boom"
    When crm provisioning fires for "alice@acme.test" on event "auth.login.success"
    Then the provisioning log row has status "FAILED"
    And the provisioning log row's last error contains "boom"
