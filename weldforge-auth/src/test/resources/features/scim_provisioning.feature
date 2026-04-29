Feature: SCIM 2.0 user provisioning
  Upstream provisioners (Okta, Workday, Entra ID) push user lifecycle
  events into WeldForge through the tenant-scoped SCIM endpoint. The
  same provisioner can deactivate a user (active=false) and the change
  must propagate immediately — login refuses inactive accounts.

  Background:
    Given tenant "acme" exists for SCIM
    And no users exist in tenant "acme"

  Scenario: An Okta-style provisioning loop
    When a SCIM client lists users in tenant "acme" with filter "userName eq \"alice@acme.test\""
    Then the SCIM list result is empty
    When a SCIM client creates user "alice@acme.test" in tenant "acme"
    Then the user is created and active
    When a SCIM client lists users in tenant "acme" with filter "userName eq \"alice@acme.test\""
    Then the SCIM list contains "alice@acme.test"

  Scenario: PATCH active=false propagates and login is refused
    Given user "alice@acme.test" was provisioned via SCIM in tenant "acme"
    When a SCIM client patches alice's active flag to false
    Then alice is marked inactive
    And a "scim.user.deactivate" audit event is recorded for alice
    And alice cannot log in

  Scenario: A reactivation flips alice back on
    Given user "alice@acme.test" was provisioned via SCIM in tenant "acme"
    And alice is currently inactive
    When a SCIM client patches alice's active flag to true
    Then alice is marked active
    And a "scim.user.reactivate" audit event is recorded for alice
