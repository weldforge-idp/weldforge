Feature: SCIM 2.0 group provisioning
  Upstream provisioners (Okta, Workday, Entra ID) push groups and
  membership changes through the tenant-scoped SCIM Groups endpoint.
  Adding a member to a group must be tenant-scoped: members from
  another tenant are silently dropped, never persisted.

  Background:
    Given tenant "acme" exists for SCIM groups
    And users "alice@acme.test" and "bob@acme.test" exist in tenant "acme"

  Scenario: Create a group then add and remove members via PATCH
    When a SCIM client creates group "Engineers" in tenant "acme"
    Then the group is created
    When a SCIM client adds alice to the group "Engineers"
    Then the group "Engineers" has 1 member
    And a "scim.group.member.add" audit event is recorded for the group
    When a SCIM client adds bob to the group "Engineers"
    Then the group "Engineers" has 2 members
    When a SCIM client removes alice from the group "Engineers"
    Then the group "Engineers" has 1 member
    And a "scim.group.member.remove" audit event is recorded for the group

  Scenario: PUT replaces the entire membership list
    When a SCIM client creates group "Engineers" in tenant "acme" with members alice and bob
    Then the group "Engineers" has 2 members
    When a SCIM client PUTs the group "Engineers" with only bob as a member
    Then the group "Engineers" has 1 member
    And the only member is bob

  Scenario: A SCIM client cannot list a group that belongs to another tenant
    Given tenant "globex" exists with its own group "Engineers"
    When a SCIM client lists groups in tenant "acme"
    Then the SCIM groups list does not contain a group named "Engineers" from globex
