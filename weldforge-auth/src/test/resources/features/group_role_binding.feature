Feature: Group-to-role binding
  When a SCIM group is mapped to a role, adding a user to that group
  automatically assigns the role. The highest-priority mapping wins
  (lowest priority number = highest precedence).

  Background:
    Given tenant "acme" exists for group-role binding
    And role "Engineer" exists in tenant "acme"
    And role "Manager" exists in tenant "acme"
    And SCIM group "Engineering" exists in tenant "acme"
    And SCIM group "Leadership" exists in tenant "acme"
    And user "alice@acme.test" exists for group-role binding in tenant "acme"

  Scenario: Adding a user to a mapped group assigns the role
    Given group "Engineering" is mapped to role "Engineer" with priority 10
    When alice is added to SCIM group "Engineering" via group-role binding
    Then alice's role is "Engineer"
    And a "group_role.apply" audit event is recorded for group-role binding

  Scenario: Higher-priority mapping wins when user is in multiple groups
    Given group "Engineering" is mapped to role "Engineer" with priority 10
    And group "Leadership" is mapped to role "Manager" with priority 1
    When alice is added to SCIM group "Engineering" via group-role binding
    And alice is added to SCIM group "Leadership" via group-role binding
    Then alice's role is "Manager"

  Scenario: Removing a user from a group recalculates their role
    Given group "Engineering" is mapped to role "Engineer" with priority 10
    And group "Leadership" is mapped to role "Manager" with priority 1
    And alice is a member of "Engineering" and "Leadership" for group-role binding
    And group-role mappings are applied for alice
    When alice is removed from SCIM group "Leadership" via group-role binding
    Then alice's role is "Engineer"

  Scenario: Tenant isolation — mappings from one tenant do not affect another
    Given tenant "globex" exists for group-role binding with role "Scientist" and group "Research"
    And group "Research" is mapped to role "Scientist" in tenant "globex"
    And group "Engineering" is mapped to role "Engineer" with priority 10
    When alice is added to SCIM group "Engineering" via group-role binding
    Then alice's role is "Engineer"
    And alice's role is not "Scientist"
