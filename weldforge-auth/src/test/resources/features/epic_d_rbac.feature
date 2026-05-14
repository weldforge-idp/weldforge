Feature: Admin RBAC — SUPER_ADMIN, TENANT_ADMIN, READ_ONLY (PRD ADM-02, ADM-04)
  Tenant admins can manage their own tenant's configuration
  without super-admin access. Read-only admins can inspect but not
  change. Regular users (NONE) get no admin access at all.

  Background:
    Given tenant "acme" exists for RBAC tests
    And user "alice@acme.test" exists in tenant "acme" for RBAC tests

  Scenario: NONE role is denied admin access
    Given alice has admin role NONE
    When alice tries to list OIDC clients
    Then the call is rejected as access denied

  Scenario: READ_ONLY may list but may not create
    Given alice has admin role READ_ONLY
    When alice lists OIDC clients
    Then the call succeeds
    When alice tries to create an OIDC client
    Then the call is rejected as access denied

  Scenario: TENANT_ADMIN may create OIDC clients
    Given alice has admin role TENANT_ADMIN
    When alice creates an OIDC client "my-app"
    Then the client is created

  Scenario: TENANT_ADMIN cannot create an OIDC client in another tenant
    Given alice has admin role TENANT_ADMIN
    And tenant "other" exists for RBAC tests
    When alice tries to create an OIDC client "leaky" in tenant "other"
    Then the call is rejected as access denied

  Scenario: SUPER_ADMIN can create an OIDC client in another tenant
    Given alice has admin role SUPER_ADMIN
    And tenant "other" exists for RBAC tests
    When alice creates an OIDC client "cross-tenant-app" in tenant "other"
    Then the client is created
    And the client belongs to tenant "other"

  Scenario: TENANT_ADMIN cannot create a tenant
    Given alice has admin role TENANT_ADMIN
    When alice tries to create a new tenant "newco"
    Then the call is rejected as access denied

  Scenario: SUPER_ADMIN can create a tenant
    Given alice has admin role SUPER_ADMIN
    When alice creates a new tenant "newco"
    Then the tenant is created

  Scenario: SUPER_ADMIN can assign admin roles to other users
    Given alice has admin role SUPER_ADMIN
    And user "bob@acme.test" exists in tenant "acme" for RBAC tests
    When alice assigns admin role TENANT_ADMIN to bob
    Then bob's admin role is TENANT_ADMIN
    And an "admin.role.assigned" audit event is recorded for RBAC

  Scenario: TENANT_ADMIN cannot assign admin roles
    Given alice has admin role TENANT_ADMIN
    And user "bob@acme.test" exists in tenant "acme" for RBAC tests
    When alice tries to assign admin role SUPER_ADMIN to bob
    Then the call is rejected as access denied

  Scenario: Assigning a role bumps the user's token version
    Given alice has admin role SUPER_ADMIN
    And user "bob@acme.test" exists in tenant "acme" with token version 3 for RBAC tests
    When alice assigns admin role READ_ONLY to bob
    Then bob's token version is 4
