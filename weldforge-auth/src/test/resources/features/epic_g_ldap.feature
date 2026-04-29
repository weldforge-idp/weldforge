Feature: LDAP / Active Directory upstream authentication (PRD DIR-01, DIR-02)
  Tenants can register an LDAP or AD provider. On login, the auth
  service tries the upstream directory first and only falls back to
  the local password store if LDAP returns empty (bad credentials,
  unknown user, directory down). Successful LDAP logins provision
  a local user marked provider=LDAP so audit, RBAC and MFA all apply.

  Background:
    Given tenant "acme" exists for LDAP tests

  Scenario: No LDAP providers configured — upstream returns empty
    When the LDAP upstream authenticates user "alice@acme.test" with password "x"
    Then the LDAP upstream returns no user

  Scenario: Successful LDAP bind provisions a local user
    Given tenant "acme" has an LDAP provider "corp-ldap" at "ldap://dc.acme.test"
    And the LDAP directory has user "alice@acme.test" with password "s3cret" and name "Alice A."
    When the LDAP upstream authenticates user "alice@acme.test" with password "s3cret"
    Then the LDAP upstream returns user "alice@acme.test"
    And the provisioned user has provider "LDAP"
    And the provisioned user has name "Alice A."

  Scenario: Wrong password returns empty (falls through to local)
    Given tenant "acme" has an LDAP provider "corp-ldap" at "ldap://dc.acme.test"
    And the LDAP directory has user "alice@acme.test" with password "s3cret" and name "Alice A."
    When the LDAP upstream authenticates user "alice@acme.test" with password "wrong"
    Then the LDAP upstream returns no user

  Scenario: Disabled LDAP provider is skipped
    Given tenant "acme" has a disabled LDAP provider "old-ldap" at "ldap://old.acme.test"
    And the LDAP directory has user "alice@acme.test" with password "s3cret" and name "Alice A."
    When the LDAP upstream authenticates user "alice@acme.test" with password "s3cret"
    Then the LDAP upstream returns no user

  Scenario: Active Directory UPN login
    Given tenant "acme" has an AD provider "corp-ad" at "ldap://dc.corp.acme.test"
    And the AD directory has user with UPN "alice@corp.acme.test" sAMAccountName "alice" password "s3cret"
    When the LDAP upstream authenticates user "alice@corp.acme.test" with password "s3cret"
    Then the LDAP upstream returns user "alice@corp.acme.test"

  Scenario: Active Directory sAMAccountName login
    Given tenant "acme" has an AD provider "corp-ad" at "ldap://dc.corp.acme.test"
    And the AD directory has user with UPN "alice@corp.acme.test" sAMAccountName "alice" password "s3cret"
    When the LDAP upstream authenticates user "alice" with password "s3cret"
    Then the LDAP upstream returns user "alice@corp.acme.test"

  Scenario: Second local attempt on LDAP-provisioned user reuses the same row
    Given tenant "acme" has an LDAP provider "corp-ldap" at "ldap://dc.acme.test"
    And the LDAP directory has user "alice@acme.test" with password "s3cret" and name "Alice A."
    When the LDAP upstream authenticates user "alice@acme.test" with password "s3cret"
    And the LDAP upstream authenticates user "alice@acme.test" with password "s3cret"
    Then exactly 1 local user exists for "alice@acme.test"
