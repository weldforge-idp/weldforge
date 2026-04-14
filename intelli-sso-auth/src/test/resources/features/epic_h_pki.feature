Feature: X.509 PKI module — CA, issuance, CRL, OCSP, client cert auth (PRD §3.6 X50-01..05)
  Each tenant has its own root CA, issues end-entity certificates for
  client authentication, publishes a signed CRL, responds to OCSP
  queries, and can resolve a presented client certificate back to a
  local user at login time.

  Background:
    Given tenant "acme" exists for PKI tests
    And the current admin acts as TENANT_ADMIN for "acme"

  Scenario: Create a root CA for the tenant
    When the admin creates a root CA valid for 5 years
    Then the returned CA certificate PEM is present
    And the CA row is stored for tenant "acme"

  Scenario: Issue an end-entity certificate signed by the CA
    Given tenant "acme" already has a root CA
    When the admin issues a certificate with subject "CN=alice@acme.test" for 90 days
    Then the returned certificate PEM is present
    And the returned private key PEM is present
    And the issued certificate has status "ACTIVE"
    And the issued certificate is signed by the CA
    And the issued certificate has EKU clientAuth

  Scenario: Revoke an issued certificate
    Given tenant "acme" already has a root CA
    And the admin has issued a certificate with subject "CN=bob@acme.test"
    When the admin revokes the certificate with reason "KEY_COMPROMISE"
    Then the issued certificate has status "REVOKED"
    And the issued certificate has revocation reason "KEY_COMPROMISE"

  Scenario: Generated CRL includes revoked serials and is signed by the CA
    Given tenant "acme" already has a root CA
    And the admin has issued a certificate with subject "CN=carol@acme.test"
    And the admin revokes that certificate with reason "SUPERSEDED"
    When a CRL is generated for tenant "acme"
    Then the CRL is signed by the CA
    And the CRL contains the revoked serial

  Scenario: OCSP responds GOOD for an active certificate
    Given tenant "acme" already has a root CA
    And the admin has issued a certificate with subject "CN=dave@acme.test"
    When an OCSP request is built for that certificate
    And OCSP is asked for the status
    Then the OCSP response status is "GOOD"

  Scenario: OCSP responds REVOKED after revocation
    Given tenant "acme" already has a root CA
    And the admin has issued a certificate with subject "CN=erin@acme.test"
    And the admin revokes that certificate with reason "KEY_COMPROMISE"
    When an OCSP request is built for that certificate
    And OCSP is asked for the status
    Then the OCSP response status is "REVOKED"

  Scenario: Client cert authenticator resolves an active cert to its user
    Given tenant "acme" already has a root CA
    And user "frank@acme.test" exists in tenant "acme" for PKI tests
    And the admin issues a certificate bound to user "frank@acme.test"
    When the client cert authenticator validates that certificate
    Then the authentication result is success
    And the authenticated user email is "frank@acme.test"

  Scenario: Client cert authenticator rejects a revoked cert
    Given tenant "acme" already has a root CA
    And user "gina@acme.test" exists in tenant "acme" for PKI tests
    And the admin issues a certificate bound to user "gina@acme.test"
    And the admin revokes that certificate with reason "KEY_COMPROMISE"
    When the client cert authenticator validates that certificate
    Then the authentication result is failure
