Feature: SAML IdP mode
  The system acts as a SAML Identity Provider, issuing signed assertions
  to registered downstream Service Providers using the tenant's RSA key.

  Background:
    Given tenant "acme" is configured for SAML IdP
    And a SAML service provider "https://app.acme.test/saml" is registered for tenant "acme"
    And user "alice@acme.test" exists for SAML IdP in tenant "acme"

  Scenario: IdP metadata contains the tenant's signing certificate
    When I fetch the IdP metadata for tenant "acme"
    Then the metadata entity ID contains "acme"
    And the metadata includes an SSO endpoint
    And the metadata includes a signing key

  Scenario: Issue a signed SAML assertion for a registered SP
    When a SAML Response is built for "alice@acme.test" to SP "https://app.acme.test/saml"
    Then the SAML response is base64-encoded
    And the decoded response contains assertion subject "alice@acme.test"
    And the decoded response contains audience "https://app.acme.test/saml"
    And a "saml_idp.assertion.issued" audit event is recorded for SAML IdP

  Scenario: AuthnRequest from an unregistered SP is rejected
    When an AuthnRequest from "https://unknown.test/saml" is validated for tenant "acme"
    Then the SAML IdP request is rejected

  Scenario: Tenant isolation — acme's IdP does not serve globex SPs
    Given tenant "globex" is configured for SAML IdP with SP "https://app.globex.test/saml"
    When an AuthnRequest from "https://app.globex.test/saml" is validated for tenant "acme"
    Then the SAML IdP request is rejected

  Scenario: A well-formed AuthnRequest's issuer is parsed safely
    When a raw SAML AuthnRequest from "https://app.acme.test/saml" is parsed
    Then the parsed SAML issuer is "https://app.acme.test/saml"

  Scenario: A SAML message carrying a DOCTYPE is rejected (XXE defense)
    When a SAML AuthnRequest containing a DOCTYPE is parsed
    Then the SAML message is rejected as unsafe
