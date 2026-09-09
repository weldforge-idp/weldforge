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

  Scenario: An SP that requires signed AuthnRequests accepts a validly-signed request
    Given an SP "https://signed.acme.test/saml" that requires signed AuthnRequests
    When a validly-signed AuthnRequest from that SP is verified
    Then the SAML signature check passes

  Scenario: An SP that requires signed AuthnRequests rejects an unsigned request
    Given an SP "https://signed.acme.test/saml" that requires signed AuthnRequests
    When an unsigned AuthnRequest from that SP is verified
    Then the SAML signature check fails

  Scenario: An SP that does not require signing accepts an unsigned request
    Given an SP "https://unsigned.acme.test/saml" that does not require signed AuthnRequests
    When an unsigned AuthnRequest from that SP is verified
    Then the SAML signature check passes

  Scenario: Signed-AuthnRequest enforcement is configurable through the admin API
    When an SP "https://api.acme.test/saml" is registered requiring signed AuthnRequests
    Then the registered SP "https://api.acme.test/saml" requires signed AuthnRequests

  # --- Sprint 5: assertion fidelity -------------------------------------
  # What the IdP asserts about itself and about the user should be true.
  # Two of these failures were silent by construction: the authentication
  # context UNDER-reported assurance, and nobody is alerted when assurance is
  # understated.

  Scenario: An assertion reports the factors the user actually used
    Given tenant "acme" is configured for SAML IdP with SP "https://sp.acme.test"
    And user "alice@acme.test" exists for SAML IdP in tenant "acme"
    When a SAML Response is built for "alice@acme.test" to SP "https://sp.acme.test" with factors "pwd hwk"
    Then the assertion's authentication context is the two-factor class

  Scenario: A password-only session is still reported as password-protected
    Given tenant "acme" is configured for SAML IdP with SP "https://sp.acme.test"
    And user "alice@acme.test" exists for SAML IdP in tenant "acme"
    When a SAML Response is built for "alice@acme.test" to SP "https://sp.acme.test" with factors "pwd"
    Then the assertion's authentication context is the password class

  Scenario: An SP may pin the context it already expects
    # Without this, an SP matching on the old fixed value breaks the day one of
    # its users enables MFA -- and that looks like an IdP outage.
    Given tenant "acme" is configured for SAML IdP with SP "https://sp.acme.test"
    And SP "https://sp.acme.test" pins its authentication context to the password class
    And user "alice@acme.test" exists for SAML IdP in tenant "acme"
    When a SAML Response is built for "alice@acme.test" to SP "https://sp.acme.test" with factors "pwd hwk"
    Then the assertion's authentication context is the password class

  Scenario: An assertion carries a session index so logout can target it
    # Without a SessionIndex an SP cannot scope logout to one session, so SLO
    # can only ever mean "log out of everything".
    Given tenant "acme" is configured for SAML IdP with SP "https://sp.acme.test"
    And user "alice@acme.test" exists for SAML IdP in tenant "acme"
    When a SAML Response is built for "alice@acme.test" to SP "https://sp.acme.test"
    Then the assertion carries a session index

  Scenario: The signature carries a real certificate, not a bare key value
    Given tenant "acme" is configured for SAML IdP with SP "https://sp.acme.test"
    And user "alice@acme.test" exists for SAML IdP in tenant "acme"
    When a SAML Response is built for "alice@acme.test" to SP "https://sp.acme.test"
    Then the signature KeyInfo contains an X509 certificate
    And the signature KeyInfo contains no bare KeyValue

  Scenario: An SP keeps the legacy issuer until it opts in
    Given tenant "acme" is configured for SAML IdP with SP "https://sp.acme.test"
    And user "alice@acme.test" exists for SAML IdP in tenant "acme"
    When a SAML Response is built for "alice@acme.test" to SP "https://sp.acme.test"
    Then the assertion issuer is "acme-idp"

  Scenario: An SP that opts in receives the metadata entityID as issuer
    Given tenant "acme" is configured for SAML IdP with SP "https://sp.acme.test"
    And SP "https://sp.acme.test" opts in to the entityID issuer
    And user "alice@acme.test" exists for SAML IdP in tenant "acme"
    When a SAML Response is built for "alice@acme.test" to SP "https://sp.acme.test"
    Then the assertion issuer is the tenant's metadata entityID
