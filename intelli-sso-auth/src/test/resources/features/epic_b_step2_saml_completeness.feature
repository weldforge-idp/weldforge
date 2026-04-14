Feature: SAML protocol completeness — metadata import, NameID formats, SLO bindings, attribute release
  PRD SAM-05 (metadata import), SAM-06 (SLO sync + async bindings),
  SAM-07 (all 4 NameID formats), SAM-08 (per-SP attribute release).

  Background:
    Given tenant "acme" exists for SAML completeness tests

  # --- SAM-05: metadata import -----------------------------------------

  Scenario: Import SP metadata from XML pre-fills the SP config
    When the admin imports SP metadata XML with entityID "https://app.acme.test/saml"
    Then the parsed SP dto has entityId "https://app.acme.test/saml"
    And the parsed SP dto has an ACS url
    And the parsed SP dto has a signing certificate in PEM format

  Scenario: Import IdP metadata from XML pre-fills the IdP config
    When the admin imports IdP metadata XML with entityID "https://idp.example.test"
    Then the parsed IdP dto has entityId "https://idp.example.test"
    And the parsed IdP dto has an SSO url

  Scenario: Metadata with DOCTYPE is rejected (XXE protection)
    When the admin imports SP metadata XML containing a DOCTYPE declaration
    Then the metadata parse is rejected

  # --- SAM-07: NameID formats ------------------------------------------

  Scenario: NameID format emailAddress uses the user's email
    Given user "alice@acme.test" exists for SAML completeness tests
    When a NameID is resolved for alice with format "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    Then the resolved NameID is "alice@acme.test"

  Scenario: NameID format persistent uses the user id
    Given user "alice@acme.test" exists for SAML completeness tests
    When a NameID is resolved for alice with format "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    Then the resolved NameID is the user id

  Scenario: NameID format transient is random per call
    Given user "alice@acme.test" exists for SAML completeness tests
    When two NameIDs are resolved with format "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    Then the two resolved NameIDs are different

  Scenario: NameID format unspecified falls back to email
    Given user "alice@acme.test" exists for SAML completeness tests
    When a NameID is resolved for alice with format "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
    Then the resolved NameID is "alice@acme.test"

  # --- SAM-06: SLO bindings --------------------------------------------

  Scenario: IdP-initiated logout with POST binding base64-encodes the request
    Given an SP "https://app.acme.test/saml" is registered for tenant "acme" with SLO URL
    And user "alice@acme.test" exists for SAML completeness tests
    When alice initiates SLO with POST binding
    Then the logout payload is base64 raw xml
    And the logout payload contains "LogoutRequest"

  Scenario: IdP-initiated logout with REDIRECT binding deflates the request
    Given an SP "https://app.acme.test/saml" is registered for tenant "acme" with SLO URL
    And user "alice@acme.test" exists for SAML completeness tests
    When alice initiates SLO with REDIRECT binding
    Then the logout payload is deflate-compressed base64

  # --- SAM-08: attribute release ---------------------------------------

  Scenario: Attribute release policy filters which attributes are emitted
    Given an SP "https://app.acme.test/saml" is registered for tenant "acme" with release policy email name
    And user "alice@acme.test" exists for SAML completeness tests
    When alice receives a SAML assertion for the SP
    Then the assertion contains attribute "email"
    And the assertion contains attribute "name"
    And the assertion does not contain attribute "groups"
    And the assertion does not contain attribute "role"

  Scenario: No release policy releases all attributes (backward compatible)
    Given an SP "https://app.acme.test/saml" is registered for tenant "acme" with no release policy
    And user "alice@acme.test" exists for SAML completeness tests
    When alice receives a SAML assertion for the SP
    Then the assertion contains attribute "email"
    And the assertion contains attribute "sub"
