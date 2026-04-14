Feature: SAML assertion encryption (PRD SAM-04)
  Service providers can opt in to receiving encrypted assertions. When
  enabled, the IdP wraps the signed Assertion in an EncryptedAssertion
  element using AES-256-CBC for the content and RSA-OAEP for the key
  wrap under the SP's public certificate. The SP decrypts using its
  private key and recovers the original signed assertion.

  Scenario: Encrypter produces an EncryptedAssertion wrapper
    Given a fresh RSA test keypair with a self-signed certificate
    And an inner signed assertion XML "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a1\">body</saml:Assertion>"
    When the assertion is encrypted to the test certificate
    Then the output contains a "saml:EncryptedAssertion" element
    And the output contains a "xenc:EncryptedData" element
    And the output references the "aes256-cbc" content algorithm
    And the output references the "rsa-oaep-mgf1p" key wrap algorithm

  Scenario: SP decrypts the EncryptedAssertion with its private key
    Given a fresh RSA test keypair with a self-signed certificate
    And an inner signed assertion XML "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a2\"><saml:Issuer>idp</saml:Issuer></saml:Assertion>"
    When the assertion is encrypted to the test certificate
    And the SP decrypts the EncryptedAssertion with its private key
    Then the recovered assertion XML equals the original

  Scenario: Different ciphertexts each encryption (IV + random AES key)
    Given a fresh RSA test keypair with a self-signed certificate
    And an inner signed assertion XML "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a3\">same</saml:Assertion>"
    When the assertion is encrypted to the test certificate twice
    Then the two ciphertexts are different
    And both decrypt back to the original
