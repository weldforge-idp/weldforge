Feature: Token model rebuild — hashed keys, scopes, service accounts (PRD TOK-01/02/03)
  API keys and service-account tokens are stored as SHA-256 hashes with a
  display-safe prefix. Raw secrets are returned exactly once on creation
  and never again. API keys can be restricted to {path, methods} scopes.
  Service accounts carry an admin role so M2M callers don't have to reuse
  a human user's credentials.

  Background:
    Given tenant "acme" exists for tokens tests

  Scenario: Create app client — raw key returned once, hash stored on disk
    When admin creates app client "integration-a"
    Then the returned raw key starts with "wf_live_"
    And the stored row has a non-null api_key_hash
    And the stored row has a null api_key

  Scenario: Auth filter accepts a hashed app-client key
    Given admin has created app client "integration-b"
    When a request to "/api/admin/ping" arrives with that raw key
    Then the auth filter allows the request

  Scenario: Auth filter rejects an unknown key
    When a request to "/api/admin/ping" arrives with raw key "wf_live_bogus"
    Then the auth filter denies the request with 403

  Scenario: Legacy plaintext key is rejected (CRITICAL-1 remediation)
    Given a legacy plaintext app client "legacy-c" exists with key "wf_live_legacy"
    When a request to "/api/admin/ping" arrives with raw key "wf_live_legacy"
    Then the auth filter denies the request with 403

  Scenario: Scoped key allows matching path and method
    Given admin has created app client "scoped-d" scoped to "/api/admin/users/**" methods "GET"
    When a GET request to "/api/admin/users/42" arrives with that raw key
    Then the auth filter allows the request

  Scenario: Scoped key rejects wrong method
    Given admin has created app client "scoped-e" scoped to "/api/admin/users/**" methods "GET"
    When a POST request to "/api/admin/users/42" arrives with that raw key
    Then the auth filter denies the request with 403

  Scenario: Scoped key rejects wrong path
    Given admin has created app client "scoped-f" scoped to "/api/admin/users/**" methods "GET"
    When a GET request to "/api/admin/roles" arrives with that raw key
    Then the auth filter denies the request with 403

  Scenario: Create service account — raw token returned once, admin role stored
    When admin creates service account "etl-bot" with role "TENANT_ADMIN"
    Then the returned raw token starts with "wf_svc_"
    And the stored service account has admin role "TENANT_ADMIN"

  Scenario: Service account auth populates TENANT_ADMIN in the TenantContext
    Given admin has created service account "etl-bot-b" with role "TENANT_ADMIN"
    When a request to "/api/admin/users" arrives with that service account token
    Then the auth filter allows the request
    And the TenantContext admin role is "TENANT_ADMIN"

  Scenario: Disabled service account is rejected
    Given admin has created service account "etl-bot-c" with role "TENANT_ADMIN"
    And the service account "etl-bot-c" is disabled
    When a request to "/api/admin/users" arrives with that service account token
    Then the auth filter denies the request with 403

  Scenario: Expired service account is rejected
    Given admin has created service account "etl-bot-d" with role "TENANT_ADMIN" that expired yesterday
    When a request to "/api/admin/users" arrives with that service account token
    Then the auth filter denies the request with 403

  # ----------------------------------------------------------------------
  # Platform HMAC key ring (B-JWT-2 / CONF-7.4)
  #
  # app.jwt.secret is shared verbatim with three external consumers, so with a
  # single key, rotating it was an all-or-nothing cutover: the instant it
  # changed, every token signed under the old one failed verification in
  # WeldForge and in all three consumers at the same moment. The ring lets the
  # new key sign while the old one still verifies, so the systems move one at a
  # time.
  # ----------------------------------------------------------------------

  Scenario: Before rotation, a token verifies under the only key
    Given the platform signing secret is "SECRET-A" with no retired keys
    When a platform token is signed
    Then the platform token verifies

  Scenario: After rotation, a token signed under the old secret still verifies
    Given the platform signing secret is "SECRET-A" with no retired keys
    And a platform token is signed and kept
    When the platform signing secret rotates to "SECRET-B" retaining "SECRET-A"
    Then the kept platform token still verifies

  Scenario: Once the overlap window is closed, the old token is refused
    Given the platform signing secret is "SECRET-A" with no retired keys
    And a platform token is signed and kept
    When the platform signing secret rotates to "SECRET-B" retaining nothing
    Then the kept platform token is refused

  Scenario: A retired key never signs
    Given the platform signing secret is "SECRET-B" with retired key "SECRET-A"
    When a platform token is signed
    Then the platform token verifies against signing secret "SECRET-B" alone
    And the platform token is refused by signing secret "SECRET-A" alone

  Scenario: A token labelled with a known key id but signed by another key is refused
    Given the platform signing secret is "SECRET-B" with retired key "SECRET-A"
    When a platform token is forged naming the active key id
    Then the platform token is refused

  Scenario: A token carrying no key id still verifies
    Given the platform signing secret is "SECRET-B" with retired key "SECRET-A"
    When a platform token is signed without a key id under "SECRET-B"
    Then the platform token verifies

  Scenario: An expired token reports expiry, not a signature failure
    Given the platform signing secret is "SECRET-B" with retired key "SECRET-A"
    When an expired platform token is signed under "SECRET-A"
    Then verifying the platform token reports that it expired
