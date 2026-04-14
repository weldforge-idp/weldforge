Feature: OIDC protocol completeness — RP-initiated logout, per-tenant session lifetimes, custom claims
  PRD OID-04 (RP-initiated logout), SSO-03 (per-tenant session TTL),
  OA2-07 (per-tenant custom JWT claims).

  Background:
    Given tenant "acme" exists for Epic B tests
    And user "alice@acme.test" exists in tenant "acme" for Epic B tests

  Scenario: OIDC discovery advertises the end_session_endpoint
    When the OIDC discovery document for tenant "acme" is fetched
    Then the discovery document contains end_session_endpoint for tenant "acme"

  Scenario: Per-tenant access TTL overrides the application default
    Given tenant "acme" has access TTL 120000 ms
    When alice logs in and receives an access token
    Then the token expires in approximately 120 seconds

  Scenario: Custom claims are injected into access tokens
    Given tenant "acme" has custom claim "org" with value "acme-corp"
    And tenant "acme" has custom claim "tier" with value "gold"
    When alice logs in and receives an access token
    Then the access token contains claim "org" with value "acme-corp"
    And the access token contains claim "tier" with value "gold"

  Scenario: Reserved claim names cannot be overwritten via custom claims
    Given tenant "acme" has custom claim "sub" with value "attacker"
    And tenant "acme" has custom claim "org" with value "acme-corp"
    When alice logs in and receives an access token
    Then the access token subject is the caller email
    And the access token contains claim "org" with value "acme-corp"

  Scenario: TTL below the allowed minimum is rejected
    When admin tries to set tenant "acme" access TTL to 30000 ms
    Then the update is rejected as out of range

  Scenario: TTL above the allowed maximum is rejected
    When admin tries to set tenant "acme" access TTL to 3000000000 ms
    Then the update is rejected as out of range
