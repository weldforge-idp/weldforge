Feature: OIDC issuer
  WeldForge issues OpenID Connect tokens, signed with a per-tenant RSA
  key. Each tenant exposes its own discovery document and JWKS, so
  tokens issued for one tenant cannot be replayed against another.

  Background:
    Given tenant "acme" has its own RSA signing key
    And tenant "acme" has registered an OIDC client "acme-app" with redirect "https://app.acme.test/callback" and PKCE required
    And user "alice@acme.test" exists in tenant "acme"

  Scenario: The discovery doc points at the tenant's own endpoints
    When I fetch the discovery document for tenant "acme"
    Then the issuer is the tenant URL
    And the jwks contains the tenant's signing key
    And RS256 is the only listed signing algorithm

  Scenario: A code flow with PKCE produces a signed access token + ID token
    Given alice generates a PKCE verifier and challenge
    When alice authorizes "acme-app" for scope "openid email"
    And alice exchanges the resulting code with the matching verifier
    Then an access token and an ID token are issued
    And the ID token is signed with the tenant's RSA key
    And the ID token's "iss" claim equals the tenant issuer
    And the ID token's "aud" claim equals "acme-app"

  Scenario: A wrong PKCE verifier rejects the exchange
    Given alice generates a PKCE verifier and challenge
    When alice authorizes "acme-app" for scope "openid email"
    And alice exchanges the resulting code with a wrong verifier
    Then the exchange is rejected with error code "invalid_grant"

  Scenario: A code issued for one tenant cannot be exchanged at another
    Given alice generates a PKCE verifier and challenge
    And tenant "globex" exists with its own signing key
    When alice authorizes "acme-app" for scope "openid email"
    And the same code is presented at tenant "globex"
    Then the exchange is rejected with error code "invalid_grant"

  Scenario: Token introspection reports an active token with claims
    Given alice generates a PKCE verifier and challenge
    When alice authorizes "acme-app" for scope "openid email"
    And alice exchanges the resulting code with the matching verifier
    And the access token is introspected at tenant "acme"
    Then the introspection result is active
    And the introspection result client_id is "acme-app"
    And the introspection result sub is alice's user id

  Scenario: Token introspection reports a revoked token as inactive
    Given alice generates a PKCE verifier and challenge
    When alice authorizes "acme-app" for scope "openid email"
    And alice exchanges the resulting code with the matching verifier
    And the access token is revoked by client "acme-app"
    And the access token is introspected at tenant "acme"
    Then the introspection result is inactive

  Scenario: Token introspection rejects garbage with active=false
    When the token "not-a-jwt" is introspected at tenant "acme"
    Then the introspection result is inactive
