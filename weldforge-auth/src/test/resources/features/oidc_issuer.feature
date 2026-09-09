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

  # ---------------------------------------------------------------------
  # Standards-conformance programme (docs/product/standards-conformance-backlog.md)
  #
  # Several of these describe a case where the server previously reported
  # success for something it had not done. Those are written from the relying
  # party's point of view on purpose: the defect was only visible from there.
  # ---------------------------------------------------------------------

  Scenario: A refreshed token carries only the scopes the user granted
    # CONF-1.1 / RFC 6749 §6. The client is registered for more than alice
    # agreed to; the refresh must not quietly hand back the difference.
    Given tenant "acme" has registered an OIDC client "wide-app" with redirect "https://app.acme.test/callback" and PKCE required
    And client "wide-app" is registered for scopes "openid email profile admin:read"
    And alice generates a PKCE verifier and challenge
    When alice authorizes "wide-app" for scope "openid email"
    And alice exchanges the resulting code with the matching verifier
    And the resulting refresh token is exchanged
    Then the issued scopes are "openid email"

  Scenario: A client may narrow scope on refresh but not widen it
    Given tenant "acme" has registered an OIDC client "wide-app" with redirect "https://app.acme.test/callback" and PKCE required
    And client "wide-app" is registered for scopes "openid email profile admin:read"
    And alice generates a PKCE verifier and challenge
    When alice authorizes "wide-app" for scope "openid email profile"
    And alice exchanges the resulting code with the matching verifier
    And the refresh token is exchanged requesting scope "openid email"
    Then the issued scopes are "openid email"
    When the refresh token is exchanged requesting scope "openid admin:read"
    Then the exchange is rejected with error code "invalid_scope"

  Scenario: Replaying an authorization code revokes the tokens it produced
    # CONF-1.2 / RFC 6749 §4.1.2. Refusing the second exchange is only half of
    # it: a replay proves the code leaked, so the first exchange's tokens are
    # suspect too -- and the victim of a race they won gets no other signal.
    Given alice generates a PKCE verifier and challenge
    When alice authorizes "acme-app" for scope "openid email"
    And alice exchanges the resulting code with the matching verifier
    And the same code is exchanged a second time
    Then the exchange is rejected with error code "invalid_grant"
    And the refresh token family from the first exchange is revoked

  Scenario: Revoking a refresh token actually revokes it
    # CONF-6.3 / RFC 7009. This previously returned 200 and did nothing, so a
    # relying party ending a session was told it had succeeded.
    Given alice generates a PKCE verifier and challenge
    When alice authorizes "acme-app" for scope "openid email"
    And alice exchanges the resulting code with the matching verifier
    And the refresh token is revoked by client "acme-app"
    Then the refresh token family from the first exchange is revoked

  Scenario: A client cannot revoke another client's refresh token
    Given tenant "acme" has registered an OIDC client "rival-app" with redirect "https://app.acme.test/callback" and PKCE required
    And alice generates a PKCE verifier and challenge
    When alice authorizes "acme-app" for scope "openid email"
    And alice exchanges the resulting code with the matching verifier
    And the refresh token is revoked by client "rival-app"
    Then the refresh token family from the first exchange is still active

  Scenario: The authorization response names the issuer that produced it
    # CONF-1.4 / RFC 9207. Every tenant is a separate issuer behind one
    # hostname, which is the deployment shape mix-up attacks target.
    When I fetch the discovery document for tenant "acme"
    Then the discovery document advertises issuer identification

  Scenario: Discovery advertises every grant the token endpoint implements
    # CONF-4.2. Capability detection is the point of discovery; it previously
    # omitted the refresh grant and the registration endpoint, both live.
    When I fetch the discovery document for tenant "acme"
    Then the discovery document lists grant type "refresh_token"
    And the discovery document lists grant type "authorization_code"
    And the discovery document advertises a registration endpoint
    And the discovery document lists auth method "client_secret_basic"
    And the discovery document lists auth method "client_secret_post"

  # --- Sprint 4: OIDC Core request parameters --------------------------

  Scenario: An ID token reports when the user actually authenticated
    # CONF-2.2 / OIDC Core §2. iat says when the TOKEN was minted and moves
    # forward on every refresh; auth_time says when the PERSON proved who they
    # are, which is what a relying party gates a sensitive operation on.
    Given alice authenticated 10 minutes ago
    And alice generates a PKCE verifier and challenge
    When alice authorizes "acme-app" for scope "openid email"
    And alice exchanges the resulting code with the matching verifier
    Then the ID token reports the authentication from 10 minutes ago
    And the ID token's auth_time is earlier than its iat

  Scenario: A grant with no recorded authentication time omits the claim
    # Defaulting it to "now" would assert a fresh login that never happened.
    Given alice's authentication time is unknown
    And alice generates a PKCE verifier and challenge
    When alice authorizes "acme-app" for scope "openid email"
    And alice exchanges the resulting code with the matching verifier
    Then the ID token has no auth_time claim

  Scenario: The ID token is bound to the access token issued with it
    # CONF-2.4. Lets a relying party detect a substituted access token.
    Given alice generates a PKCE verifier and challenge
    When alice authorizes "acme-app" for scope "openid email"
    And alice exchanges the resulting code with the matching verifier
    Then the ID token's at_hash matches the issued access token

  Scenario: A standing consent is remembered, so the user is not asked twice
    # CONF-2.3. Re-prompting on every login trains people to click through the
    # one screen that asks them to think.
    Given alice has already consented to "acme-app" for scope "openid email"
    When alice's consent for "acme-app" covering "openid email" is checked
    Then the standing consent applies

  Scenario: Consent does not stretch to scopes the user never agreed to
    Given alice has already consented to "acme-app" for scope "openid email"
    When alice's consent for "acme-app" covering "openid email admin:write" is checked
    Then the standing consent does not apply

  Scenario: A narrower request is covered by a wider standing consent
    Given alice has already consented to "acme-app" for scope "openid email profile"
    When alice's consent for "acme-app" covering "openid" is checked
    Then the standing consent applies

  Scenario: max_age forces a fresh factor when the last one is stale
    # CONF-2.1. The step-up machinery existed but nothing on the wire could
    # reach it: /authorize never bound max_age and passed a literal null.
    Given "acme-app" requires MFA
    And alice has a verified factor last used 40 minutes ago
    And alice generates a PKCE verifier and challenge
    When alice authorizes "acme-app" for scope "openid email" with max_age 600
    Then a step-up challenge is required

  Scenario: A recent factor satisfies max_age without re-prompting
    Given "acme-app" requires MFA
    And alice has a verified factor last used 2 minutes ago
    And alice generates a PKCE verifier and challenge
    When alice authorizes "acme-app" for scope "openid email" with max_age 600
    Then an authorization code is issued without a step-up challenge
