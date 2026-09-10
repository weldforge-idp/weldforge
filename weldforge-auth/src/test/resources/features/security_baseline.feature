Feature: Platform security baseline
  CONF-7.2 (Content-Security-Policy on every response, nonces on the
  server-rendered pages) and CONF-7.3 (RFC 9457 Problem Details on /api/**,
  protocol endpoints unchanged).

  These scenarios run the real header writer, page renderers, exception
  handler and filters. The same acceptance criteria are also checked through
  the complete Spring Security chain -- where Referrer-Policy and nosniff come
  from -- in SecurityHeadersAndProblemsIntegrationTest.

  # --- CONF-7.2 -------------------------------------------------------------

  Scenario: Security headers are present
    When any response is returned
    Then Content-Security-Policy is present with default-src 'self'
    And inline scripts and styles need this response's nonce
    And no page may frame the response
    And no two responses share a nonce

  Scenario Outline: A server-rendered page renders under its own policy
    When the <page> is served
    Then its inline blocks carry a per-render nonce matching the CSP
    And the page needs nothing the policy forbids

    Examples:
      | page                     |
      | consent screen           |
      | SAML POST form           |
      | tenant verification page |
      | hosted sign-in page      |

  # --- CONF-7.3 -------------------------------------------------------------

  Scenario: API errors are Problem Details
    When an /api/** call fails validation
    Then the content type is application/problem+json
    And the body carries type, title, status and detail
    And the body still carries the legacy error and message members

  Scenario: Errors written by filters are Problem Details too
    When an /api/** call is refused for its content type
    Then the content type is application/problem+json
    And the body carries type, title, status and detail

  Scenario: Protocol endpoints are unchanged
    When an OAuth2 token request fails
    Then the body is still {error, error_description}
    When a SCIM request fails
    Then the body is still a SCIM error response
