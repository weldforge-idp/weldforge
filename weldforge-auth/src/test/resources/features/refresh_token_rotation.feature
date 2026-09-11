Feature: Refresh token rotation with reuse detection
  Refresh tokens rotate on every use. Presenting a token that has
  already been rotated is an unambiguous theft signal — the entire
  family is revoked and a high-severity audit event is recorded.

  Background:
    Given alice is logged in and holds refresh token "A"

  Scenario: Using the refresh token issues a successor and invalidates the original
    When alice exchanges "A" for a new access token
    Then the rotation succeeds
    And "A" is marked as used
    And a new token "B" is issued in the same family

  Scenario: Replaying the original token after it has been rotated kills the whole family
    Given alice has already rotated "A" and received "B"
    When alice exchanges "A" for a new access token
    Then the operation is rejected as "bad credentials"
    And every token in the family is revoked
    And an "auth.refresh.reuse_detected" audit event with outcome DENIED is recorded

  # B-TEN-7 (2026-09-11): the refresh cookie is scoped to the whole base
  # domain, so a browser signed in to two tenants sends one tenant's token to
  # the other's refresh. A family is only ever rotated for its own tenant.

  Scenario: A refresh for alice's own tenant rotates her token
    When "A" is presented to a refresh for tenant "acme"
    Then the rotation succeeds
    And "A" is marked as used

  Scenario: A refresh for another tenant is refused and leaves the token intact
    When "A" is presented to a refresh for tenant "intellisuite"
    Then the failure is a bad-credentials error
    And "A" is still unused and unrevoked
    And an "auth.refresh.tenant_mismatch" audit event with outcome DENIED is recorded
    When "A" is presented to a refresh for tenant "acme"
    Then the rotation succeeds
