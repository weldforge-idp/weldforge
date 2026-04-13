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
