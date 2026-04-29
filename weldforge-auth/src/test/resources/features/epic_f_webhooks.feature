Feature: Outbound webhooks — matching, HMAC signing, retry, dead-letter (PRD API-05, API-06, SSO-09)
  Tenants register HTTP endpoints to receive lifecycle events. Every
  delivery is signed with HMAC-SHA256 using the subscription secret.
  Failed deliveries are retried with exponential backoff and eventually
  dead-lettered after max_attempts.

  Background:
    Given tenant "acme" exists for webhook tests
    And tenant "other" exists for webhook tests

  Scenario: Subscription with no filter receives every event
    Given tenant "acme" has webhook subscription "all" targeting "https://hook.acme.test/all"
    When webhook event "user.create" is published for tenant "acme"
    Then a delivery was attempted to "https://hook.acme.test/all"
    And the delivery carries an HMAC-SHA256 signature header
    And the delivery was marked SUCCESS

  Scenario: Event type matches a glob filter
    Given tenant "acme" has webhook subscription "users" targeting "https://hook.acme.test/users" filtering "user.*"
    When webhook event "user.create" is published for tenant "acme"
    Then a delivery was attempted to "https://hook.acme.test/users"

  Scenario: Event type does not match the filter — no delivery
    Given tenant "acme" has webhook subscription "mfa-only" targeting "https://hook.acme.test/mfa" filtering "mfa.*"
    When webhook event "user.create" is published for tenant "acme"
    Then no delivery was attempted to "https://hook.acme.test/mfa"

  Scenario: Tenant isolation — other tenant's subscriptions do not see events
    Given tenant "other" has webhook subscription "nosey" targeting "https://hook.other.test/all"
    When webhook event "user.create" is published for tenant "acme"
    Then no delivery was attempted to "https://hook.other.test/all"

  Scenario: 5xx response schedules a retry with backoff
    Given tenant "acme" has webhook subscription "flaky" targeting "https://hook.acme.test/flaky"
    And the HTTP client returns 500 for "https://hook.acme.test/flaky"
    When webhook event "user.create" is published for tenant "acme"
    Then the delivery was marked PENDING
    And the delivery has next_attempt_at in the future

  Scenario: Repeated failures reach dead letter after max_attempts
    Given tenant "acme" has webhook subscription "broken" targeting "https://hook.acme.test/broken" with max attempts 2
    And the HTTP client returns 500 for "https://hook.acme.test/broken"
    When webhook event "user.create" is published for tenant "acme"
    And the retry scheduler runs
    Then the delivery was marked DEAD_LETTER

  Scenario: 4xx response is a non-retryable failure
    Given tenant "acme" has webhook subscription "bad-url" targeting "https://hook.acme.test/bad"
    And the HTTP client returns 404 for "https://hook.acme.test/bad"
    When webhook event "user.create" is published for tenant "acme"
    Then the delivery was marked FAILED
