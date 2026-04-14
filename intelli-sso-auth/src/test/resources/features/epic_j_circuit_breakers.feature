Feature: Circuit breakers guard downstream dependencies (PRD AVL-04)
  Outbound calls to dependencies like the webhook HTTP client and Twilio
  run inside a Resilience4j circuit breaker. Consecutive failures open
  the breaker so the next calls fast-fail instead of piling up on a
  struggling downstream. A successful call in half-open state closes
  the breaker and normal traffic resumes.

  Background:
    Given a circuit breaker "webhook" with failure threshold 50% and window 5
    And the webhook HTTP client is wrapped with the "webhook" circuit breaker

  Scenario: Successful calls keep the breaker closed
    Given the underlying HTTP client always succeeds
    When the webhook client posts 5 times
    Then the circuit breaker state is "CLOSED"
    And 5 underlying calls were made

  Scenario: Breaker opens after enough failures
    Given the underlying HTTP client always fails with 500
    When the webhook client posts 5 times
    Then the circuit breaker state is "OPEN"

  Scenario: Open breaker fast-fails subsequent calls
    Given the underlying HTTP client always fails with 500
    When the webhook client posts 5 times
    And the webhook client posts 3 more times
    Then the circuit breaker state is "OPEN"
    And only 5 underlying calls were made
    And the last 3 results all carry a "circuit breaker open" error

  Scenario: Breaker recovers via half-open probe
    Given the underlying HTTP client always fails with 500
    When the webhook client posts 5 times
    Then the circuit breaker state is "OPEN"
    Given the circuit breaker is transitioned to half-open
    And the underlying HTTP client always succeeds
    When the webhook client posts 3 times
    Then the circuit breaker state is "CLOSED"
