Feature: Platform billing — payment-first-then-provision

  WeldForge charges subscribers via a configured payment gateway and
  provisions the tenant only after the gateway confirms funds cleared.
  The slug is reserved for 10 minutes while checkout is in flight and
  released if the customer never pays. Webhook delivery is idempotent:
  Stripe-style retries are absorbed by the (gateway_id, gateway_tx_id)
  unique index on billing_transactions.

  Background:
    Given the platform has a fake payment gateway configured for USD
    And the tier "cloud-starter" costs 2900 cents monthly

  Scenario: Happy path — paid order provisions a tenant
    When a customer submits an order for tier "cloud-starter" with slug "acme" and email "ops@acme.test"
    Then the order is in state "CHECKOUT_STARTED"
    And the customer received a checkout URL
    When a payment-succeeded webhook arrives for that order with tx id "ch_acme_1"
    Then the order is in state "PROVISIONED"
    And a tenant with slug "acme" exists
    And a TENANT_ADMIN service-account token exists for tenant "acme"
    And exactly 1 billing transaction is recorded as SUCCEEDED
    And an audit event "tenant.provisioned_via_billing" is recorded

  Scenario: Customer cancels checkout
    When a customer submits an order for tier "cloud-starter" with slug "widgets" and email "ops@widgets.test"
    And a checkout-cancelled webhook arrives for that order
    Then the order is in state "CANCELLED"
    And no tenant with slug "widgets" exists

  Scenario: Webhook with invalid signature is rejected
    Given a customer submitted an order for tier "cloud-starter" with slug "spoof" and email "bad@example.test"
    When a webhook arrives for that order with an invalid signature
    Then the webhook result is "SIGNATURE_INVALID"
    And the order is in state "CHECKOUT_STARTED"
    And no tenant with slug "spoof" exists

  Scenario: Duplicate webhook delivery does not double-provision
    When a customer submits an order for tier "cloud-starter" with slug "dup" and email "x@dup.test"
    And a payment-succeeded webhook arrives for that order with tx id "ch_dup_1"
    Then the order is in state "PROVISIONED"
    When the same payment-succeeded webhook arrives again with tx id "ch_dup_1"
    Then the order is in state "PROVISIONED"
    And exactly 1 billing transaction is recorded as SUCCEEDED
    And exactly 1 tenant with slug "dup" exists

  Scenario: Unpaid order expires when slug reservation lapses
    Given a customer submitted an order for tier "cloud-starter" with slug "stale" and email "late@stale.test" 11 minutes ago
    When the expiry scheduler runs
    Then the order is in state "EXPIRED"
    And the slug "stale" is available for a new order
