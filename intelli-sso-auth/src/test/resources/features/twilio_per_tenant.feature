Feature: Per-tenant Twilio configuration and SMS OTP MFA
  Twilio credentials are stored per-tenant (encrypted at rest) and managed
  via the admin portal. SMS OTP MFA uses the caller's tenant Twilio config
  to deliver the code. No global TWILIO_* env vars.

  Background:
    Given tenant "acme" exists for Twilio tests
    And user "alice@acme.test" exists in tenant "acme" for Twilio tests

  Scenario: Admin configures Twilio for a tenant
    When admin saves Twilio config for tenant "acme" with SID "ACaaaa1111" and token "tok-secret-aaa" and from "+27821111111"
    Then the Twilio config for tenant "acme" has account SID "ACaaaa1111"
    And the Twilio auth token is stored encrypted
    And a "twilio_provider.upsert" audit event is recorded for Twilio

  Scenario: Tenant isolation — tenant A cannot read tenant B's Twilio config
    Given tenant "globex" exists for Twilio tests
    And admin saves Twilio config for tenant "globex" with SID "ACgggg1111" and token "tok-secret-ggg" and from "+27822222222"
    When the acting tenant is "acme" and we try to read tenant "globex" Twilio config
    Then the read is rejected as cross-tenant

  Scenario: Enroll an SMS OTP factor using tenant Twilio
    Given admin saves Twilio config for tenant "acme" with SID "ACaaaa1111" and token "tok-secret-aaa" and from "+27821111111"
    When alice enrolls an SMS factor with phone "+27831234567"
    Then an SMS is sent via the tenant Twilio config
    And a pending unverified SMS factor exists for alice
    And a "mfa.sms.code_sent" audit event is recorded for Twilio

  Scenario: Activate the SMS factor with the correct code
    Given admin saves Twilio config for tenant "acme" with SID "ACaaaa1111" and token "tok-secret-aaa" and from "+27821111111"
    And alice enrolls an SMS factor with phone "+27831234567"
    When alice activates the SMS factor with the code that was sent
    Then the SMS factor is marked verified

  Scenario: SMS enrollment fails when tenant has no Twilio config
    When alice enrolls an SMS factor with phone "+27831234567"
    Then the SMS enrollment is rejected because no Twilio config exists
