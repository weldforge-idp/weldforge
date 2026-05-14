# PRD MAIL-01 — Password reset email send

**Status:** proposed, not yet implemented
**Captured:** 2026-05-07

## Background

`PasswordResetService.requestReset` currently logs the raw reset token to
stdout instead of emailing it. The code carries an explicit TODO:

```java
// In production this would be emailed. For now, log it.
log.info("Password reset token for {}: {}", email, rawToken);
```

The HTTP endpoint returns 200 with the standard "if that email is
registered, a reset link has been sent" body, so the API contract looks
correct from the outside. End users see "we sent a link" in the UI but
no link arrives — the only way to recover the token today is to read
sso-api logs (operator access required), which is not a real
self-service password recovery.

## Requirement

Implement actual email send for password-reset, email-verification, and
admin-invite flows. The system already has the surrounding plumbing —
audit events, token persistence, per-tenant feature flags
(`password_recovery_enabled`) — only the SMTP / provider call is
missing.

### Functional requirements

1. **Provider abstraction.** A single `MailSender` interface with a
   pluggable implementation. Concrete adapters at minimum: SMTP (RFC
   5321, with STARTTLS), and one HTTP API provider (SendGrid /
   Mailgun / Postmark / SES — pick one for first cut).
2. **Per-tenant configuration.** Like the existing Twilio / LDAP
   configs, each tenant chooses its provider + credentials. Empty
   configuration = use the platform default. Empty platform default =
   continue to log-only (preserves current dev behaviour).
3. **Templates.** At minimum: password-reset, email-verification,
   admin-invite. Templates are HTML + plaintext, per tenant overrideable
   (sits naturally next to the existing tenant `branding` JSONB).
4. **Failure mode.** A send failure is logged, audited
   (`AUTH_PASSWORD_RESET_EMAIL_FAILED`), and surfaced to the operator —
   but it must NOT leak via the API response. The endpoint stays 200 to
   avoid user enumeration.
5. **Bounce handling.** Out of scope for v1; capture in a follow-up.
   First cut just needs reliable forward-path delivery.

### Non-functional requirements

- Token must remain log-only when no provider is configured, so dev
  loops keep working.
- Provider credentials encrypted at rest (use
  `EncryptedStringConverter` like the SAML / Twilio creds).
- Send is non-blocking — the controller must not wait on SMTP RTT.
  Either an executor or a webhook-style queue.

## Touch points

- `tech.cwvermaak.weldforge.service.PasswordResetService` — the
  `// In production this would be emailed` TODO.
- `tech.cwvermaak.weldforge.service.EmailVerificationService` — same
  pattern likely lives there.
- `tech.cwvermaak.weldforge.service.AdminService` invitation flow.
- New table `tenant_mail_providers` (tenant_id, provider_type,
  config_json, enabled) following the `tenant_twilio_providers` shape.
- New `MAIL_*` PRD code group in agents.html / docs.

## Out of scope (for MAIL-01)

- Bounce / complaint webhook handling.
- Click-tracking.
- Marketing-style scheduled / drip campaigns.
- Outbound CRM sync (separate CRM-* requirements).

## Sequencing note

Build behind a feature flag so a deploy that doesn't yet have a
provider configured continues to log the token (current behaviour) and
nothing changes for existing tenants until they explicitly opt in.
