---
name: SendGrid mail is now alert-monitored, not calendar-monitored
description: New SendGrid account since 2026-09-13; mail was dead for two weeks after the GCP move; the Prometheus alert replaces the old manual smoke test
metadata:
  node_type: memory
  type: project
---

The old account and its 2026-07-16 trial-perks date are **history**.

**Outbound mail was dead from the GCP move (2026-08-31) until 2026-09-13** — no
SMTP was configured on k3s at all. Nobody noticed for two weeks, because
`SmtpMailService` catches the delivery failure and the triggering security
operation (password reset, email verification, identity-proofing challenge)
still returns success by contract. Every account recovery in that window
silently failed.

Current state:
- New SendGrid account; sender domain authentication completed on
  `weldforge.org` via Cloudflare (`em1505` CNAME, `s1`/`s2._domainkey`).
- SMTP settings: `smtp.sendgrid.net:587`, STARTTLS **true** and SSL **false**
  (not interchangeable), username the literal string `apikey`, password in
  `SPRING_MAIL_PASSWORD` in the SOPS secret — **different values in staging and
  production**, verify rather than assume. From `no-reply@weldforge.org`.
- Free tier, 100/day, comfortably above current volume. Trial perks on the new
  account run to 2026-11-12 per the dashboard at signup — a perks date, not a
  plan cliff, and there is nothing to click when it passes.
- Dead Cloudflare records from the old account still to clean up: `em8050`,
  `107605731`, `url7762`.

**How to apply:** do **not** re-add a calendar reminder for a manual smoke test.
The `WeldForgeMailDeliveryFailing` Prometheus alert watches
`sso_mail_send_total{outcome="failure"}` and pushes to ntfy within 15 minutes of
a failure — that is what the old 48h-before check was standing in for. See
[[session_2026_09_14]] and `docs/monitoring.md` in the infrastructure repo.
