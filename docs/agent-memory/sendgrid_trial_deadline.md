---
name: sendgrid-trial-deadline
description: SendGrid free trial ends 2026-07-16 — downgrade to the free plan before then or transactional email stops
metadata: 
  node_type: memory
  type: project
  originSessionId: e91dbe85-0918-4ed6-96ef-1ead548c4fc7
---

weldforge-auth sends transactional email (password reset, email verification) via SendGrid SMTP — `smtp.sendgrid.net`, API key in GCP Secret Manager `wf-sendgrid-api-key`. The SendGrid account is on a **Free Trial that ends 2026-07-16**. Before that date, downgrade to SendGrid's permanent Free plan.

**Why:** if the trial lapses, email delivery stops with no visible error in the app — `SmtpMailService` logs a delivery failure but the triggering security operation still succeeds, so account recovery silently breaks for every tenant.

**How to apply:** in the SendGrid dashboard, select the Free plan before 2026-07-16. See also docs/email-deliverability.md and [[deployment_pipeline]].
