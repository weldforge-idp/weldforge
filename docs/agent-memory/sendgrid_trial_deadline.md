---
name: sendgrid-trial-deadline
description: SendGrid trial-tier perks expire 2026-07-16 but the account is already on Free — no downgrade action needed; verify delivery on 2026-07-14
metadata: 
  node_type: memory
  type: project
  originSessionId: e91dbe85-0918-4ed6-96ef-1ead548c4fc7
---

weldforge-auth sends transactional email (password reset, email verification, V2a tenant verification challenges) via SendGrid SMTP — `smtp.sendgrid.net`, API key in GCP Secret Manager `wf-sendgrid-api-key`.

**Plan state confirmed 2026-05-22 by the account owner.** The SendGrid dashboard's plan-selection page shows **Free** as "Your Current Plan" with **100 emails/day**. The 2026-07-16 date is when SendGrid's *trial-tier perks layered on top of Free* expire (extended activity history, higher daily limits during trial), not a hard plan cliff. After that date the account stays on Free at the standard 100/day limit. There is no "Downgrade to Free" button to click; the account is already there.

**Why this differs from the original framing:** earlier session notes treated 2026-07-16 as a hard deadline by which an explicit downgrade had to be performed to avoid silent delivery breakage. The dashboard inspection on 2026-05-22 (Twilio Console → SendGrid → Account Details → Email API Plans page) showed "Your Current Plan" indicator was already on the Free row. The "Free Trial" label on the same row is a trial of paid-tier *perks*, not a trial of paid-tier *access*. SendGrid's trial mechanic has changed over the years; the original framing was a worst-case interpretation that turned out not to apply.

**How to apply:**
- Don't attempt a SendGrid "downgrade" action — there's no UI button for it. The account is already on Free.
- Hold a calendar reminder for **2026-07-14** (48h before perks expire) to run the smoke test: `curl -X POST https://sso.weldforge.org/api/auth/forgot-password -H 'Content-Type: application/json' -d '{"identifier":"<test-email>"}'` then check SendGrid Activity Feed for "Delivered".
- If delivery does break, escalate via SendGrid Ticket Support (included on the Free tier per the dashboard's plan feature list).
- The 100/day cap is comfortably above current send volume (single-digit emails/day across all tenants), so the cap itself isn't a concern in foreseeable timelines.

**Residual concern (independent of SendGrid).** `SmtpMailService` logs a delivery failure at WARN but the triggering security operation still returns success. So *any* silent SMTP breakage — not just plan changes — leaves the platform without a user-visible signal. A Prometheus alert on `sso.mail.send` failure counter would close that gap properly; tracked as a separate observability follow-up.

See also docs/email-deliverability.md and [[deployment_pipeline]].
