# Email deliverability — SendGrid SMTP

How WeldForge sends transactional email (password reset, email verification)
and how to keep it out of spam folders.

## 1. Transport

`SmtpMailService` (Spring `JavaMailSender`) sends via SendGrid SMTP. It is
**dormant until an SMTP host is configured** — `LoggingMailService` is the
fallback, which only logs. Helm wires the SMTP settings into the `sso-api`
deployment from `.Values.mail` (`infrastructure/helm/weldforge/values.yaml`).

Host, port, username (`apikey`) and the From address are non-secret. Only the
**API key** is sensitive; it is never committed — it lives in GCP Secret
Manager and is injected at deploy time.

## 2. Activation — one step

Everything is gated on the SendGrid API key being present in Secret Manager
(`api-secret.yaml` renders `SPRING_MAIL_*` only when `mail.password` is set).
To go live:

1. Obtain a SendGrid API key with the **Mail Send** scope only (see
   `docs/sendgrid-setup.md` or the registration steps).
2. Store it in GCP Secret Manager:
   ```bash
   printf '%s' 'SG.xxxxxxxx' | gcloud secrets create wf-sendgrid-api-key \
       --project=weldforge --data-file=-
   # if the secret already exists, add a new version instead:
   printf '%s' 'SG.xxxxxxxx' | gcloud secrets versions add wf-sendgrid-api-key \
       --project=weldforge --data-file=-
   ```
3. Trigger a deploy — push to `main`, or run the `deploy-gcp` workflow via
   `workflow_dispatch`.

`deploy-gcp.yml` reads the secret (tolerantly — an absent secret is treated as
empty), `--set-string mail.password=…`, and the chart then renders the SMTP
env. `SmtpMailService` (`@Primary`) takes over on pod start. With no secret,
nothing renders and mail stays on `LoggingMailService` — the deploy is safe
either way, so this change can ship before SendGrid is set up.

## 3. Deliverability — DNS (the anti-spam fix)

A password-reset email from `no-reply@weldforge.org` **will be spam-filtered**
unless the sending domain is authenticated. These are DNS records on
`weldforge.org`, applied at the registrar — they are **not** in this repo and
must be added by hand.

### 3a. SendGrid domain authentication (DKIM) — required

In SendGrid: **Settings → Sender Authentication → Authenticate Your Domain**,
for `weldforge.org`. SendGrid generates **three CNAME records that are unique
to the account** — shaped like:

```
em####.weldforge.org         CNAME  u#######.wl###.sendgrid.net
s1._domainkey.weldforge.org  CNAME  s1.domainkey.u#######.wl###.sendgrid.net
s2._domainkey.weldforge.org  CNAME  s2.domainkey.u#######.wl###.sendgrid.net
```

Add the three CNAMEs **exactly as SendGrid shows them**, then click Verify.
This provides DKIM signing and a domain-aligned return path.

### 3b. SPF

The April 2026 security audit flagged the apex SPF as `?all` (neutral — anyone
may spoof the domain). Tighten it:

```
weldforge.org  TXT  "v=spf1 include:spf.host-h.net -all"
```

Use `-all`, not `?all`. SendGrid's CNAME-based domain auth carries its own SPF
on the `em####` return-path subdomain, so no SendGrid `include` is needed on
the apex record — but the apex must still be hardened.

### 3c. DMARC

The audit flagged DMARC as missing. Add:

```
_dmarc.weldforge.org  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@weldforge.org; fo=1"
```

Start at `p=none` (monitor only — collects aggregate reports without affecting
delivery). After a week or two of clean reports, raise to `p=quarantine`, then
`p=reject`.

## 4. Verify

After DNS has propagated and a deploy with the secret is live:

- SendGrid console shows the domain as **Verified**.
- `POST /api/auth/forgot-password` for a test user — the pod log shows
  `Sent email: …` (`SmtpMailService`) rather than `Outbound email queued …`
  (`LoggingMailService`).
- Send a test message to a Gmail address; **Show original** should report
  **SPF: PASS, DKIM: PASS, DMARC: PASS**.
