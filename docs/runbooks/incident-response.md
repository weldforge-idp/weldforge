# Security Incident-Response Plan — WeldForge IAM Platform

> **Audience:** the WeldForge operations team (small — see *Roles* below).
> **Scope:** the hosted WeldForge identity platform and everything that
> trusts it: `sso.weldforge.org`, `admin.weldforge.org`, the GKE cluster
> `weldforge-gke`, Cloud SQL `weldforge-db`, the tenant data it stores
> (credentials, MFA secrets, audit logs, per-tenant signing keys), and the
> external token consumers that share the platform HMAC (Safe Space, Krusty,
> Commons).
>
> **This is a runbook, not a policy essay.** When an incident is live, jump
> straight to the matching playbook. Read the rest cold, before you need it.
>
> Contacts that need real values are marked **`TODO`** — fill them in and keep
> them current; do not invent them mid-incident.

---

## 0. First five minutes (the cold-start checklist)

1. **Declare.** Say out loud / in writing "we have a security incident". Start
   a timestamped log (a single shared doc or a pinned chat thread). Every
   action and time goes here — you will need it for POPIA notification and the
   post-incident review.
2. **Assign the Incident Commander** (IC). On a one-person shift, you are it.
3. **Classify severity** using the matrix in §1. When unsure, round *up*.
4. **Preserve evidence before you remediate** — see §6. A Cloud SQL snapshot
   and a dump of pod logs take two commands and cannot be recovered after you
   start changing things.
5. **Start the clock for POPIA** (§5). The notification obligation begins the
   moment you have reasonable grounds to believe a compromise occurred — not
   when you finish fixing it.
6. **Open the matching playbook** (§4) and work detect → contain → eradicate →
   recover → post-incident.

---

## 1. Scope & severity matrix

Severity is driven by **blast radius** (how many tenants / data subjects) and
**what was exposed** (credentials and signing material are worse than metadata).

| SEV | Definition | Concrete WeldForge examples | Target ack | Target containment |
|-----|------------|------------------------------|------------|--------------------|
| **SEV1** | Platform-wide credential/crypto compromise, or cross-tenant data exposure affecting many tenants. Existential. | • `app.jwt.secret` (the shared HMAC, GCP `wf-jwt-secret`) leaked — every consumer (Safe Space, Krusty, Commons) trusts forged tokens.<br>• A tenant's OIDC/SAML **signing key** or `app.crypto.secret` (`wf-app-crypto-secret`) leaked.<br>• Cross-tenant isolation breach: tenant A reading tenant B's users/credentials at scale.<br>• Cloud SQL `weldforge-db` exfiltrated.<br>• Admin/super-admin account takeover. | **15 min** | **1 hour** |
| **SEV2** | Single-tenant compromise or serious exposure with a bounded blast radius. | • Single tenant-admin account takeover.<br>• One tenant's end-user accounts compromised (small set).<br>• Leak of one tenant's branding/config secrets (e.g. Twilio creds, SAML SP secrets).<br>• Confirmed exploit of an auth endpoint affecting one tenant. | **1 hour** | **4 hours** |
| **SEV3** | Security-relevant but contained / low-impact, or a credible-but-unconfirmed report. | • Credential-stuffing / brute-force campaign in progress (lockout + rate limit holding).<br>• A dependency CVE that is reachable but not yet exploited.<br>• A single end-user account takeover via phished credentials.<br>• Suspicious admin action under review. | **4 hours** | **1 business day** |
| **SEV4** | Hygiene / low-risk / informational. Track and fix, no emergency. | • Low-severity dependency CVE, not reachable.<br>• Audit findings of the "missing header / info disclosure" class (cf. `SECURITY_AUDIT_2026-04-15.md` LOW/INFO).<br>• Single failed-login anomaly that resolves on inspection. | **2 business days** | Next sprint |

**Public commitment to honour (README):** *"We acknowledge within 48 hours and
publish a CVE with credit where warranted."* For externally-reported issues to
`security@weldforge.org`, the 48h acknowledgement is a hard SLA regardless of
internal severity. The CVE is published once a fix ships (see the public
template in §7).

**Escalation rule:** any SEV3 that turns out to involve the shared HMAC, a
signing key, or more than one tenant **immediately becomes SEV1**. Re-declare.

---

## 2. Roles

WeldForge is operated by a small team, so in practice **one person wears
several hats**. The roles still exist as a checklist of responsibilities that
must be covered — not as a headcount.

| Role | Owns | Small-team reality |
|------|------|--------------------|
| **Incident Commander (IC)** | Declares severity, runs the incident, makes the contain/eradicate calls, owns the timeline log. | The on-call person. Default IC: **`TODO: primary on-call name/contact`**. |
| **Comms Lead** | Internal updates, affected-tenant notices, the POPIA filings, the public/CVE statement. | Usually the IC on a solo shift. Pull in a second person before sending external comms if at all possible — a second reader catches over/under-claiming. |
| **Technical Lead / Operator** | Hands on the keyboard: `kubectl`, `gcloud`, Cloud SQL, key rotation, deploys. | The IC on a solo shift. |
| **Scribe** | Keeps the timeline if the IC is heads-down on the keyboard. | Optional; merge into IC if no one is free. |
| **Legal / DPA owner** | POPIA Information Officer duties, reviews breach notices, checks tenant-DPA timelines. | **`TODO: WeldForge POPIA Information Officer name + contact`** (POPIA requires a registered Information Officer — usually the business owner). |

If you are alone: be IC, preserve evidence, contain, and **call in a second
person before any irreversible step** (HMAC rotation, mass token invalidation,
tenant data deletion) — not for permission, but for a second set of eyes.

---

## 3. Detection sources

Where signals come from, and how to read them in a hurry.

- **Audit log (`audit_events` table / `AuditService`).** The primary forensic
  record. Append-only; each write runs `REQUIRES_NEW` so it survives a rolled-
  back business transaction. Search via the admin portal or
  `AuditService.search(tenantId, eventType, actorEmail, since, until, …)`.
  High-signal event types (`AuditEventTypes`):
  - `auth.login.failed` spikes → brute-force / credential stuffing.
  - `auth.login.success` from unusual IP/UA for an admin → takeover.
  - `admin.cross_tenant.access` → cross-tenant admin selector use; verify it
    was a legitimate super-admin.
  - `service_account.rotate` / `service_account.create`, `pki.cert.issue`,
    `pki.ca.create`, `saml_idp.assertion.issued`, `oidc.client.dynamic_register`,
    `federation.rules.update` → privileged actions; unexpected ones are red flags.
  - `mfa.factor.remove` / `mfa.admin_reset` → possible MFA stripping during a
    takeover.
  - The audit row carries `ipAddress` (from `X-Forwarded-For`/`X-Real-IP`) and
    `userAgent` — use them to scope blast radius and build IP blocklists.
- **Prometheus / metrics (Actuator).** Watch HTTP 4xx/5xx rates, login
  failure counters, latency. `/actuator/**` is **not** publicly routed — query
  it from inside the cluster:
  `kubectl -n sso exec deploy/sso-api -c sso-api -- curl -s http://localhost:8076/actuator/health`
  (and `/actuator/prometheus`, `/actuator/circuitbreakers`).
  > **Known gap:** there is no `sso.mail.send` failure counter yet, so silent
  > email-delivery breakage will not page you. Treat SendGrid as a manual check
  > (below) until that metric + alert exist.
- **SendGrid activity feed.** Confirms whether security emails (password reset,
  email verification, identity-proofing challenges) are actually delivering.
  A flood of password-reset sends = possible account-recovery abuse; a sudden
  delivery failure = account recovery is silently broken (the API still returns
  success to the caller). API key: GCP Secret Manager `wf-sendgrid-api-key`.
- **GCP / GKE logs.** Cloud Logging for the `sso` namespace, GKE audit logs
  (who touched the cluster), Cloud SQL logs (connection sources, query errors),
  Secret Manager access logs (who read `wf-jwt-secret` / `wf-app-crypto-secret`
  / `wf-db-password` — critical for a suspected-key-leak investigation),
  Artifact Registry + GHA deploy logs (unexpected image pushes / deploys).
- **External report.** `security@weldforge.org`. Triage within the 48h SLA.
- **Consumer reports.** Safe Space / Krusty / Commons noticing forged-token or
  auth anomalies is itself a SEV1 signal for the shared HMAC.

---

## 4. Response playbooks

Each playbook is **Detect → Contain → Eradicate → Recover → Post-incident**.
Always do §6 (evidence) before destructive contain/eradicate steps.

### 4.1 Suspected signing-key / `app.jwt.secret` (shared HMAC) compromise — **SEV1**

This is the worst case: the HMAC in `wf-jwt-secret` is mirrored to every
consumer's `WELDFORGE_JWT_SECRET`. A leak means anyone can forge tokens that
Safe Space, Krusty, and Commons will accept. A leaked per-tenant OIDC/SAML
**signing key** is the same class of problem scoped to one tenant.

> **The coordinated rotation procedure lives in `docs/runbooks/key-rotation.md`
> and is the source of truth for the exact steps.** This playbook is the
> incident wrapper around it.
> _(If `key-rotation.md` does not yet exist in the tree, that runbook is a
> **TODO** to author — it must cover: minting a new secret, the consumer-by-
> consumer cut-over so all of them rotate in the same window, and the forced
> token-version bump described below. Do not improvise an HMAC rotation without
> it; a partial rotation locks tenants out of every consumer at once.)_

- **Detect.** Secret Manager access log shows an unexpected read of
  `wf-jwt-secret` / `wf-app-crypto-secret`; a consumer reports tokens it didn't
  issue validating; the secret appears in a leaked artifact (cf. the
  `SECURITY_AUDIT_2026-04-15.md` CRITICAL-1 pattern — a credential baked into a
  shipped bundle).
- **Contain.**
  1. Snapshot evidence (§6) first.
  2. Treat **all** outstanding tokens as untrusted. Force a global token
     invalidation by bumping the per-user **token version** (`User.tokenVersion`
     → `CLAIM_TOKEN_VERSION`, checked by `JwtAuthenticationFilter`):
     incrementing it for affected users (or all users in the blast radius)
     makes every previously-issued access token fail validation, forcing
     re-authentication. The exact bump command is in `key-rotation.md`.
  3. Rotate the shared HMAC in GCP Secret Manager (`wf-jwt-secret`) **and** the
     consumers' `WELDFORGE_JWT_SECRET` in the **same maintenance window** —
     because they all verify with the same key, a half-rotation breaks SSO for
     all three consumers simultaneously. Coordinate via the consumer-owner
     contacts: **`TODO: Safe Space / Krusty / Commons on-call contacts`**.
- **Eradicate.** Find and close the leak path (leaked bundle, exposed env,
  over-broad IAM on Secret Manager, compromised laptop/CI). Remove the
  credential from wherever it leaked; do not just rotate around it.
- **Recover.** Redeploy `sso-api` with the new secret; confirm each consumer is
  on the new key; verify a fresh login on `sso.weldforge.org` works and that
  consumers accept the new tokens. Spot-check a live tenant's OIDC discovery
  (use the `leap` tenant:
  `https://sso.weldforge.org/t/leap/.well-known/openid-configuration` → 200).
- **Post-incident.** Tighten Secret Manager IAM + access alerting; review why
  the leak was possible; this is almost certainly a POPIA-notifiable event
  (credentials of multiple tenants put at risk) → §5.

### 4.2 Tenant account takeover — **SEV2** (admin) / **SEV3** (single end-user)

- **Detect.** `auth.login.success` from anomalous IP/UA; `mfa.factor.remove`
  or `mfa.admin_reset` followed by config changes; affected user reports it; a
  burst of privileged audit events under one actor.
- **Contain.**
  1. Lock the account and **bump that user's `tokenVersion`** to kill all their
     live sessions/tokens immediately.
  2. Force a password reset; if MFA was removed, require re-enrolment.
  3. If an admin/super-admin was taken over, treat as SEV1-adjacent: review
     everything they touched (cross-tenant access, key/cert operations, service
     accounts) and rotate any secret they could have read.
- **Eradicate.** Determine entry vector (phishing, reused password, stuffing,
  session theft). Revoke any tokens, API keys, or service accounts the attacker
  created (`service_account.*`, `oidc.client.dynamic_register` audit events).
- **Recover.** Confirm legitimate owner regains access with MFA; monitor that
  account's audit trail for 48–72h.
- **Post-incident.** If the takeover exposed other users' personal data,
  POPIA applies (§5). Notify the affected tenant (§7) regardless.

### 4.3 Cross-tenant isolation breach — **SEV1**

Tenant scoping is enforced at the DAO layer ("every query tenant-scoped from
the DB up"). A breach means that boundary failed.

- **Detect.** `admin.cross_tenant.access` by a non-super-admin; a tenant
  reports seeing another tenant's data; an audit/test finding (cf. audit
  Phase-2 "multi-tenant isolation" item, deferred in `SECURITY_AUDIT_2026-04-15.md`).
- **Contain.** Snapshot evidence (§6). If a specific endpoint leaks across
  tenants, disable/route-block it at nginx or feature-flag it off. If a
  compromised admin is the vector, lock + token-bump them (§4.2).
- **Eradicate.** Fix the missing tenant predicate in the offending query/DAO;
  add a regression test (the BDD suite covers isolation — add a scenario).
- **Recover.** Deploy the fix; re-run isolation checks against the live binary;
  quantify exactly which tenant pairs and records were exposed (you need this
  precise scope for POPIA + tenant notices).
- **Post-incident.** Multi-tenant data exposure is a textbook POPIA-notifiable
  compromise (§5). Each affected tenant gets a tailored notice (§7).

### 4.4 Credential-stuffing / brute-force campaign — **SEV3** (escalate if it lands)

- **Detect.** `auth.login.failed` spike in the audit log; lockout events
  (`mfa.challenge.blocked`); 4xx spike in metrics; concentration on one tenant
  or one source IP range (use the audit `ipAddress` field).
- **Contain.**
  1. Confirm **rate limiting is ON** (defaults: login 10/15min, register
     5/60min) and **lockout is engaging** (5/15min). Do **not** disable rate
     limiting during an attack (`APP_RATE_LIMIT_ENABLED` must stay `true`).
  2. Block the abusive source IPs/CIDRs at the GKE Ingress / nginx layer.
  3. If a known credential dump is being replayed, force password resets for
     any matched accounts and bump their `tokenVersion`.
- **Eradicate.** Identify any accounts that were actually compromised (a
  `auth.login.success` following the failed burst from the same IP) and treat
  each as a takeover (§4.2).
- **Recover.** Keep IP blocks until the campaign subsides; watch the
  failure-rate metric return to baseline.
- **Post-incident.** If no account was breached, this is contained (no POPIA
  trigger). If any account was compromised, escalate to §4.2 and assess §5.

### 4.5 Dependency CVE / supply-chain — **SEV varies by reachability**

- **Detect.** Dependabot/SCA alert, `mvn dependency:list` review, upstream
  advisory (e.g. the Spring Security CVE-2024-38821 noted in the April audit),
  or a suspicious Artifact Registry image / unexpected GHA deploy.
- **Contain.** Assess reachability — is the vulnerable code path actually
  exercised? If actively exploitable, treat per the resulting impact (a
  reachable auth-bypass in Spring Security = SEV1). If a build/CI compromise is
  suspected, freeze deploys, rotate the WIF-bound deployer's trust if needed,
  and verify the running image digest matches a known-good build.
- **Eradicate.** Bump the dependency (e.g. Spring Boot to the latest patch),
  run the full test suite (`./mvnw -B -ntp verify -Dtests.integration=true`),
  and rebuild from a clean, verified source tree.
- **Recover.** Deploy via the normal `deploy-gcp.yml` path; confirm the new
  image digest is live; re-scan.
- **Post-incident.** If the CVE was exploited against tenant data, §5 applies.
  Otherwise record it and tighten SCA gating.

---

## 5. POPIA breach-notification obligations (South Africa)

WeldForge is hosted in South Africa and is POPIA-native by design. **POPIA
§22 legally requires** that where there are reasonable grounds to believe
personal information has been accessed or acquired by an unauthorised person,
the responsible party must notify **(a) the Information Regulator and (b) the
affected data subjects**, "as soon as reasonably possible after the discovery
of the compromise."

- **When the clock starts.** At *discovery / reasonable belief* of a
  compromise — not when remediation finishes. Containment may be delayed only
  if a law-enforcement body or the Regulator says delay is needed to protect
  the investigation.
- **Who notifies.** The **POPIA Information Officer** (Legal/DPA owner role,
  §2 — **`TODO`**) files with the Regulator and coordinates data-subject
  notices. The Comms Lead drafts; the Information Officer signs off.
- **Information Regulator contact path.** File via the Regulator's prescribed
  channel. **`TODO: confirm current Information Regulator security-compromise
  notification email / portal`** (historically `inforeg@justice.gov.za` /
  `complaints.IR@justice.gov.za` and the Regulator's online eServices portal —
  verify the live address before filing; do not rely on a cached one).
- **What the notice must contain (POPIA §22(5)).** Enough for a data subject to
  protect themselves:
  - a description of the possible consequences of the compromise;
  - a description of the measures WeldForge took / intends to take to address
    it;
  - a recommendation of what the data subject can do to mitigate harm (e.g.
    reset passwords, re-enrol MFA, watch for phishing);
  - the identity of the unauthorised person who may have accessed the data, if
    known.
  Data-subject notice must be in writing and communicated directly (email,
  posted to the account, or — if direct contact isn't feasible — a public
  notice / website + media), in one of the prescribed manners.
- **How WeldForge's multi-tenancy maps to this.** WeldForge is typically a
  **processor/operator** acting for each tenant (the responsible
  party/controller for their end users). In practice:
  1. WeldForge notifies the **affected tenant(s)** immediately (§7 template) so
     *they* can meet their own data-subject obligations; **and**
  2. for WeldForge's own data subjects, or where the DPA puts the notification
     duty on WeldForge, WeldForge notifies the Regulator and subjects directly.
  Confirm the split per tenant against the signed DPA.
- **Tenant DPAs may impose tighter contractual timelines** than "as soon as
  reasonably possible" — e.g. *notify the tenant within X hours of discovery*.
  Check each affected tenant's DPA: **`TODO: where signed tenant DPAs are
  filed`**. The contractual clock can be shorter than the statutory one — meet
  the shorter of the two.
- **GDPR (EU data subjects).** If **any** affected data subject is in the EU/EEA
  (a tenant or its end users), GDPR Art. 33 applies: notify the relevant
  supervisory authority **within 72 hours** of becoming aware, and affected
  data subjects "without undue delay" where there is high risk. Determine EU
  exposure early — the 72h clock is much tighter than POPIA's wording.

---

## 6. Evidence preservation (do this BEFORE remediating)

Remediation overwrites the crime scene. Capture first.

1. **Snapshot Cloud SQL** so the DB state at incident time is frozen:
   ```bash
   gcloud sql backups create \
       --instance=weldforge-db --project=weldforge \
       --description="incident-$(date +%Y%m%dT%H%M%SZ)"
   ```
   (Or an on-demand export to a locked-down GCS bucket.)
2. **Preserve audit logs.** The `audit_events` rows are your forensic spine —
   they are append-only, but a DB restore/rotation could disturb them. Export
   the relevant window to secure storage before any data fix:
   capture by tenant + time range via `AuditService.search(...)` /
   admin portal export, and keep the raw export hash.
3. **Capture GKE pod logs** before pods are rolled/restarted (logs are
   ephemeral on pod recreation):
   ```bash
   kubectl -n sso logs deploy/sso-api -c sso-api --since=24h \
       > incident-sso-api-$(date +%Y%m%dT%H%M%SZ).log
   ```
   Repeat for the frontend pod if relevant.
4. **Pull GCP logs** for the window: Cloud Logging (`sso` namespace), Cloud SQL
   connection logs, **Secret Manager access logs** (essential for §4.1), GKE
   audit logs, Artifact Registry + GHA deploy history. Export to a bucket you
   control.
5. **Record running image digests** (`kubectl -n sso get pods -o
   jsonpath=...image...`) so you can prove what code was live.
6. **Note all timestamps in UTC** and keep them in the timeline log.
7. **Chain of custody.** Store exports in a restricted location, record who
   captured what and when, and don't edit the originals — work on copies.

---

## 7. Communication templates (stubs)

Keep them short, factual, and free of speculation. Fill the brackets.

### 7.1 Internal (kick-off / status)
```
[SEV?] WeldForge incident — <one-line summary>
Status: <investigating | contained | eradicated | recovered>
Started (UTC): <ts>   IC: <name>   Comms: <name>
What we know: <facts only>
Blast radius: <tenants / users / consumers affected, or "scoping">
Current actions: <bullet list>
Next update by (UTC): <ts>
```

### 7.2 Affected-tenant notice
```
Subject: Security incident affecting your WeldForge tenant <slug>

Dear <tenant contact>,

On <date/time UTC> we detected <plain-language description>. Your tenant
<slug> is affected. Based on our investigation so far, the following data
may have been involved: <data categories>.

What we have done: <containment + remediation, factual>.
What we recommend you and your users do: <reset passwords / re-enrol MFA /
watch for phishing, as applicable>.

Under POPIA you may have your own obligations to notify your end users and
the Information Regulator; we are providing this notice promptly to support
that. We will follow up by <date> with a fuller report.

WeldForge Security — security@weldforge.org
```

### 7.3 Public statement / CVE (honours the README commitment)
```
WeldForge Security Advisory <ID> — <title>

Acknowledged: <date> (within our 48h SLA)
Severity: <CVSS / SEVn>
Affected: <versions / components>
Summary: <what, in one paragraph, no exploit detail until patched>
Impact: <who/what was at risk>
Fix: <version / deploy / mitigation>
Credit: <reporter, with consent>
Timeline: reported <d> · acknowledged <d> · fixed <d> · disclosed <d>
```
Publish the CVE once a fix is deployed; coordinate disclosure with the reporter.

---

## 8. Post-incident review checklist

Run within ~5 business days, blameless, while memory is fresh.

- [ ] **Timeline** reconstructed from the log: detection → containment →
      eradication → recovery, with UTC timestamps and who did what.
- [ ] **Root cause** identified (technical *and* contributing process gaps),
      not just the proximate trigger.
- [ ] **Detection assessment:** did our sources (§3) actually catch it, or did
      we find out from a tenant/consumer/external report? What would have caught
      it sooner? (e.g. the missing `sso.mail.send` alert.)
- [ ] **Severity check:** was the initial classification right? Did we
      escalate correctly?
- [ ] **Blast radius finalised:** exact tenants, users, data categories,
      consumers affected — confirmed, not estimated.
- [ ] **Notification audit:** were POPIA / GDPR / DPA obligations met on time?
      Records of every filing and tenant notice attached.
- [ ] **Evidence archived** with chain of custody; snapshots/exports retained
      per policy.
- [ ] **Secrets hygiene:** every credential the attacker could have touched is
      rotated and confirmed rotated across consumers.
- [ ] **Action items** with owners and due dates (preventive fixes, new
      alerts, runbook gaps — e.g. authoring/updating `key-rotation.md`).
- [ ] **Runbook updated:** fold lessons learned back into *this* document and
      `CLAUDE.md` project memory.

---

## 9. Quick reference

| Thing | Value |
|-------|-------|
| Public URL | `https://sso.weldforge.org` (admin: `admin.weldforge.org`) |
| GCP project / region | `weldforge` / `africa-south1` |
| GKE cluster / namespace | `weldforge-gke` / `sso` |
| Cluster context | `gke_weldforge_africa-south1_weldforge-gke` (pass explicitly) |
| Cloud SQL | instance `weldforge-db`, db `weldforge` (Postgres) |
| Shared HMAC secret | GCP Secret Manager `wf-jwt-secret` (mirrored to consumers' `WELDFORGE_JWT_SECRET`) |
| Crypto secret | `wf-app-crypto-secret`; DB password `wf-db-password`; SendGrid `wf-sendgrid-api-key` |
| Internal health check | `kubectl -n sso exec deploy/sso-api -c sso-api -- curl -s http://localhost:8076/actuator/health` |
| Live "is it up" tenant | `leap` — `https://sso.weldforge.org/t/leap/.well-known/openid-configuration` |
| Token kill-switch | bump `User.tokenVersion` (invalidates all that user's access tokens) |
| External token consumers | Safe Space, Krusty, Commons (share the platform HMAC) |
| Security inbox | `security@weldforge.org` (48h ack SLA) |
| Coordinated key rotation | `docs/runbooks/key-rotation.md` *(author if missing)* |
| Security baseline | `SECURITY_AUDIT_2026-04-15.md` |
| Primary on-call / IC | **`TODO`** |
| POPIA Information Officer | **`TODO`** |
| Information Regulator notify path | **`TODO` (verify before filing)** |
| Consumer on-call contacts | **`TODO`** |
| Tenant DPA repository | **`TODO`** |
