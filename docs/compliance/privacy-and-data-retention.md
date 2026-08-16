# Privacy & Data-Retention Framework — WeldForge IAM

> **STATUS: WORKING DRAFT — NOT LEGAL ADVICE.**
> This document is an engineering-derived starting framework for WeldForge's
> POPIA compliance posture. It was assembled from the actual data model in the
> repository (JPA entities under `weldforge-auth/.../model/` and the Flyway
> migrations under `weldforge-auth/.../db/migration/`). **Every retention
> period, role assignment, and rights-handling flow below requires review and
> sign-off by a qualified South African privacy lawyer / the appointed
> Information Officer before it is published, contracted, or relied upon.**
> Items needing a business or legal decision are marked **`TODO`**.
>
> Scope: the `weldforge-auth` Spring Boot backend and its PostgreSQL database
> (Cloud SQL instance `weldforge-db`), hosted on GCP `africa-south1`
> (Johannesburg). Last reviewed against the schema at migration **V44**.

WeldForge markets itself as **"POPIA-native by design"** (`README.md`,
`LAUNCH.md`). This document is the substantiation of that claim. POPIA (the
Protection of Personal Information Act 4 of 2013) terminology is used
throughout: **Responsible Party** (controller), **Operator** (processor),
**Data Subject**, **Information Officer**, **Operator agreement**.

---

## 1. Roles — who is the Responsible Party?

WeldForge plays **two distinct roles depending on whose data is in question**.

### 1.1 WeldForge as Operator (processor)

For the **end-user personal data of tenant companies' users**, WeldForge is an
**Operator** processing on behalf of each tenant, which is the **Responsible
Party**. Each tenant company (e.g. `techmetropolis`, `leap`) decides why and
how its users' identity data is processed; WeldForge merely stores, secures and
serves it under the tenant's instruction.

- The tenant Responsible Party owes the POPIA duties (notification, data-subject
  rights, lawful basis) to its own users.
- WeldForge owes the **§19–21 security and Operator duties**: process only on
  the Responsible Party's authority/instruction, maintain security safeguards,
  and notify the Responsible Party of any compromise.
- This relationship **must** be papered by a written **Operator agreement /
  DPA** (POPIA §20–21 require a written contract). See §8 — **this does not yet
  exist** and is a pre-launch TODO.

### 1.2 WeldForge as Responsible Party (controller)

For WeldForge's **own direct-customer / billing data** — the people who buy a
WeldForge subscription, their contact details and payment records (the
`pending_orders`, `subscriptions`, `billing_transactions` tables) — **WeldForge
is itself the Responsible Party** and owes the full set of POPIA duties directly
to those customers.

### 1.3 The 8 POPIA conditions for lawful processing (high level)

Both roles are bound, for the data they control, by POPIA's 8 conditions:

| # | Condition | What it means for WeldForge |
|---|---|---|
| 1 | **Accountability** | A registered Information Officer is accountable for compliance (§4, §55). **TODO — not yet appointed/registered.** |
| 2 | **Processing limitation** | Lawful, minimal, with consent/justification; collect only what's needed. Audit the data inventory in §2 against this. |
| 3 | **Purpose specification** | Collect for a specific, defined purpose; don't retain longer than needed (drives the retention schedule, §4). |
| 4 | **Further processing limitation** | Don't reuse data for incompatible purposes (e.g. CRM provisioning push must stay within tenant's stated purpose). |
| 5 | **Information quality** | Keep data accurate/complete — supported by the self-service correction path and SCIM sync. |
| 6 | **Openness** | Maintain this documentation + a public privacy notice; record processing operations (§2 is the processing register). |
| 7 | **Security safeguards** | §19–21: technical + organisational measures. Partially evidenced below (encryption at rest, password/secret hashing, tenant isolation). |
| 8 | **Data subject participation** | Access, correction, deletion rights (§5, §23–25). See §5 — current technical capability is partial. |

---

## 2. Data inventory / records of processing

The following personal-data categories are **actually persisted** today,
derived from the entities and migrations. (Configuration-only tables holding
no personal data — signing keys, OIDC/SAML client config, branding,
feature flags — are omitted; provider-credential tables are listed because they
hold tenant operator secrets.)

| Category | Table(s) / entity | Fields (actual) | Subject | Role | Purpose | Protection at rest |
|---|---|---|---|---|---|---|
| **Account identifiers** | `users` (`User`) | `username`, `email`, `name`, `cellPhoneNumber`, `imageUrl` (profile image URL), `provider`, `providerId` | Tenant end-user | Operator | Authentication, identity, SSO | DB-level (Cloud SQL encryption); not field-encrypted |
| **Credentials** | `users` | `password` (BCrypt hash, cost 12) | Tenant end-user | Operator | Authentication | One-way hash |
| **Account status / security state** | `users` | `emailVerified`, `cellPhoneVerified`, `active`, `failedLoginAttempts`, `lockedUntil`, `tokenVersion`, `superAdmin`, `adminRole`, `role` | Tenant end-user | Operator | Access control, anti-brute-force | DB-level |
| **MFA secrets** | `user_mfa_factors` (`MfaFactor`) | `totpSecretEnc` (TOTP seed, **AES-GCM encrypted** via `EncryptedStringConverter`), WebAuthn `credentialId`/`publicKeyCose`/`userHandle`/`aaguid`, SMS `phoneNumber`, `smsCodeHash` (BCrypt) | Tenant end-user | Operator | Second-factor auth | TOTP seed + SMS code hashed/encrypted |
| **Backup codes** | `BackupCode` | One-time recovery codes (hashed) | Tenant end-user | Operator | MFA recovery | Hashed |
| **Session / refresh tokens** | `refresh_tokens` (`RefreshToken`) | `tokenHash` (SHA-256, raw never stored), `ipAddress`, `userAgent`, `familyId`, issue/expiry/revoke timestamps | Tenant end-user | Operator | Session continuity, theft detection | Hashed; **IP + UA are personal data** |
| **Password-reset tokens** | `password_reset_tokens` | `tokenHash`, `expiresAt`, `returnTo` | Tenant end-user | Operator | Self-service password reset | Hashed |
| **Email-verification tokens** | `email_verification_tokens` | `tokenHash`, `expiresAt` | Tenant end-user | Operator | Email ownership proof | Hashed |
| **Audit / security log** | `audit_events` (`AuditEvent`) | `actorEmail`, `actorUserId`, `eventType`, `target*`, `outcome`, **`ipAddress`**, **`userAgent`**, free-form `metadata` (JSONB) | Tenant end-user, admins | Operator (tenant events) / Responsible Party (platform-wide super-admin events) | Security, forensics, compliance evidence | DB-level; **append-only, never deleted by the app** |
| **CRM provisioning ledger** | `crm_provisioning_log` | `externalId`, `matchKeyValue` (concatenated match keys, may contain email/name), per-user push status | Tenant end-user | Operator | Downstream CRM sync (PRD CRM-04) | DB-level |
| **OAuth authorization codes** | `OAuthAuthorizationCode` | short-lived codes bound to a user | Tenant end-user | Operator | OAuth2/OIDC flow | Short TTL |
| **Tenant operator contact** | `tenants` (`Tenant`) | `contactEmail`, `verifiedByUserId` | Tenant operator (a person) | Responsible Party (it's WeldForge's customer contact) | Onboarding, identity-proofing | DB-level |
| **Direct-customer order data** | `pending_orders` | `contactName`, `contactEmail`, `organisation`, `region`, `gatewayCustomerId` | WeldForge direct customer | **Responsible Party** | Sales / onboarding | DB-level |
| **Billing / subscription** | `subscriptions`, `billing_transactions` | `gatewayCustomerId`, `gatewaySubscriptionId`, `gatewayTransactionId`, `amount_cents`, `currency`, `card_country`, `bin` (card BIN, first 6–8 digits) | WeldForge direct customer | **Responsible Party** | Billing, accounting, tax | DB-level; **no full PAN stored** (PAN handled by gateway) |
| **Tenant Twilio credentials** | `tenant_twilio_providers` | `accountSid`, `authToken` (**AES-GCM encrypted**), `fromPhone` | Tenant (operator secret) | Operator | Per-tenant SMS sending | Auth token encrypted |
| **Payment-gateway credentials** | `payment_gateways` | `credentials_encrypted` (AES-GCM-256, key in k8s Secret `payment-master-key`) | WeldForge / tenant secret | Both | Payment routing | Encrypted |

**Notes on minimisation (condition 2):**
- IP address + user-agent are captured in **both** `audit_events` and
  `refresh_tokens`. Both are personal data under POPIA. **TODO:** confirm this
  duplication is justified and bounded by the retention schedule.
- `audit_events.metadata` is free-form JSONB — there is a risk of incidental
  personal data leaking into it. **TODO:** review what is written into
  `metadata` and ensure no excess personal data is captured.

---

## 3. Security safeguards (POPIA §19) — evidence

What the code already does (cite when answering due-diligence questionnaires):

- **Passwords**: BCrypt cost 12 (one-way).
- **MFA TOTP seeds & Twilio auth tokens**: AES-GCM encrypted at rest
  (`EncryptedStringConverter`); payment-gateway credentials AES-GCM-256.
- **Tokens** (refresh, password-reset, email-verify): only **hashes** stored;
  raw values never persisted.
- **Tenant isolation**: application-layer, enforced per-DAO via the
  `TenantAccessor` guard; every cross-tenant query is scoped by `tenant_id`.
- **Data residency**: Cloud SQL `weldforge-db` in `africa-south1`.
- **Transport**: TLS at the ingress (`https://sso.weldforge.org`).

**Gaps / TODO:**
- No application-level field encryption on `users.email` / `users.name` /
  `cellPhoneNumber` — relies on Cloud SQL disk encryption only. **TODO:**
  decide whether direct identifiers need field-level encryption.
- **TODO:** document the backup/restore retention of Cloud SQL automated
  backups — deleted data may persist in backups beyond the logical retention
  windows in §4.

---

## 4. Data-retention schedule (PROPOSED)

POPIA condition 3 (§14): personal data must not be kept longer than necessary
for the purpose, unless a law requires longer or the data subject consented.
**All periods below are proposals requiring sign-off.**

| Category | Proposed retention | Trigger / basis | Current technical behaviour |
|---|---|---|---|
| **Active user accounts** | Life of the account + **TODO** grace period after tenant offboarding | Tenant instruction (Operator) | Hard-deleted on demand via `AdminService.deleteUser` (tenant-admin only) |
| **Inactive / deactivated accounts** (`active = false`) | **TODO** — propose auto-purge after N months of inactivity | Minimisation | **No automatic purge today** — deactivated rows persist indefinitely |
| **Audit / security log** (`audit_events`) | **TODO** — propose 12 months online + archive (security logs are a legitimate-interest justification under §14) | Security, forensics | **Append-only; never deleted by the app.** No purge/rotation job exists |
| **Refresh tokens** | Until expiry/revocation; purge expired rows after **TODO** (e.g. 30 days post-expiry) | Session lifecycle | Revoked on logout, password change, tenant deletion; **no purge of expired rows** |
| **Password-reset tokens** | Delete after expiry (short TTL) | One-time use | Expire by `expiresAt`; **TODO** add cleanup job for spent/expired rows |
| **Email-verification tokens** | Delete after expiry | One-time use | Same as above — **no cleanup job** |
| **CRM provisioning log** | **TODO** — tie to user lifetime | Dedupe ledger | Persists; not auto-purged |
| **Deleted-tenant data** | On `deleteTenant`: refresh tokens revoked immediately; **TODO** define purge of the tenant's users/audit rows | Tenant offboarding | `TenantService.deleteTenant` (super-admin only) revokes all refresh tokens (`reason=tenant_deleted`) and writes a **slug-holdback** record. `audit_events.tenant_id` is **set NULL** (rows survive); user rows survive unless explicitly cascaded — **confirm actual cascade behaviour before quoting** |
| **Tenant slug holdback** | **90 days** (configurable `wf.public.slug-holdback-days`) | Anti identity-confusion | `tenant_slug_holdback` rows retained as audit trail even after the window; **expired rows not yet purged** (noted as a future cleanup job in `V37`) |
| **Pending orders** (unpaid) | Slug reservation 10 min TTL; order rows transition to `EXPIRED`/`CANCELLED`/`REFUNDED` | Sales funnel | `OrderExpiryScheduler` transitions states; rows are **not deleted** |
| **Billing transactions / subscriptions** | **Retain ≈ 5 years** to satisfy SARS / Companies Act record-keeping (a §14 "required by law" exception) — **TODO confirm exact statutory period with accountant/lawyer** | Tax / accounting / dispute | Retained indefinitely today |

**Cross-cutting TODO:** there is currently **no scheduled data-retention /
purge job** for any category except order-expiry. Implementing a retention
sweeper is the single biggest technical gap for POPIA condition 3.

---

## 5. Data-subject rights (POPIA §5, §23–25)

### 5.1 Routing of requests

- **Tenant end-users** (the majority): the **tenant company is the Responsible
  Party**, so a data-subject request (access / correction / deletion) must be
  **routed to and authorised by the tenant**, not actioned by WeldForge
  directly. WeldForge assists the tenant as Operator. The DPA (§8) must define
  this assistance SLA.
- **WeldForge direct customers** (billing contacts): WeldForge is the
  Responsible Party and handles the request directly via its Information Officer.

### 5.2 Current technical capability vs. the right

| Right (POPIA) | Current capability | Gap |
|---|---|---|
| **Access** (§23 — "what do you hold about me") | No self-service or admin **data-export endpoint** exists (grep for export/erasure across `weldforge-auth/src` returns no feature). Data can only be assembled by manual DB query. | **GAP — no export/portability endpoint.** **TODO:** build a per-user data-export. |
| **Correction** (§24) | Self-service profile edit + admin edit + SCIM PATCH from upstream IdPs. | Reasonable for `users` fields; no path to correct `audit_events` (correctly — it's append-only). |
| **Deletion / destruction** (§24/§25) | `AdminService.deleteUser` performs a **hard delete** of the user row (tenant-admin gated; cannot delete a super admin). | **Partial gap:** deletion is **not a coordinated erasure** — it does not demonstrably purge linked `audit_events` (intentionally retained, but needs a documented justification), `crm_provisioning_log`, or backups. There is **no anonymisation path** and **no self-service erasure endpoint**. **TODO:** define and build a documented erasure workflow that distinguishes "delete identifiers" from "retain audit trail under legitimate interest". |
| **Objection / restriction** | Account deactivation (`active=false`) halts sign-in. | No formal "restrict processing" flag. **TODO.** |

**TODO:** publish the request channel (a `privacy@weldforge.org` or the
Information Officer's address) and an internal runbook for fulfilling
access/erasure requests within the POPIA-reasonable timeframe.

---

## 6. Sub-processor register (TEMPLATE)

Sub-processors evident from the repository. **TODO:** confirm each contract,
DPA, and data-residency commitment; complete the "Data shared" and "Location"
columns from each vendor's current DPA.

| Sub-processor | Service | Data shared | Location / residency | POPIA §72 transfer concern |
|---|---|---|---|---|
| **Google Cloud (GCP)** | Compute (GKE `weldforge-gke`), Cloud SQL (`weldforge-db`), Secret Manager, Artifact Registry | All personal data at rest | `africa-south1` (Johannesburg) — **in-country** | None for primary storage; **TODO** confirm no GCP control-plane/support data leaves ZA |
| **SendGrid** (Twilio) | Transactional email (password reset, email verification, identity-proofing) | Recipient **email address**, name, the email body | **US** | **§72 cross-border transfer** — recipient email leaves ZA. Needs §72 justification (data-subject consent or adequate-protection contract) |
| **Twilio** | Per-tenant SMS / MFA OTP delivery | Recipient **E.164 phone number**, OTP message | **US** (Twilio global) | **§72 cross-border transfer.** Per-tenant — the tenant Responsible Party authorises it |
| **Stripe / Paddle / PayFast / Yoco / Peach** (payment gateways) | Checkout, subscription billing | Cardholder/customer data (handled gateway-side; WeldForge stores only `gatewayCustomerId`, BIN, card country) | Stripe/Paddle **US/EU**; **PayFast/Yoco/Peach ZA** | Choosing a **ZA gateway (PayFast/Yoco/Peach)** keeps billing data in-country; Stripe/Paddle = §72 transfer. **TODO:** state which gateway(s) are live for platform billing |

**TODO:** maintain this register as the authoritative sub-processor list,
publish it (POPIA openness + standard SaaS practice), and notify tenants of
changes per the DPA's sub-processor-change clause.

---

## 7. Cross-border transfers (POPIA §72)

- **Primary residency is in-country**: all persisted personal data lives in
  Cloud SQL in `africa-south1`. This is the substance of the "POPIA-native
  Cape Town residency" marketing claim (note: infra is Johannesburg
  `africa-south1`, not Cape Town — **TODO:** reconcile the "Cape Town" copy in
  `README.md`/`LAUNCH.md` with the actual GCP region, or clarify "Cape
  Town-built" vs "Johannesburg-hosted").
- **Transfers offshore happen via sub-processors**: SendGrid (email) and
  Twilio (SMS) are US-based, and Stripe/Paddle (if used) are US/EU. Sending a
  password-reset email or an SMS OTP **transfers a data subject's email/phone
  outside the Republic**, which POPIA §72 permits only on one of the listed
  grounds (e.g. the recipient consented, the transfer is necessary to perform a
  contract with the data subject, or the recipient is bound by adequate
  protection). **TODO:** record the §72 ground relied on for each transfer.
- **Minimisation lever**: choosing the ZA payment gateways (PayFast / Yoco /
  Peach) for platform billing avoids a §72 transfer for billing data entirely.

---

## 8. Operator agreement / Data Processing Agreement (DPA)

POPIA §20–21 require a **written contract** between Responsible Party and
Operator. `LAUNCH.md` lists "Legal pages resolve (TOS / Privacy / **DPA** at
least as placeholder stubs)" as a **pre-launch prerequisite** — i.e. **the DPA
does not yet exist.** This is a launch blocker for any tenant handling
real personal data.

A WeldForge tenant-facing Operator agreement / DPA should cover at minimum:

- **Roles**: tenant = Responsible Party, WeldForge = Operator (mirrors §1).
- **Subject matter & duration** of processing; categories of data subjects and
  personal data (reference §2).
- **Processing only on documented instruction** of the Responsible Party.
- **§19 security safeguards** (reference §3) and §21 Operator confidentiality.
- **Sub-processor** list, authorisation, and change-notification (reference §6).
- **Cross-border transfer** terms and §72 grounds (reference §7).
- **Data-subject-rights assistance** SLA (reference §5).
- **Breach notification** — Operator → Responsible Party timeline (see §9).
- **Return / deletion** of data on termination (reference §4 retention).
- **Audit / inspection** rights.

**TODO:** draft and have counsel review the DPA; publish a stub at
`/dpa` so links don't 404 at launch.

---

## 9. Breach / security-compromise notification (POPIA §22)

POPIA §22 requires notification to the **Information Regulator** and to
**affected data subjects** "as soon as reasonably possible" after a compromise
of personal data is discovered. As Operator, WeldForge must additionally notify
the affected **tenant Responsible Party** (who then notifies its data subjects).

- **Cross-reference:** the incident-response runbook at
  [`docs/runbooks/incident-response.md`](../runbooks/incident-response.md), which
  covers: detection → containment → assessment →
  §22 notification decision tree → Regulator + tenant + data-subject
  notification templates → post-incident review.
- The **append-only `audit_events` log** (with IP/user-agent) is the primary
  forensic source for breach assessment — a reason its retention (§4) matters.
- **TODO:** define the internal SLA for Operator→Responsible-Party notification
  in the DPA (§8), and the channel/role responsible.

---

## 10. Information Officer (POPIA §55–56)

POPIA requires every Responsible Party to have a designated **Information
Officer** (by default the head of the organisation), **registered with the
Information Regulator** before performing duties, optionally supported by
Deputy Information Officers.

- **TODO:** appoint and **register** the Information Officer with the
  Information Regulator (South Africa).
- **TODO:** publish the Information Officer's contact details and the
  data-subject request channel (e.g. `privacy@weldforge.org`).
- **TODO:** produce a **PAIA manual** (Promotion of Access to Information Act),
  which the Information Officer is also responsible for.

---

## 11. Outstanding-actions summary (engineering + legal)

**Legal / business (require sign-off):**
1. Appoint + register the Information Officer; publish contact + PAIA manual (§10).
2. Draft + counsel-review the tenant DPA / Operator agreement; ship a `/dpa` stub (§8).
3. Confirm all retention periods in §4 — especially the statutory billing-record period (§4).
4. Record the §72 transfer ground for SendGrid / Twilio / offshore gateways (§7).
5. Reconcile "Cape Town" marketing copy with the actual `africa-south1` region (§7).

**Engineering (capability gaps):**
6. Build a **per-user data-export** endpoint (access/portability) (§5).
7. Define + build a **documented erasure workflow** (identifiers vs retained audit trail; covers `crm_provisioning_log`, backups) (§5).
8. Implement a **scheduled retention/purge job** (audit log rotation, expired tokens, inactive accounts, expired slug-holdbacks) (§4).
9. Author `docs/runbooks/incident-response.md` with the §22 notification decision tree (§9).
10. Review what is written into `audit_events.metadata` to prevent excess personal data (§2).

---

*Working draft — pending legal review. Keep in sync with the schema: re-verify
against the latest Flyway migration version whenever the data model changes.*
