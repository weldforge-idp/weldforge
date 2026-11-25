# Provider framework — one descriptor-driven way to configure every tenant provider

*Status: proposal, not started. Written 2026-11-25 against `main` @ `3b94062`.
Origin: a hand-over from the Mercator session
(`C:\dev\CWVermaak\Tech\mercator\docs\WELDFORGE-HANDOVER.md`), on Wimpie's
instruction to configure WeldForge's providers the same way Mercator configures
payments. Mercator's pattern was itself taken from WeldForge's provider code and
improved; this proposal takes the improvements back. Decision taken 2026-11-25:
**spec now, build after Sprints 1–7 are deployed.** Planned as Sprint 9; not to
start until the deploy gate clears.*

---

## 1. Why

WeldForge has five kinds of per-tenant provider, each built independently:

| Kind | Entity | Table (migration) | Types | Secret | Test-conn today |
|---|---|---|---|---|---|
| Social sign-in | `TenantSocialProvider` | `V4` | `SocialProviderType`: Google, Microsoft, GitHub, Facebook, Apple, LinkedIn, Twitter | client secret, AES-GCM (`EncryptedStringConverter`) | no |
| SAML upstream | `TenantSamlProvider` | `V6` | one generic | none (entity id, SSO/SLO URLs, signing cert) | no |
| LDAP | `TenantLdapProvider` | `V26` | generic | bind password, encrypted | **yes** (`/test-connection`) |
| CRM push | `TenantCrmProvider` | `V28` | `CrmProviderType`: Salesforce, HubSpot, Dynamics, Pipedrive | API token, encrypted | **yes** (`/test-connection`) |
| SMS | `TenantTwilioProvider` | `V18` | Twilio only | auth token, encrypted | no |

Adding a provider type today costs: a new enum value, often a new entity or
columns, a new DTO, a new controller section, a new hand-written form in the
admin portal, and new per-type special cases (Microsoft's directory field,
Google's `hd`, `asserted_amr`). Five code sites per change, drifting apart over
time (two of five already grew a `test-connection` endpoint; three did not).

**What is already right and stays:** one row per tenant and provider type,
secrets encrypted at rest and never echoed on read, an enabled switch, one client
interface with a fake for tests, endpoint defaults in code so a tenant supplies
only its own keys. The framework generalises these; it does not replace them.

## 2. The six parts

### P1 — one framework, a descriptor per type

Each provider type declares itself in code as a `ProviderDescriptor`:

```
ProviderDescriptor {
  kind:         social-sign-in | saml | ldap | crm | sms | email …
  type:         "google"                       // stable id within the kind
  name, summary, docsUrl
  capabilities: { kind-specific flags: social.assertsAmr, social.hostedDomain,
                  social.pkce; sms.countries, sms.alphanumericSender;
                  crm.upsert, crm.dedupeByEmail }
  fields: [ { key, label, kind: text|select|number|boolean|textarea|file,
              secret, required, pattern, options, help, showWhen } ]
  verify:       what "Test connection" does for this type
}
```

The admin portal draws every provider form from `GET /api/admin/provider-types?kind=`.
Adding a type becomes backend code in `weldforge-auth` only. Per-type special
cases become described fields: Microsoft's directory id is a `text` field with
`showWhen type == microsoft`; Google's `hd` and `asserted_amr` are fields with
help text, not screen code.

**Acceptance:** adding a new social type (e.g. a generic OIDC provider — see Q2
below, WeldForge has none today) changes **no** portal code; every existing form
renders from descriptors with the same fields and validation it has now.

### P2 — secrets write-only, with hints, verified before use

Secrets stay write-only. Added:
- the screen shows **"saved, ending in 4f2a"** and a **Replace** button, never an
  empty field that reads as unset;
- **Test connection** runs the descriptor's `verify` before a provider can be
  **enabled**, and shows what issuer/account was reached and when;
- a provider whose credentials are **refused in use** is marked **broken**, the
  tenant admin is told, and sign-in stops offering it rather than failing at the
  provider.

LDAP and CRM already have a `test-connection` endpoint — generalise theirs into
the descriptor `verify` contract rather than inventing a new one.

**Acceptance:** a provider cannot be enabled until verify passes; a refused secret
marks it broken and hides its sign-in button; no secret ever appears in a
response, log or audit value — only hints.

### P3 — two scopes: platform-wide and per-tenant

- **platform-wide** (operator) providers any tenant may switch on without its own
  keys — e.g. WeldForge's own Twilio account for SMS one-time codes, or a shared
  email transport;
- **tenant** providers with the tenant's own keys (as today).

A tenant sees both, switches each on/off for itself, and orders them where order
matters (the sign-in page buttons).

**Acceptance:** a tenant can use the platform SMS account with no Twilio keys of
its own, and can see neither the platform's secrets nor another tenant's
providers.

### P4 — rules: which provider for which case

Ordered rules, first match wins, falling back to the tenant's default. Same
mechanism, three decisions:

| Decision | Conditions | Action |
|---|---|---|
| Which **SMS provider** sends a one-time code | recipient country (from the number), tenant, time, a share of traffic | provider A, else B |
| Which **sign-in options** the page shows | relying party (client), email domain typed (home-realm discovery), user country | show these social/SAML providers in this order; or skip to one SAML provider for `@contoso.com` |
| Which **CRM** gets a new user | the client signed up through, a role, a custom attribute | CRM A, or none |

Rules are data, evaluated **server-side**, ordered, with a **"Try it"** preview in
the portal (enter a number or an email+client, see which rule wins) and a warning
for a rule no case can reach.

**Acceptance:** a Namibian number can route to a different SMS provider than a
South African one; an email at a federated domain goes straight to its SAML
provider; the preview matches live behaviour.

### P5 — failover

When the chosen provider cannot do the job, the next offered one is tried before
the user sees an error, and the event records which was skipped and why.

**Acceptance:** with two SMS providers, the first failing still delivers through
the second, and the admin sees both attempts.

### P6 — every change audited, secrets as hints

Add, test, replace-secret (hint only), enable, disable, reorder and rule changes
are written to the audit trail with who and when; personal or secret values
appear only as `"[personal]"` or a hint. Reuses the existing audit infrastructure.

**Acceptance:** an audit export shows a tenant's full provider-config history with
no secret in it.

## 3. Explicitly not copied from Mercator

- **Holding money or payment keys** — payment keys stay in Mercator's payment
  service, never in WeldForge (Mercator D23). A breach of the identity service
  must not expose merchants' money. WeldForge grows no payment provider kind.
- **Payment-specific parts** — card/EFT methods, saved-card charges, the
  shop/company model. P3's platform-vs-tenant is WeldForge's own shape of the
  same split.

## 4. Answers to the hand-over's five questions

**Q1 — one `tenant_provider(kind, type, settings jsonb, sealed_secrets)` table, or
keep the existing tables under a common descriptor layer?**
**Recommendation: keep the five existing tables; add the descriptor layer above
them.** The descriptor maps its `fields` to each entity's columns through a
per-kind adapter. Reasons: (a) the risk rule for this estate is "a new global
constraint/large reshape must apply cleanly against live production data" — a
big-bang move to one jsonb table migrates five populated production tables with
encrypted columns and zero functional gain on day one; (b) `EncryptedStringConverter`
already gives per-column sealing, so `sealed_secrets` buys nothing; (c) typed
columns keep Flyway/Hibernate validation honest. A shared table can come later
per-kind if a kind genuinely needs it; the descriptor layer makes the storage
choice invisible to the portal either way. **This is the lower-risk path and the
one the suggested order already allows.**

**Q2 — is home-realm discovery already partly there, and should rules replace or
extend it?**
Partly, but for a different purpose. `EmailDomainPolicy` (+ `Tenant.allowedEmailDomains`)
exists and is used for **authorization** — `permits(...)` gates *which emails may
sign in* through a social provider (`CustomOAuth2UserService`). It is **not** used
for **routing** — choosing which provider to *show*. So P4's home-realm discovery
is net-new and should **extend** `EmailDomainPolicy`'s primitives (`domainOf`,
`matches`), not replace them. Keep authorization and routing separate: a domain
rule that routes `@contoso.com` to a SAML provider must not silently widen who is
allowed in.

**Q3 — platform-wide SMS: which account, whose cost, how is a tenant's use
limited? → NEEDS WIMPIE'S DECISION (operator/cost).** Recommendation to confirm:
WeldForge's own Twilio account funds it; default **off**, opt-in per tenant; a
per-tenant monthly quota plus the existing per-IP/-tenant rate limiting; usage
metered on the existing Micrometer counters tagged by tenant so cost is
attributable. Platform SMS is the one P3 case that spends real money, so it does
not ship until the quota + cost answer is set.

**Q4 — do relying parties need any of this through the API, or admin-portal only?**
Partly already public. `GET /api/auth/tenants/{slug}/social-providers` and
`/saml-providers` already return a tenant's sign-in options **unauthenticated**
(the `/api/auth/*` exemption in `AppAuthorizationFilter`), and the sign-in page
reads them. So P4's "which sign-in options to show" must **feed those existing
public endpoints** — the rule output replaces today's static list. Keep that
public read contract stable (additive only). Rules, secrets, verify results and
audit stay admin-portal only. No new public surface for CRM/SMS.

**Q5 — where does this sit against the current sprint, and does it need Wimpie's
word?** Yes, and it has it (2026-11-25): **spec now, build after deploy.** Sprint 8
is paused at the owner deploy gate; this is planned as **Sprint 9** and starts
only once Sprints 1–7 are live and validated.

## 5. Sprint 9 plan (build order, after deploy)

Each item is a PR off `main`, backend gated by `./mvnw -B -ntp verify
-Dtests.integration=true`, portal by CI `ng build`. New columns/tables follow the
live-data rule in Q1. Proboulos epic + stories created under project **WF**
(see §6).

1. **P1+P2 for social sign-in first** (most special cases, best exemplar):
   `ProviderDescriptor` + registry, `GET /provider-types`, portal renders the
   social form from descriptors, Microsoft/Google/`asserted_amr` become fields,
   `verify` + "saved, ending in …" + Replace + broken-state. Acceptance: a generic
   OIDC social type added with no portal change.
2. **P6 alongside P1** — audit hooks on add/test/replace/enable/disable/reorder.
   Small once the framework exists.
3. **CRM, SMS, SAML, LDAP onto the framework**, one PR each, each keeping its
   table (Q1). Fold the existing LDAP/CRM `test-connection` into `verify`.
4. **P3 platform-wide providers, with SMS** — *gated on Q3's cost decision.*
5. **P4 rules + "Try it" preview**, then **P5 failover** — SMS first (country
   routing + failover), then sign-in options (home-realm discovery, extending
   `EmailDomainPolicy`), then CRM.

Risks: P4/P5 touch the live sign-in path — feature-flag per tenant, default to
today's behaviour. P3 spends money — no platform SMS until Q3 is answered. The
descriptor registry must stay backward-compatible with the public
`social-providers`/`saml-providers` contracts (Q4).

## 6. Proboulos backlog

Created under project **WF** on 2026-11-25: epic **WF-36**, stories **WF-37…WF-42**
mapping to P1…P6, and **WF-43** the platform-SMS cost/quota decision for Wimpie
(P3 / WF-39 is gated on it). All seven sit in **Sprint 9 — Provider framework**
(id 110), which is planned but **not started** — it begins only when Sprints 1–7
are deployed and staging is validated.

*Mercator depends on none of this; it is offered because Wimpie wants the two
products configured the same way. Peer confirmation that this spec matches
WeldForge's code was sent to the Mercator session on 2026-11-25.*
