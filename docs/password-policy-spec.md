# Per-tenant password policy

**Status:** specified 2026-09-20, implementing.
**Decision origin:** 2026-09-15 — *"Password composition: relax toward 800-63B,
and make the rules per-tenant configurable in the management interface."*

The first half shipped: `app.security.password.*` defaults to length-12 with no
composition rules and breach screening on (NIST SP 800-63B §5.1.1.2). This
specifies the second half — letting an individual tenant set its own rules —
and the constraints that make that safe on a shared hosted platform.

---

## 1. The problem

`PasswordPolicyService.validate(String)` reads one immutable
`PasswordPolicyProperties` bean, so every tenant on a deployment gets identical
rules. That is wrong in both directions:

- A hosted tenant with a corporate standard ("12 chars, one digit, one symbol")
  cannot express it, and must either accept ours or not adopt.
- A deployment cannot relax for one tenant without relaxing for all.

Three call sites need it: registration (`AuthService.register`), self-service
change (`AuthService`), and reset (`PasswordResetService`). All three currently
call `validate(password)` with no tenant argument.

---

## 2. The invariant: tenants may only tighten

**A tenant override may make the policy stricter than the deployment baseline.
It may never make it weaker.**

This is the load-bearing decision, so the reasoning is recorded rather than
assumed:

- On `weldforge.org` the tenants are customers of one operator. A tenant that
  could lower `minLength` to 6 and disable breach screening would weaken
  accounts the operator is answerable for, and the blast radius of the
  resulting compromise is the operator's reputation, not only that tenant's.
- The people affected are the tenant's *end users*, who never chose the policy
  and cannot see it before registering.
- Self-hosters are not constrained by this: they own
  `app.security.password.*`, so lowering the baseline lowers the floor for
  their whole deployment. The rule limits tenants relative to their operator,
  which is exactly the boundary that matters.

Concretely, given baseline `B` and tenant override `T`, the effective policy is:

| field | effective value |
|---|---|
| `minLength` | `max(B, T)` |
| `maxLength` | `min(B, T)` — still hard-capped at 72, see §4 |
| `requireUppercase` / `Lowercase` / `Digit` / `Symbol` | `B OR T` |
| `breachCheckEnabled` | **`B` only — not tenant-configurable, see below** |

**Breach screening is deployment-wide.** It was in an earlier draft of this
table as `B OR T`; implementing it showed that to be wrong twice over. When
`app.security.password.breach-check.enabled=false` the injected
`BreachedPasswordScreen` is a **no-op stub**, so a tenant switching it on would
change nothing while appearing to. And that flag exists for air-gapped
deployments, so honouring the request would let a tenant force outbound network
calls the operator deliberately switched off. A tenant cannot weaken it either —
it simply always follows the baseline, and the key is rejected as unknown at
write time.

So a tenant turning a composition rule **off** when the baseline has it **on**
is silently a no-op rather than an error — see §6 for why that is surfaced in
the UI rather than accepted quietly.

---

## 3. Storage

A nullable `password_policy` JSONB column on `tenants`, matching the existing
`branding`, `custom_claims`, `matching_rules` and `claim_transforms` pattern.

```jsonc
{
  "minLength": 14,
  "requireDigit": true,
  "requireSymbol": true
}
```

**NULL means inherit**, and is the default for every existing and new tenant.
Absent keys inherit individually, so a tenant that only cares about length sets
only `minLength`. Partial objects are the normal case, not an edge case.

JSONB over six nullable columns because the shape is optional-by-nature, the
precedent is established in this table, and adding a rule later is a
documentation change rather than a migration.

`V60__tenant_password_policy.sql` adds the column. No backfill: NULL is the
correct value for every existing row.

---

## 4. Bounds, and what is *not* tenant-configurable

`maxLength` is capped at **72 bytes** regardless of what either the baseline or
a tenant asks for. bcrypt hashes only the first 72 bytes, so a higher value
silently ignores the tail and weakens the hash — the existing comment in
`PasswordPolicyProperties` says so, and the cap must survive tenant
configuration.

`minLength` is **not** floored at 800-63B's 8. A self-hosted operator owns
`app.security.password.min-length` and may set it lower; an existing test
(`PasswordPolicyServiceTest.relaxedConfig_allowsShorter`) pins that as intended.
An early draft of the implementation clamped it, broke that test, and in doing
so contradicted §2 — the boundary this feature draws is *tenants relative to
their operator*, not operators relative to us. Tighten-only already guarantees
a tenant cannot land beneath the baseline, so no floor is needed.

For the same reason the write-time validator's lower bound is 1, not 8:
refusing a tenant value that sits between a sub-8 baseline and 8 would reject
something *stricter* than what the deployment already permits.

Rejected values are a `400` at write time with the reason, not a silent clamp.
A tenant that asks for `minLength: 200` and is quietly given 72 would believe
something false about its own security posture.

---

## 5. Resolution

```java
EffectivePasswordPolicy resolve(Tenant tenant)   // baseline + tenant override
void validate(String password, Tenant tenant)    // new
void validate(String password)                   // retained, baseline-only
```

The single-argument overload stays for callers with no tenant in scope, and is
the deployment baseline. The three real call sites pass the tenant.

Resolution is pure and side-effect-free; the breach lookup remains the only I/O
and still runs last, only once local rules pass.

---

## 6. Surfaces

**Admin (write).** `passwordPolicy` joins `TenantDto`, so it travels on the
existing `PUT /api/admin/tenants/{id}` with no new endpoint. Subject to the
usual `/api/admin/**` tenant-selector rules — see `docs/cross-tenant-admin-spec.md`.

**Admin (UI).** Tenants → a *Password policy* subtab beside Branding. It shows
the deployment baseline alongside the tenant's override and **the effective
result**, because §2 means a tenant can enter a value that does nothing. A
field that is being overridden by a stricter baseline is shown as such rather
than appearing to have been saved.

**Public (read).** `GET /api/auth/tenants/{slug}/password-policy` returns the
*effective* policy so the register and reset forms can state the rules before
the user submits. Password rules are not secret, and a form that only reveals
them on rejection is the worst case for the user.

Note this sits under `/api/auth/`, which `AppAuthorizationFilter` exempts
wholesale — it is ungated, like `/tenants/{slug}/branding`. That is deliberate
and matches the sibling endpoints; do not assume a key is required.

**Customising the login and password-reset forms.** The rules surfaced here are
rendered by the tenant's own auth forms, which are themed per tenant: set
branding in the admin portal under Tenants → Branding, or via
`PUT /api/admin/tenants/{id}` with a `branding` JSON. Supported keys
(`logoUrl`, `primaryColor`, `primaryDarkColor`, `accentColor`, `bgColor`,
`bg2Color`, `textColor`, `displayFont`, `sansFont`, `tagline`, `eyebrow`,
`headline`, `ctaLabel`, …) plus `displayName`, and the per-tenant toggles
`registrationEnabled`, `passwordRecoveryEnabled`, `emailVerificationRequired`,
`returnToCallerEnabled`, are documented in `docs/tenant-branding.md`. Each
tenant's forms live on its own subdomain —
`https://{slug}.sso.weldforge.org/{login,forgot-password,reset-password,register,verify-email}`
— so browsers and password managers treat each tenant as a distinct site.

---

## 7. Testing

- **Unit** — resolution table from §2 exhaustively, including that a weakening
  override is a no-op and that the 72-byte cap survives.
- **Integration** — the column round-trips; a partial object inherits the rest;
  NULL behaves exactly as the baseline.
- **BDD** — registering under a tenant with a stricter policy is refused with
  the tenant's reasons, and the same password succeeds under a tenant that
  inherits.

The existing `PasswordPolicyServiceTest` must keep passing unchanged: the
baseline-only overload is not being altered, and a regression there would mean
the default path moved.

---

## 8. Out of scope

- **Password history / reuse prevention.** Needs a `password_history` table and
  a retention decision under POPIA; a separate piece of work.
- **Per-tenant lockout and rate-limit tuning.** Same shape of problem, and the
  rate limiter is still per-instance (see `docs/scaling.md`), so tenant-level
  tuning would not mean what it appears to mean.
- **Dictionary/denylist per tenant.** 800-63B permits it; the breach corpus
  already covers the common case.
