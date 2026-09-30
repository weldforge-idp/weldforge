# Service account tokens

A service account is a machine identity scoped to one tenant. It authenticates
with a `wf_svc_*` token in the `x-app-authorization` header, and may carry an
admin role so automation gets explicit capabilities instead of borrowing a
person's credentials.

Portal: **Service Accounts**. API: `/api/admin/service-accounts`.

---

## Lifetime

Every token has one. It is either an instant, or never.

Ask in the units you think in — `expiresInDays`, optionally plus
`expiresInHours`. The server turns that into the stored instant.

```json
POST /api/admin/service-accounts
{ "name": "ci-deploy", "adminRole": "TENANT_ADMIN", "expiresInDays": 90 }
```

**`0` means the token never expires.** That is deliberate and it is the only
way to say it:

```json
{ "name": "bootstrap", "adminRole": "TENANT_ADMIN", "expiresInDays": 0 }
```

Omitting both duration fields means *leave the existing expiry alone*. On
create that resolves to no expiry, which keeps older callers behaving exactly
as they did.

**Why zero rather than null.** Without a sentinel, "never expires" and "don't
change the expiry" are both `null` on the wire. The update path reads `null` as
"leave alone", so a token that expires could never be made permanent again —
the expiry could only ever be moved further out. Zero separates the two.

Negative durations are refused. So is anything over **3650 days**, which is not
a security boundary (indefinite is still allowed, explicitly) but a guard
against typing hours into the days box: a token quietly issued for 87,600 days
reads as "expires" in every listing while being permanent in practice.

### Defaults

| Where | Default |
|---|---|
| API, when no duration is sent | **no expiry** — unchanged from before |
| Portal create form | **90 days** |

The split is intentional. Existing machine callers must not have expiry
imposed on them by an upgrade. A token a person creates through the UI should
expire unless they deliberately say otherwise — and until the form had this
field, *every* token created there was permanent, because permanent was the
only thing the screen could express.

---

## Rotation

Rotating issues a new secret and invalidates the old one immediately.

By default the expiry is **left alone**, so a token rotated every 30 days keeps
its original end date rather than being silently extended forever. Send a
duration to reset it:

```json
POST /api/admin/service-accounts/42/rotate
{ "expiresInDays": 90 }
```

**Rotating an already-expired token without a new lifetime is refused.** It
would hand back a credential that cannot authenticate, and the caller would not
discover that until the first 401. The portal handles this for you: rotating an
expired token offers a fresh 90-day lifetime and says so in the dialog.

---

## Reading the list

The **Expires** column shows `never`, `in 40 days`, or `expired`. Anything
inside 14 days is amber; expired is red. Amber is a scheduling problem, red is
an outage already in progress.

---

## What expiry does and does not do

**Enforced at authentication.** `AppAuthorizationFilter` rejects an expired
token with `Service account token expired`. It is not merely advisory metadata.

**Not a replacement for disabling or deleting.** Expiry is a scheduled end, not
a revocation. To stop a token *now*, toggle the account off or delete it —
both take effect on the next request.

**No warning is sent.** Nothing emails or alerts before a token lapses; the
portal column is the only signal. If a token matters, put its expiry in a
calendar. Instrumenting this is on the backlog.

---

## Known gap: auto-provisioned bootstrap tokens

When a tenant is provisioned from a paid order, `TenantProvisioningService`
mints a `bootstrap-admin` service account with `TENANT_ADMIN` and **no
expiry**, described as "Rotate after first login". In practice nobody does.

It was left as-is deliberately when the duration fields were added: giving it a
default lifetime would be correct security, but doing so silently risks locking
a customer out of a tenant they have not signed into yet. Changing it is an
operator decision, not a quiet default — see the note in
`docs/security/hardening-backlog.md`.

---

## Roles

A service account's `adminRole` is one of `NONE`, `READ_ONLY`, `TENANT_ADMIN`
or `SUPER_ADMIN`. Only a super admin may grant `SUPER_ADMIN`, mirroring the
user-side rule.

This is separate from the tenant **Role** assigned to human users, which feeds
the token's `roles` claim for relying parties. See
`docs/product/oidc-client-administration.md`.
