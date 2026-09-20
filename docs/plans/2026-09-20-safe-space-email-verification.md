# Safe Space email verification, and the two-instance problem

Assessment and plan, 2026-09-20, in response to the Safe Space handover.

The handover is good. Its priorities are right, its warnings are real, and the
recommendation on gating (app-side first, platform-side later behind a flag) is
the one I would have made. This document records where I agree, the two things
it misses, and the sequence I propose.

---

## 1. Verified before planning

Everything below was checked against the live systems rather than taken from the
handover. Where I could not verify something, it says so.

| Claim | Verified | Result |
|---|---|---|
| Two live instances | ✅ | `sso-api.weldforge.org` → 136.68.154.69 answers 200 on `/health` **and** OIDC discovery for `techmetropolis`. It is live. |
| tech01 is separate | ✅ | `sso.weldforge.org` → 196.40.100.82, different database, own tenants. |
| GKE is behind | ✅ | 8 failures from `Test-PrePromotion.ps1`; see §3. |
| Cloud SQL backups off | ❌ not verified | No GCP auth from this session. **Treat as true and verify before any migration.** |
| Helm revision 5 FAILED | ❌ not verified | Same reason. The handover is specific enough to be credible. |

### The thing the handover missed

**Both instances serve `techmetropolis` with the same private signing key.**

```
sso-api.weldforge.org   kid: wf-66256c5b-a66c-4044-bd98-a3d97b81adc0
sso.weldforge.org       kid: wf-66256c5b-a66c-4044-bd98-a3d97b81adc0
```

tech01's copy is a restored clone — same tenant, same 9 users, same key, a
different issuer. That was never written down anywhere. It matters three ways:

1. **Compromise of either instance compromises the tenant on both.** The blast
   radius of the old, unpatched GKE instance now includes tech01's copy.
2. **A token minted by one validates against the other's JWKS.** Only `iss`
   separates them. Any relying party not checking `iss` strictly accepts tokens
   from either instance.
3. **Rotating `app.jwt.secret` is a four-way coordination**, not three-way: GKE,
   tech01, and the three app backends. The handover's Task 3 undercounts it.

This does not block the email-verification work, but it belongs in the risk
register and it changes how Task 3 must be sequenced.

---

## 2. Where I agree with the handover, and why

- **Task 3 (rotate the exposed secrets) first.** Correct. A key known to be in a
  transcript is a key in someone's scrollback.
- **Option (b) — app gates, platform exposes the flag — now; option (a) behind a
  per-tenant flag later.** Correct, and for the stated reason: (a) alone locks
  out every existing unverified account across four tenants. Shipping (b) first
  gets Nyasha the behaviour she asked for with no blast radius.
- **`kubectl set image`, never `helm upgrade`.** Correct given a FAILED revision
  5 and a hand-patched secret Helm does not know about.
- **Back up Cloud SQL before rolling the image.** Correct, and the sharpest point
  in the handover: 13 Flyway migrations run on first boot and automated backups
  are off. The migration is the risk, not the DTO change.
- **Verify mail actually sends before promising verification.** Correct.
  `SmtpMailService` returns success to the caller even when delivery fails — by
  contract — so "the endpoint returned 200" proves nothing about delivery.

---

## 3. What running a June image actually costs

The handover frames this as "~96 commits and 13 migrations behind". That
understates it. Running `Test-PrePromotion.ps1` against the live GKE instance —
the one Safe Space authenticates through — gives **8 failures**:

| Failure | What it means live today |
|---|---|
| `/actuator/prometheus` **200, publicly readable** | 83 KB, 153 metric families, unauthenticated: JVM internals, datasource pool state, per-endpoint HTTP timings, and the full auth URI surface. Closed on tech01 on 2026-09-13; still open here. |
| `/actuator/health` **200, publicly readable** | Same exposure class. |
| Malformed JSON → **500** (three cases) | B-API-2. A client mistake is a server error; it leaks stack context and pollutes any 5xx alerting. |
| No `Referrer-Policy` | The app sends `no-referrer` because its protocol URLs carry codes, state and SAML payloads. This instance sends nothing, so those can leak in `Referer`. |
| `/tenants` → 403 | The ingress `/t` string-prefix bug. Cosmetic here (no portal on this host). |
| No per-tenant subdomain | Expected — different hosting model. |

Not visible to a black-box probe, but equally absent from that image:

- **The atomic single-use fix (B-OIDC-6 / B-AUTH-6).** Demonstrated exploitable
  on 2026-09-15: eight concurrent rotations of one refresh token all succeeded
  and reuse detection never fired. **This instance still has that race.**
- Tenant-scoped WebAuthn username resolution, the per-tenant refresh cookie
  (B-TEN-7), `SameSite` on the refresh cookie, `X-Robots-Tag`, and the
  ShedLock fix that makes more than one replica safe.

**Conclusion:** the version drift is not housekeeping. The instance carrying real
users is the one missing every security fix of the last month.

---

## 3a. Measured, 2026-09-20 — the picture is better than feared, with one landmine

GCP access restored, so the numbers are now real rather than inferred.

**A backup exists for the first time.** `gcloud sql backups list` showed none at
all; automated backups confirmed **disabled**, no PITR. On-demand backup
`1789894702688` taken and `SUCCESSFUL` before anything else was touched.

**The data delta is one account.**

| | GKE (Cloud SQL) | tech01 |
|---|---|---|
| Schema | **V44** (2026-06-16) | **V58** |
| `techmetropolis` users | **10** | **9** |
| Tenants | 7 (incl. an empty `intelli`) | 6 |
| OIDC clients for techmetropolis | **none** | none |
| App-client keys for techmetropolis | **none** | none |

tech01 is a strict subset: every tech01 account exists on GKE, and exactly one
GKE account is missing from tech01. Its email domain is **`hgmail.com`** — a
typo of gmail.com. That account can never receive mail and can never reset a
password. It is, precisely, the defect Nyasha reported.

**Safe Space does not use OIDC.** No OIDC client and no app-client key exists
for this tenant on either side; it authenticates through the legacy JSON proxy
with `X-Tenant-Slug`. So there is no client configuration to migrate, which
removes the biggest cutover risk.

### The landmine

`Tenant.emailVerificationRequired` **already exists**, defaults to `true`, and
is already `true` for `techmetropolis`. **Nothing in the login path reads it**,
and every one of the 10 users has `email_verified = false`.

So option (a) is not "add a per-tenant flag" as the handover assumed — the flag
is there and it is already on. Wiring enforcement to it as-is would lock out
**every user on every tenant at the moment of deploy**. The backfill is not a
tidy-up step to schedule later; it is a precondition, and the order is:

1. Backfill existing accounts to `email_verified = true` (grandfather them).
2. Only then enforce, and only for tenants that opt in.

Reversing those two steps is an outage for all three apps.

## 4. Plan

Sequenced so each step is independently shippable and nothing blocks Nyasha
longer than it must.

### Step 1 — Expose `emailVerified` on `/api/auth/me` *(this repo, low risk)*

Add `emailVerified` to `UserResponseDto` and populate it in
`AuthController.currentUser`. Additive: existing clients ignore an unknown
field.

**Do it properly, not just for `/me`.** Also emit `email_verified` as an OIDC
**ID-token claim** — it is a standard claim (OIDC Core §5.1) and it lets a
resource server gate without an extra round trip to `/me`. Exposing it only on
`/me` means every backend must call the IdP on every request to know, which
nobody will do, so they will trust the client instead. That is the failure mode
option (b) has to avoid.

Coordination: safe-space-api proxies `/me` with `X-Tenant-Slug: techmetropolis`.
Check `AuthProxyService` forwards unknown fields rather than re-mapping a fixed
shape, or the field dies at the proxy.

### Step 2 — Prove mail works on GKE *(no deploy)*

`POST https://sso-api.weldforge.org/api/auth/resend-verification`, then read the
pod logs for `Sent email` / `Email delivery`. If it silently logs, stop: Task 2
comes first, because verification email that never arrives is worse than none —
it blocks signup with no recourse.

### Step 3 — Roll the GKE image *(the risky step)*

1. On-demand Cloud SQL backup, **verified restorable**, not just taken.
2. `kubectl set image` to a GHCR `sha-` tag containing Step 1.
3. Watch 13 Flyway migrations on first boot. Have the rollback tag written down
   before starting.
4. Re-run `Test-PrePromotion.ps1` against `sso-api.weldforge.org`; the 8
   failures should become at most the 2 structural ones.

This single step also closes the actuator exposure, B-API-2, the referrer leak
and the token-rotation race — which is why it is worth the risk rather than
cherry-picking the DTO onto `r2`.

### Step 4 — Per-tenant `require_email_verification` *(option (a), later)*

Column + migration, default **false**, enforced in `AuthService.login`. Backfill
existing accounts to verified so nobody is stranded. Enable per tenant, starting
with `techmetropolis`, only once Safe Space's screen is live and mail is proven.

### Step 5 — Task 2 (chart), Task 3 (rotation), Task 4 (quick wins)

Per the handover, with one amendment: **Task 3's `JWT_SECRET` rotation is
four-way**, because tech01 shares the key. Sequence it as a key-ring change
(`B-JWT-2`) rather than a flag day, or every token in every app breaks at once.

---

## 5. Out of scope here

- **Task 5, per-tenant custom domains.** Correctly deferred; it is a schema and
  host-resolution change, not config.
- **Consolidating the two instances.** The right long-term answer, and too big to
  bundle with a signup fix. The shared signing key should be the argument that
  starts that conversation.

## 6. What I will not do without explicit approval

- Anything against the GKE cluster: `kubectl set image`, secret patches, backups.
  It is a live IdP for three apps and I have not verified its state myself.
- Rotating `JWT_SECRET`. Four systems break simultaneously if it is done wrong.
- Sending anything to Nyasha. House rule: drafts only.
