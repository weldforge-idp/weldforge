# `max_age` and `prompt=login` — options for OpenID Basic OP certification

**Status:** options for decision, 2026-09-20. Nothing implemented.
**Blocks:** OpenID Foundation self-certification, Basic OP profile (agreed 2026-09-15).
**Deviations:** D1 and D2 in `docs/compliance/standards-conformance.md`.

The certification suite exercises both directly, so both have to change. *How*
they change is a product decision, not a bug fix, because it alters what an
existing relying party observes.

---

## 1. What is wrong today

**D1 — `max_age` means the wrong thing.** OIDC Core §3.1.2.1 defines it as the
maximum permitted time *since the user last authenticated*. WeldForge routes it
into `OidcAuthorizationService.enforceStepUp`, where it becomes a freshness
window on the user's **MFA factor**. When the window is exceeded — or the user
has no MFA factor at all — `/authorize` answers `400 {"error":"mfa_required"}`
in the browser.

Three separate problems in one behaviour:

- It measures the wrong thing (factor use, not authentication).
- It ends in a **400 in the browser** rather than re-authenticating the user or
  redirecting the error to the RP, which §3.1.2.6 requires.
- `mfa_required` is **not a registered error code**.

**D2 — `prompt=login` is ignored.** An existing session is silently reused.
`prompt=none` and `prompt=consent` are both handled correctly; `login` simply
falls through.

---

## 2. Measured blast radius: effectively zero

This is the finding that decides the recommendation. Read from production
(`weldforge_prod`) on 2026-09-20:

| | |
|---|---|
| OIDC clients with `max_authentication_age_s` set | **0 of 8** (all zero) |
| OIDC clients with `require_mfa` | **0 of 8** |
| Rows in `tenant_mfa_policies` | **0** |
| Verified MFA factors across all tenants | **1** |

So no client and no tenant currently drives the step-up path. It is reachable
today **only** when an RP sends `max_age` on the request — and because exactly
one account in the estate has a verified factor, an RP doing so would break
login for essentially every user. That is the documented D1 impact, confirmed.

**Nothing in production depends on the current interpretation.** Changing it is
close to free now, and gets more expensive with every adopter who discovers
`max_age` and works around the 400.

---

## 3. The good news: both need the same primitive, and most of it exists

Both fixes reduce to *"force a fresh authentication, then resume this
authorization request"*. Two of the three pieces are already built:

- **`auth_time` is real.** Captured in `JwtAuthenticationFilter`
  (`AUTH_TIME_ATTRIBUTE`), persisted on `OAuthAuthorizationCode.auth_time`,
  minted as a claim, and advertised in discovery. **We do not need to start
  tracking authentication time — we already do.**
- **The resume-after-login round trip is real.** An unauthenticated
  `/authorize` already 302s to
  `{tenant-origin}/login/?oidcReturnTo=<base64 of the original URL>`, and the
  portal SPA reads it back (`core/oidc-continuation.ts`).
- **Missing:** a way to say *"re-authenticate even though a session exists"*.
  Today the SPA would see a valid `wf_session` and bounce straight back,
  producing a redirect loop rather than a login form.

That third piece is the actual work, and it is shared by D1 and D2. Build it
once.

---

## 4. Options for D1 (`max_age`)

### Option A — Spec semantics, MFA step-up kept as a separate concern ✅ recommended

`max_age` compares against `auth_time`. Stale ⇒ re-authenticate and resume.
MFA step-up stays, driven by `client.requireMfa` and the tenant's
`defaultStepupMaxAge` — where it belongs — and stops being triggered by the
request parameter.

- **Conformance:** passes.
- **Risk:** an RP relying on `max_age`-as-MFA-freshness loses it. Per §2 there
  is no such RP.
- **Cost:** the shared primitive, plus separating the two code paths in
  `enforceStepUp`.
- **Bonus:** removes the unregistered `mfa_required` error from the browser
  path.

### Option B — Per-client semantics flag

Add `max_age_semantics = SPEC | LEGACY_MFA`, defaulting to `SPEC`.

- **Conformance:** passes (the default is what the suite sees).
- **Cost:** a permanent fork in behaviour, and a migration flag that in practice
  is never removed. Every future reader of `enforceStepUp` has to hold two
  meanings in their head.
- **Justified only if** an adopter actually depends on the current behaviour.
  None does.

### Option C — Fix only the error shape

Keep MFA-freshness semantics; replace the browser `400 mfa_required` with a
spec-shaped redirect carrying a registered error code.

- **Conformance:** **fails.** The suite checks that `max_age` forces
  re-authentication and that `auth_time` moves accordingly.
- **Worth noting anyway:** this is a strict subset of Option A and is the right
  thing to ship if certification is deferred — it removes a
  browser-facing 400 that is wrong under any interpretation.

---

## 5. Options for D2 (`prompt=login`)

### Option A — Honour it with the shared primitive ✅ recommended

`prompt=login` ⇒ always force re-authentication, regardless of session age,
then resume.

- **Conformance:** passes.
- **Subtlety worth stating:** re-authentication must be *provable*, not
  cosmetic. If the flag only renders a form while leaving `wf_session` valid, a
  user pressing back — or an SPA that auto-resumes — yields an unchanged
  `auth_time`, and we would be asserting a fresh login that did not happen. The
  primitive has to invalidate or bypass the existing session and write a new
  `auth_time` on success.

### Option B — Error instead

Return `login_required` when a fresh login cannot be guaranteed. The spec does
permit erroring when re-authentication is impossible.

- **Conformance:** partial. Legal for an OP that genuinely cannot
  re-authenticate; ours can.
- Poor experience and a worse story for enterprise buyers, who ask for
  `prompt=login` by name for step-up flows.

### Also required, and currently missing

- `prompt=none` combined with any other value must be `invalid_request`.
- When `max_age` is requested, `auth_time` becomes **REQUIRED** in the ID token.
  We mint it today, but nothing enforces that it is present in that case.

---

## 6. Recommendation

**D1 Option A + D2 Option A, built on one shared re-authentication primitive,
in a single change.** They share the mechanism, the test surface and the risk;
splitting them means building the hard part twice and shipping a half-conformant
`/authorize` in between.

Sequence:

1. The primitive: force-reauth signal on the login redirect, session bypass, new
   `auth_time` on success, resume the original request.
2. Point `prompt=login` at it (D2) — the simpler consumer, and it proves the
   primitive works.
3. Re-point `max_age` at `auth_time` and split MFA step-up out of it (D1).
4. `prompt=none` + other values ⇒ `invalid_request`; enforce `auth_time` when
   `max_age` was requested.
5. Update `standards-conformance.md`: D1 and D2 move to resolved.

---

## 7. Scope check — what else Basic OP needs

Certification is a suite run, not a single fix. Known from the conformance
statement, not yet verified against the suite:

- **D3 — PKCE.** Clients registered before the default can still run a code flow
  without a challenge. The plan on file is to refuse once
  `sso.oidc.pkce.missing` reads zero. Basic OP does not require PKCE, so this
  is not a blocker, but it should be checked rather than assumed.
- **D4 — `401` vs `400 invalid_client`** at the token endpoint, with
  `WWW-Authenticate` when HTTP Basic was attempted. Small, and the suite does
  test error shapes.
- **Not implemented and out of Basic OP scope:** `claims`, `request` /
  `request_uri`, `acr` / `acr_values`, pairwise subjects, session management,
  front- and back-channel logout.

I would run the suite once against staging **before** writing any code. It costs
an afternoon and replaces this list with a real one — I would rather fix what it
reports than what we predict it will report.

---

## 8. Decisions needed

1. **D1 semantics** — Option A (recommended), B, or C?
2. **D2** — Option A (recommended) or B?
3. **Ship together or separately?** Recommendation is together.
4. **Run the conformance suite against staging first?** Recommended, and note
   staging now has a `techmetropolis` tenant plus `default`.
5. **Is `mfa_required` in the browser worth fixing independently**, if
   certification slips? It is wrong under every reading of the spec.
