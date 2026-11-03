# Removing MFA requires proving you still hold it (B-AUTH-5)

**Status:** IMPLEMENTED 2026-11-03. Written before the code; the departures are listed at the end.
**Backlog item:** B-AUTH-5 (Low) — "Self-service MFA reset is password-only, unthrottled."
**Fix number:** F60.

## The invariant this sprint buys

> A user cannot go from MFA-protected to unprotected without proving, in one
> request, that they hold **both** the password **and** one currently-valid factor.

Everything below exists to make that sentence true, and the tests assert the
sentence rather than the mechanics.

## What the backlog says, and where it is wrong

B-AUTH-5 reads:

> `service/mfa/MfaService.java` (`selfReset`). A token+password attacker can strip
> all factors. Fix: require a current valid second factor to remove the last
> factor; rate-limit.

The remediation is right. The threat statement understates it in one way and
overstates it in another, and both matter for scoping.

**It understates the attacker.** `selfReset` is not the cheapest way to strip
MFA. `DELETE /api/auth/mfa/factors/{id}` takes `@AuthenticationPrincipal` and a
path variable — **no password, no factor proof, nothing**. A token-only attacker
deletes the factors one at a time and never visits `/reset`. So `selfReset`'s
password check is not a weak control, it is a control that can be walked around
entirely, and a fix that only hardens `/reset` closes the door while the wall is
missing. This is why the invariant above is phrased over the account state and
not over one endpoint.

**It overstates the reachability.** Neither route is reachable with a password
alone. `AuthService.login` returns `mfaRequired(true)` and an *MFA challenge
token* when the user has an active factor (`AuthService` line ~240), and both
routes require a full authenticated principal. So the attacker needs a live
access token — stolen, or an unexpired token from a session that was
authenticated before the factors were added. That is what keeps this Low rather
than High, and it is worth stating because the fix is cheap enough that the
severity does not need inflating to justify it.

**The third thing, which the backlog does not mention at all.** `selfReset`'s
password check is an *unthrottled password oracle*. `/api/auth/mfa/reset` is
absent from `RateLimitingFilter.ROUTES`, a wrong password raises
`BadCredentialsException` and **nothing is recorded** — no audit row, no
`lockoutService.recordFailure`, no metric. An attacker holding a stolen access
token can guess the account password at full speed, silently, and the per-user
lockout that protects `/api/auth/login` never sees it. Of the three problems
this is the one with no precondition beyond the stolen token the other two
already assume, so it is the one worth fixing most.

## Decisions

### 1. Proof required to wipe factors, and backup codes count as proof

`selfReset` will require a factor proof in the same request, reusing
`MfaService.verifyChallenge(user, MfaVerifyRequestDto)` — so TOTP, SMS,
WebAuthn and **backup codes** all qualify, because `verifyChallenge` tries the
backup code first, independent of `type`.

Backup codes counting is not a weakening, it is the point. The reason
`selfReset` exists is the lost-authenticator case, and "prove you hold a factor"
would otherwise mean "prove you hold the thing you just told us you lost",
leaving the user with no self-service path at all. The ladder is therefore:

| Situation | Path |
|---|---|
| Holds an authenticator | TOTP / SMS / WebAuthn proof |
| Lost the authenticator, kept the backup codes | backup code |
| Lost everything | `adminReset` — a human, out of band |

`adminReset` already exists and is already audited, so the bottom rung is built.

### 2. A user with no verified factor still resets with the password alone

If `hasVerifiedFactor(user)` is false there is nothing to protect and no proof
the user could possibly supply. Requiring one would make the endpoint
permanently unusable for exactly the accounts that are not at risk — an
abandoned half-finished enrollment plus stale backup codes. Password only, in
that case.

This is a deliberate branch, not an oversight, and it is the one place where
reading the code will look like the invariant is not enforced. It holds: an
account with no verified factor is already unprotected, so the transition the
invariant forbids cannot occur.

### 3. `deleteFactor` refuses the last verified factor rather than growing a body

The DELETE route stays shaped as it is. It will refuse when the target is the
caller's last **verified and enabled** factor, with a 409 and a message pointing
at `/reset`. Three reasons for refusing rather than accepting a proof here:

- A `DELETE` with a request body is legal but widely mishandled by proxies and
  clients, and this is the one route an attacker would rather use.
- The proof flow already exists at `/reset`, which wipes backup codes too — the
  correct end state for "I am turning MFA off" anyway.
- It keeps the enrollment-cancel path working untouched.

That last point is load-bearing. `security.component.ts` line ~422 calls
`deleteFactor(enroll.factorId)` to abandon a half-finished enrollment, and that
factor is **unverified**. Keying the rule on verified-and-enabled factors means
cancelling an enrollment is unaffected; keying it on "the last row" would have
broken the enrollment UI, and the symptom would have been a user unable to back
out of a TOTP setup they mistyped.

**Accepted residual:** deleting a *non-last* verified factor still needs only
the token, so a stolen token can take a user from three factors to one. It
cannot take them to zero, which is the transition that matters, and every
removal is already audited as `mfa.factor.remove`. Narrowing further means
requiring proof on every removal, which costs the DELETE-with-body problem above
for an attack that cannot remove MFA protection. Recorded, not fixed.

### 4. Both failure modes return one indistinguishable response

| Server-side | Recorded as | Response |
|---|---|---|
| Wrong password | audit `auth.mfa_reset.denied` reason `bad_password` + `lockoutService.recordFailure` | 401 `unauthorized` |
| Right password, bad proof | audit `mfa.self_reset.denied` + `recordChallengeFailure` | 401 `unauthorized` |

Same status, same body, same message — "Password or verification code
incorrect". The caller is not told which half failed, so the endpoint cannot be
used to confirm a password independently of a factor. The two cases are fully
distinguishable in the audit log, which is where the distinction is useful.

Note the asymmetry in what gets recorded, which is deliberate: a wrong password
feeds the **account lockout**, a wrong proof feeds the **MFA challenge-failure**
counter. A wrong password here is the same event as a wrong password at
`/api/auth/login` and belongs in the same counter; a wrong code is the same
event as a wrong code at `/api/auth/mfa/verify`.

### 5. Locked accounts are not oracles

`selfReset` will call `lockoutService.ensureNotLocked(user)` before looking at
the password, as `AuthService.login` does. Without it, lockout would stop
guessing at the front door and this endpoint would keep answering.

### 6. Rate limit: the `RECOVERY` bucket, not a new one

`/api/auth/mfa/reset` joins `ROUTES` as `RECOVERY` — the bucket B-AUTH-3 added
for `forgot-password` / `reset-password` / `resend-verification` / `mfa/sms/send`,
on the register cadence. MFA reset is the same shape of operation: rare,
sensitive, never called in a loop by a legitimate client. `LOGIN` would have
made a reset attempt and a sign-in starve each other from one office NAT.

The per-IP bucket is the weaker of the two new controls and is not the one being
relied on — it is defeated by rotating source addresses, which is why decision 4
wires the per-user lockout in as well. Stated here so the next reader does not
mistake the bucket for the fix. It also inherits whatever the trusted-proxy
boundary is worth (see F59, in review at the time of writing).

## Out of scope, and why

**`FailedLoginRecorder.badCurrentPassword` is the same defect, untouched.** It
audits `auth.password.change_failed` and then returns — it never calls
`lockoutService.recordFailure`, and `/api/auth/change-password` is not in
`ROUTES` either. So the self-service password-change endpoint is an unthrottled
password oracle in exactly the way `/reset` is, two methods away in the same
class.

Not fixed here. Adding lockout to it changes the behaviour of a different
endpoint that every signed-in user touches, and the failure mode of getting it
wrong is locking people out of working accounts. It is a one-line change with a
real blast radius, which makes it its own decision rather than a rider on this
one. Filed as **B-AUTH-6** with this analysis.

**The `MFA_STEPUP_REQUIRED` audit type already exists** (`AuditEventTypes` line
~78) and is not used by this work. Left alone rather than borrowed: whatever it
was reserved for, overloading it would make two different events share a name.

## Build order

1. `LastFactorProtectedException` + its 409 mapping in `GlobalExceptionHandler`,
   following the `SeatLimitExceededException` precedent.
2. `AuditEventTypes`: `MFA_SELF_RESET_DENIED`, `AUTH_MFA_RESET_DENIED`.
3. `FailedLoginRecorder.badResetPassword(User)` — audit **and** `recordFailure`.
4. `MfaService.selfReset(user, password, proof)`; `deleteFactor` last-factor guard.
5. `RateLimitingFilter.ROUTES` += `/api/auth/mfa/reset`.
6. `MfaController.selfReset` reads the proof fields from the body.
7. Admin portal: `mfa.service.ts`, `security.component.ts` + template, specs.
8. Tests: unit, BDD feature, rate-limit routing.
9. Docs: backlog B-AUTH-5 → FIXED (F60), new B-AUTH-6, threat model.

## What the tests must assert

The invariant, not the plumbing:

- Password alone no longer wipes a verified factor.
- Password + valid TOTP does.
- Password + valid backup code does (the lost-device ladder).
- Wrong password: no wipe, lockout counter moved, response identical to the next case.
- Right password + wrong code: no wipe, challenge-failure recorded, same response.
- A locked account gets refused before the password is read.
- No verified factor: password alone still works.
- `deleteFactor` refuses the last verified factor, 409.
- `deleteFactor` still removes an **unverified** factor — the enrollment-cancel path.
- `deleteFactor` still removes a verified factor when another verified one remains.
- `/api/auth/mfa/reset` resolves to the `RECOVERY` bucket in `RateLimitingFilter`.

---

## Where the implementation departed from this spec

Four things, none of them structural.

**The reset panel uses a text toggle, not a checkbox.** The plan did not name a
control, and the obvious one was `mat-checkbox` — but `MatCheckboxModule` is
imported nowhere in the admin portal, and pulling a new Material module in for
one boolean was not worth the bundle. It is a `mat-button` that flips the label
between "Authenticator code" and "Backup code", using a module already imported.

**`removeFactor` needed no error-handling change.** The plan assumed the UI would
have to surface the new 409 message. It does not: `err()` already appends the
server's `detail`/`message` through `apiErrorMessage`, and both of
`GlobalExceptionHandler`'s body shapes carry it. The only edit was the label, so
an expected guard does not read as "Failed to remove factor".

**Two test call sites the plan did not account for.** `TwilioPerTenantSteps`
constructs `MfaService` directly, and `MfaResetSteps` had a second `selfReset`
call in the wrong-password step. Both surfaced as compile errors on the first
`test-compile` — the argument the house rule makes for compiling rather than
reasoning about a constructor change.

**`RateLimitingFilterTest` asserts a count, so adding a route changed an existing
assertion** from `times(4)` to `times(5)` rather than adding a case. Left as a
count because that is what makes a *silently dropped* route fail the test; a new
standalone case would have passed with the route missing from the loop.

## Verified

Local, on this branch: `test-compile` BUILD SUCCESS; then
`MfaServiceTest` **17/17**, `RateLimitingFilterTest` **6/6**, `CucumberRunner`
**220/220** — **243 tests, 0 failures, 0 errors, 0 skipped, BUILD SUCCESS**. All
six new or rewritten `mfa_reset.feature` scenarios were listed as executed by
name, including "The correct password alone no longer turns MFA off" and "The
delete route cannot be used to strip the last factor".

The admin-portal Vitest suite and `ng build` are the CI frontend job's to run:
a fresh worktree has no `node_modules`.
