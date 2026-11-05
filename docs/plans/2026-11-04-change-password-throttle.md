# A failed password change is a recorded, throttled event (B-AUTH-6)

**Status:** IMPLEMENTED 2026-11-04. Written before the code; the departures are listed at the end.
**Backlog item:** B-AUTH-6 (Low) — "Self-service password change is an unthrottled password oracle."
**Fix number:** F61.

## The invariant this sprint buys

> No endpoint that re-verifies the account password can be asked an unlimited
> number of questions, and none of them can be asked silently.

F60 made that true of `/api/auth/mfa/reset`. This makes it true of the last one,
`/api/auth/change-password`, which is the endpoint B-AUTH-6 names.

## What is actually wrong

`AuthService.changePassword` compares the supplied current password and, on a
mismatch, calls `FailedLoginRecorder.badCurrentPassword(user)` — which writes one
audit row (`auth.password.change_failed`) and **returns**. It never calls
`lockoutService.recordFailure`, and `/api/auth/change-password` is absent from
`RateLimitingFilter.ROUTES`. There is also no `ensureNotLocked` on the path.

So a caller holding a stolen access token can test password guesses against it at
full speed, forever, and the only trace is an audit row nothing alerts on. Each
guess costs a bcrypt comparison, so it is a CPU amplifier as well as an oracle.

This is the same defect F60 fixed two methods away in the same class, and the
reason it was filed separately rather than fixed as a rider: the remediation
changes the behaviour of an endpoint every signed-in user touches, and the
failure mode of getting it wrong is locking people out of working accounts.

## Decision 1 — yes, a failed change feeds the account lockout

The question B-AUTH-6 left open was whether a failed change should be able to
lock an already-authenticated account. It should, and the argument is symmetry
rather than appetite for risk:

**An attacker gains no new capability.** `FailedLoginRecorder.badPassword`
already calls `recordFailure` on the `/api/auth/login` path, and that path is
reachable with nothing but an email address. Anyone who knows a user's email can
already lock that account for 15 minutes by sending five wrong passwords, with no
token at all. Adding `recordFailure` here therefore hands an attacker a lever
they already had from a *weaker* position, while closing an oracle that only this
endpoint offers.

**The cost to a legitimate user is bounded and small.** `app.security.lockout` is
`max-attempts: 5`, `lock-minutes: 15`, and `ensureNotLocked` auto-clears the lock
and resets the counter once the window elapses. The worst case for someone who
genuinely cannot remember their current password is a fifteen-minute wait, not an
administrator call.

**The alternative does not work.** Rate limiting alone is keyed per IP and is
defeated by rotating source addresses; it is also the control that hurts
legitimate shared-NAT users first. The per-user counter is the one that actually
bounds the number of questions.

## Decision 2 — a locked account is told so, honestly, and with a 423

Both login paths catch `AccountLockedException` and rethrow
`BadCredentialsException("Invalid credentials")` on purpose, so an attacker
enumerating accounts cannot tell "locked" from "does not exist". **That rationale
does not transfer here.** The caller of `/api/auth/change-password` is already
authenticated as the account owner: they know the account exists, they know it is
theirs, and there is nothing left to conceal. Being vague would withhold
information from its owner to no benefit.

So this path lets the lock be visible: a new `@ExceptionHandler` maps
`AccountLockedException` to **423 Locked**, code `account_locked`, with a
`Retry-After` header and a message naming the wait. Adding that handler cannot
change login, because both login call sites convert the exception before it can
escape (`AuthService` lines ~221 and ~292) — checked, not assumed.

**423 rather than 401 is load-bearest, for a reason that is not about semantics.**
See decision 3.

## Decision 3 — the portal's 401 handling is why this needs care

While reading the path I found a live defect, and it is the thing that would have
made decision 1 dangerous.

`auth.interceptor.ts` keeps `PRE_AUTH_PATHS`, a list of "endpoints whose 401 means
bad credentials, not session expired". Neither `/api/auth/change-password` nor
`/api/auth/mfa/reset` is on it. Both answer 401 for a credential the caller just
supplied, so the interceptor:

1. sees a 401 on a path it believes should never produce one,
2. calls `/api/auth/refresh` and gets a fresh token,
3. replays the change-password request with `SKIP_REFRESH_RETRY` set,
4. gets the same 401, because the current password is still wrong,
5. clears `access_token` and navigates to `/login?reason=session_expired`.

So any client calling that endpoint gets signed out when it reports a mistyped
password, and is told its session expired. Combined with decision 1 that becomes:
mistype, get signed out, sign back in, mistype, get signed out — and on the fifth
attempt the account locks, so signing back in stops working too.

**Correction to an earlier draft of this spec, which overstated it.** The admin
portal has *no change-password UI at all* — zero references to the endpoint — so
this cascade is not reachable in the portal today for change-password. It is
reachable for any other API consumer, and a future password-change form here
would reintroduce it, which is why the path is allowlisted pre-emptively. The
part that *is* live in the portal is `/api/auth/mfa/reset`, below.

**`/api/auth/mfa/reset` has the same hole, and F60 put it there.** F60 made that
endpoint return 401 for a wrong password *or* a wrong factor code, and it is not
in `PRE_AUTH_PATHS` either. The "Password or code incorrect" message F60 added to
the reset panel is therefore unreachable in the browser — the interceptor
redirects before the component can render it. That is a regression in work that
shipped this week and it is fixed here.

Both paths join `PRE_AUTH_PATHS`. And a locked account returns 423, not 401, so
the interceptor never looks at it at all — which is the defence-in-depth reason
for decision 2's status choice: the one response a user hits *repeatedly* while
locked cannot be mistaken for session expiry even if this list goes stale again.

**Accepted residual:** on an allowlisted path a genuinely expired access token now
also passes through instead of being refreshed, so a token that expires while the
form is open yields an error on that submit instead of a transparent retry. The
panels show the server's `detail` rather than a hardcoded string, so the user
reads "Authentication required" and a reload fixes it — truthful, if not elegant.
Closing it properly means branching on the problem document's `error` code rather
than on a path list, because the server does distinguish the two cases
(`ApiAuthenticationEntryPoint` writes "Authentication required";
`GlobalExceptionHandler` writes the thrown message) but gives both the same code,
`unauthorized`. That is a contract change affecting every client. Filed as
**B-AUTH-7** rather than done here.

## Decision 4 — a dedicated rate-limit bucket, not `RECOVERY`

Neither existing bucket fits, and the F60 comment explains half of why:

| Bucket | Cadence | Why not |
|---|---|---|
| `RECOVERY` | 5 / 60 min | A legitimate change consumes a token too. Five users behind one office NAT rotating passwords after an incident hit the cap, and the sixth is refused |
| `LOGIN` | 10 / 15 min | Shared map, so a password change and a sign-in from the same NAT starve each other — the exact objection F60 recorded against putting `/mfa/reset` here |

So: a new `PASSWORD_CHANGE` endpoint with its **own bucket map** on the **login
cadence** (10 per 15 minutes per IP). No new configuration properties — reusing an
existing cadence for a new map is the pattern `RECOVERY` already set when it
borrowed the register cadence.

Note what this bucket is and is not for. It is not the control that closes the
oracle — the per-user lockout is, because five failures end the attempt
regardless of how many addresses the caller rotates through. The bucket's job is
to stop one source burning bcrypt CPU. Sized accordingly: generous enough that no
legitimate office notices it.

**`RateLimitingFilter.ROUTES` also converts from `Map.of` to `Map.ofEntries`.**
`Map.of` accepts at most 10 key/value pairs; F60 took it to 9, and this entry
takes it to exactly 10. The next route added would fail to compile with an error
that names an arity rather than a limit, so the cliff is removed now rather than
left for whoever hits it.

## Out of scope, and why

**The `sso.auth.login` meter is broken in production and is not fixed here.**
`FailedLoginRecorder.bumpFailureCounter` registers `sso.auth.login` with tags
`[outcome, tenant]`, while something else registers the same name with
`[outcome]` alone. Micrometer refuses the second registration, so the production
log carries `registration has failed: Prometheus requires that all meters with
the same name have the same set of tag keys` and some login metrics are silently
dropped. It is real, it is in a class this sprint edits, and it predates all of
F58/F59/F60. It is also a metrics-contract question — whether `tenant` belongs on
that meter at all, given it multiplies cardinality by tenant count — and not a
security fix. Filed as **B-OBS-1**; not touched, so this sprint does not add a
new tag to a meter that is already failing to register.

**No new audit event type.** `auth.password.change_failed` already exists and
already fires; what was missing was the lockout and the throttle beside it. The
audit row gains a `locked` field so a reader can tell a counted failure from the
one that tripped the lock, but the event name does not change.

## Build order

1. `AccountLockedException` → 423 handler in `GlobalExceptionHandler`, with
   `Retry-After`.
2. `FailedLoginRecorder.badCurrentPassword` — add `recordFailure`, keep the audit
   row, return whether the account ended up locked.
3. `AuthService.changePassword` — `ensureNotLocked` before the password compare.
4. `RateLimitingService` — `PASSWORD_CHANGE` enum value + bucket map, login cadence.
5. `RateLimitingFilter.ROUTES` — `Map.ofEntries`, add `/api/auth/change-password`.
6. Portal: `PRE_AUTH_PATHS` += change-password and mfa/reset; both panels show the
   server's message and label 423 as a wait rather than a failure.
7. Tests: unit, BDD, rate-limit routing, interceptor.
8. Docs: backlog B-AUTH-6 → FIXED (F61), new B-AUTH-7 and B-OBS-1, threat model.

## What the tests must assert

The invariant, not the plumbing:

- A wrong current password moves the lockout counter (it did not before).
- Five wrong current passwords lock the account.
- The fifth response, and any attempt while locked, is 423 — not 401.
- A locked account is refused **before** the password is compared, so the endpoint
  is not an oracle while locked (same property F60 gave the reset path).
- A *correct* current password on a locked account is still refused — otherwise
  the lock is decorative.
- A successful change still resets the failure counter, so earlier fumbles do not
  accumulate across a success.
- A wrong current password still audits `auth.password.change_failed`.
- `/api/auth/change-password` resolves to the `PASSWORD_CHANGE` bucket, and
  `/api/auth/mfa/reset` still resolves to `RECOVERY` (the F60 routing is intact).
- Interceptor: a 401 from change-password and from mfa/reset propagates to the
  caller and does **not** navigate to `/login` — the regression test for
  decision 3.
- Interceptor: a 401 from a non-allowlisted API path still refreshes and replays,
  so the allowlist change did not disable session refresh generally.

---

## Where the implementation departed from this spec

**`badCurrentPassword` returns a `LocalDateTime`, not a boolean.** The spec said
"return whether the account ended up locked". Returning the expiry instead lets
the 423 carry a real `Retry-After` and name the wait in its message, which is the
whole reason for choosing 423 over a bare refusal.

**`recordSuccess` on a successful change was in the test list but not the build
order.** Implemented: without it, fumbles accumulate across successful changes and
someone who mistyped twice months ago starts three attempts away from a lock.

**Decision 3's rationale was overstated in the first draft and is corrected
in place.** The admin portal has no change-password UI at all, so the sign-out
cascade is not reachable there for that endpoint — it affects other API consumers,
and `/api/auth/mfa/reset` is the instance that was live in the portal.

## Found by running the gate, filed not fixed

**B-TEST-1 (Medium).** All 22 integration-test classes run against
`postgres:16-alpine` while production is `postgres:18.1-alpine`. Every migration
in this repository is therefore proven two majors below where it is applied. This
sprint ships no migration so nothing here is exposed, but the next one is, and the
failure would land at deploy time in every environment at once instead of in CI.

## Verified

Full house gate on this branch — `./mvnw -B -ntp -o verify -Dtests.integration=true`:
**1576 tests, 0 failures, 0 errors, 0 skipped, BUILD SUCCESS**, with the
integration classes starting real Postgres containers (not skipped).
`CucumberRunner` **239/239** including the five new change-password scenarios,
`FailedLoginRecorderTest` **6/6**, `RateLimitingFilterTest` **8/8**.

Portal: **26 test files / 255 tests passing** (up from 25/251 — the new interceptor
spec), `npm run build` exit 0.
