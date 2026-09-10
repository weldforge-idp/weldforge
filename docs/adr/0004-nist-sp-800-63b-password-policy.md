# ADR 0004 — NIST SP 800-63B memorized-secret policy: adopted, two deviations

**Status:** Accepted · 2026-09-10 · CONF-8.2 (implemented by CONF-7.1, Sprint 6)

## Context

NIST SP 800-63B §5.1.1.2 sets the rules for verifiers of memorized secrets:

- at least 8 characters, and SHOULD permit at least 64;
- SHALL NOT impose composition rules (e.g. "one uppercase, one digit, one
  symbol");
- SHALL compare new passwords against a list of known-compromised values;
- SHALL NOT require periodic changes, and SHALL NOT offer hints.

Until Sprint 6, WeldForge required uppercase, lowercase, digit and symbol by
default and checked no breach corpus. Composition rules produce `Password1!`,
which satisfies every class and appears in every breach list. Enterprise buyers
increasingly audit password policy against 800-63B directly.

## Decision

Adopt 800-63B §5.1.1.2 as the default policy:

| Rule | WeldForge default |
|---|---|
| Minimum length | **12** characters (above the 8 floor) |
| Composition rules | **Off.** Each can be re-enabled per deployment (`app.security.password.require-*`) |
| Breach screening | **On:** Pwned Passwords range API, k-anonymity |
| Periodic change | Never required |
| Hints | None offered |
| Throttling | Rate limit plus lockout (5 failures / 15 minutes) |
| Storage | bcrypt, cost 12, upgraded on login |

Only the first five hex characters of the password's SHA-1 leave the server.
The match against the returned suffixes happens locally. See
`service/security/PwnedPasswordsScreen.java`.

## Recorded deviations

1. **Maximum length is 72 bytes, not "at least 64 characters".** bcrypt only
   hashes the first 72 bytes, and WeldForge refuses longer input rather than
   silently truncating it. For ASCII, 72 bytes is 72 characters, which is above
   64. For passwords that are mostly 3-byte UTF-8 characters, the cap is 24
   characters. Lifting it would mean pre-hashing before bcrypt, which changes
   the stored format for every user. It is not worth that for a limit
   practically no one reaches.
2. **Screening fails open.** If the corpus cannot be reached (timeout, non-200,
   egress refused), the password is **accepted**, with a WARN log and
   `sso.password.breach_check{outcome="unavailable"}` incremented. 800-63B's
   SHALL is unconditional. The alternative is that an outage of a third-party
   service blocks every registration and password reset on the platform. The
   counter is how an operator notices screening has quietly stopped. Alert on
   it.

## Consequences

- Existing passwords are unaffected. The policy applies when a password is
  set: registration, change and reset.
- "Correct horse battery staple" is accepted; `Password1!` is refused.
- To a non-specialist reviewer the defaults can read as weaker. This record,
  and `docs/security/configuration-reference.md`, are the answer to that
  question.
- An air-gapped deployment sets
  `app.security.password.breach-check.enabled=false`. That logs a WARN at boot,
  and the deployment loses the control.

## Reversal conditions

- **Composition rules:** a customer contract or regulator that mandates them.
  Re-enable them per deployment, and record the deviation in the conformance
  statement.
- **Fail-open:** if `unavailable` becomes a meaningful fraction of checks, move
  to a locally mirrored corpus (the range data is downloadable). Then a
  failure is our own outage, and failing closed becomes reasonable.
- **72-byte cap:** only if pre-hashed bcrypt (or a move to Argon2id) is adopted
  for other reasons.
