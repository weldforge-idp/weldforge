# Security policy

WeldForge is an identity platform. A vulnerability here is a vulnerability in
everyone who signs in through it, so we would much rather hear from you than
not.

## Reporting a vulnerability

**Use GitHub private vulnerability reporting:**
[Report a vulnerability](https://github.com/weldforge-idp/weldforge/security/advisories/new).

That opens a private thread with the maintainers. It is the preferred route
because it needs no shared mailbox, keeps the report out of public issues until
there is a fix, and gives you a CVE and credit at the end if you want them.

Please do **not** open a public issue or pull request for a security problem. A
public report starts a clock for every operator running this code, including
self-hosters we cannot contact.

### What to expect

| | |
|---|---|
| First response | Within **3 working days** |
| Triage decision (accepted / needs info / not a vulnerability) | Within **10 working days** |
| Fix for a confirmed High or Critical | Prioritised over feature work |
| Credit | Yours by default, anonymous on request |

WeldForge is maintained by a small team in South Africa (SAST, UTC+2). We do not
run a bug-bounty programme and cannot offer payment — we can offer a fast, real
response from someone who understands the code.

## Scope

**In scope**

- This repository: `weldforge-auth`, `weldforge-admin-portal`, `weldforge-www`.
- The hosted service at `https://sso.weldforge.org` and its per-tenant
  subdomains.
- The marketing site at `https://www.weldforge.org`.

**Out of scope**

- Findings that require a compromised device, a malicious browser extension, or
  physical access.
- Missing hardening headers with no demonstrated impact, absent SPF/DMARC on
  non-mail subdomains, or automated-scanner output with no working proof.
- Denial of service through volume. We know a single node can be exhausted; you
  do not need to prove it, and see the testing rules below.
- Anything already recorded as a known, accepted risk in
  [`docs/security/hardening-backlog.md`](docs/security/hardening-backlog.md) or
  [`docs/security/review-2026-09-14.md`](docs/security/review-2026-09-14.md).
  Please do check those first — several items you might find are already
  documented with a decision and a reason.

## Rules for testing — read this part

`sso.weldforge.org` is **live production carrying real tenants and real end
users**, some belonging to organisations other than ours. Testing against it can
lock out or expose people who never agreed to be part of your research.

So:

- **Do not test against production tenants.** Create your own tenant, or use the
  public `leap` demo tenant, whose protocol endpoints are deliberately open:
  `https://sso.weldforge.org/t/leap/.well-known/openid-configuration`.
- **Do not run load, stress or fuzzing against the hosted service.** If you need
  volume to prove something, run it against your own deployment —
  `docker compose up` gives you the whole platform locally.
- **Never access, modify or retain another tenant's data.** If a flaw exposes
  data, stop, capture only what is needed to prove it, and tell us.
- **Do not attempt social engineering** of our staff, customers or suppliers.

Self-hosting is the right way to test invasively, and it costs you nothing.

## Safe harbour

If you follow the rules above, act in good faith, and give us a reasonable
chance to fix the issue before disclosing it, we will not pursue or support any
legal action against you, and we will say so publicly if anyone else does.

If you are unsure whether something is in scope, ask first via the reporting
link. An early question is never held against you.

## Disclosure

We aim to publish an advisory once a fix is available, crediting you. If a fix
is going to take longer than **90 days**, we will tell you why and agree a date
with you rather than let it drift silently.

Because the code is source-available, self-hosters need to be able to act on a
fix. Advisories are published on this repository's
[Security tab](https://github.com/weldforge-idp/weldforge/security), which you
can subscribe to with *Watch → Custom → Security alerts*.

## Supported versions

We ship from `main` and there is no long-term-support branch. **The supported
version is the latest release**; if you self-host, track it. Container images
are published per commit as
`ghcr.io/weldforge-idp/weldforge-auth:sha-<short-sha>`.

## If you operate a WeldForge deployment

Two things worth knowing, both documented in the repository:

- **`app.jwt.secret` is a single shared HMAC** with no key ring, so rotation is
  currently all-or-nothing across every consumer that verifies with it. Plan
  accordingly — `docs/runbooks/key-rotation.md`.
- **Rate limiting is per-instance.** Running more than one replica multiplies
  every configured limit; see `docs/scaling.md` in the infrastructure repo
  before scaling out.

---

*This file is mirrored by [`/.well-known/security.txt`](https://www.weldforge.org/.well-known/security.txt)
(RFC 9116). If you change the contact details here, change them there too — and
note that `security.txt` carries an `Expires` date that has to be renewed.*
