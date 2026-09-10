# ADR 0002 — RFC 9207 authorization server issuer identification: adopted

**Status:** Accepted · 2026-09-10 · CONF-8.2 (implemented by CONF-1.4, Sprint 3)

## Context

RFC 9207 has the authorization server put an `iss` parameter on every
authorization response, and advertise
`authorization_response_iss_parameter_supported: true`. A client that talks to
several authorization servers checks `iss` before redeeming the code. That
defeats the **mix-up attack**, in which an attacker-controlled server gets a
client to send it a code that another server issued.

The conformance review recorded RFC 9207 as absent. At the time it was an
unrecorded gap rather than a decision.

## Decision

Adopt RFC 9207. `iss` is on every authorization response, success and error
alike, and discovery advertises the parameter.

## Reasoning

WeldForge is the deployment shape the attack is built for. Every tenant is a
distinct issuer (`https://sso.weldforge.org/t/{slug}`) behind **one** hostname.
A relying party integrated with two tenants — a common case for a vendor
serving several customer organisations — cannot tell from the redirect alone
which tenant answered. The cost is one query parameter.

## Consequences

- Clients that ignore `iss` are unaffected.
- Clients that check it must compare against the tenant issuer from that
  tenant's discovery document, not a hard-coded host.

## Reversal conditions

None expected. Withdrawing the parameter would reintroduce the mix-up
exposure. Revisit only if a later RFC supersedes 9207.
