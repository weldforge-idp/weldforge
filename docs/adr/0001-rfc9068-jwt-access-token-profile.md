# ADR 0001 — RFC 9068 JWT access-token profile: declined

**Status:** Accepted · 2026-09-10 · CONF-8.2

## Context

RFC 9068 profiles JWT access tokens so that any resource server can validate
any authorization server's tokens the same way. It requires the header
`typ: at+jwt`, an `aud` naming the **resource** the token is for, and the claims
`iss`, `exp`, `sub`, `client_id`, `iat` and `jti`.

WeldForge's OIDC access tokens (`OidcTokenService.buildAccessToken`) are
RS256-signed JWTs with `kid`, `iss`, `sub`, `client_id`, `scope`, `iat`, `exp`,
`amr` and `roles`. They differ from RFC 9068 in three ways:

| RFC 9068 | WeldForge |
|---|---|
| header `typ: at+jwt` | no `typ` |
| `aud` = the resource server | `aud` = the **client_id** |
| `jti` required | no `jti` |

WeldForge has never claimed RFC 9068 conformance.

## Decision

Do not adopt RFC 9068.

## Reasoning

- **`aud` semantics are the breaking part.** Every relying party that validates
  its own access tokens today checks `aud == client_id`; Spring Security's
  resource-server defaults and the Tech Metropolis services do exactly that.
  Changing `aud` to a resource identifier breaks each of them at once, and
  WeldForge has no resource-indicator registry (RFC 8707) to supply the value.
- **No resource server in the estate needs it.** The profile pays off when a
  resource server trusts several authorization servers and wants one
  validation path. Here each tenant's tokens are consumed by that tenant's own
  relying parties.
- **The security properties it adds are available otherwise.** Token-type
  confusion (an ID token presented as an access token) is already refused:
  UserInfo and introspection check `token_type` (B-OIDC-3, F18). Revocation is
  by token hash, so it does not need `jti`.

## Consequences

- A resource server written against RFC 9068 will not validate WeldForge access
  tokens without configuration: accept no `typ` and accept `aud == client_id`.
- Replay detection keyed on `jti` is not possible. Introspection plus short
  lifetimes are the control.

## Reversal conditions

Adopt RFC 9068, as a **per-client opt-in** with the current format the default,
if any of these happens:

- a customer's resource server requires `at+jwt` (API gateways increasingly do);
- WeldForge adds resource indicators (RFC 8707), which gives `aud` a correct
  value;
- a resource server has to trust tokens from more than one issuer.

`typ` and `jti` could be added on their own at any time. They break nothing,
and are the cheap first step if the demand appears.
