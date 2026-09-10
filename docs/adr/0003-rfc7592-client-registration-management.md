# ADR 0003 — RFC 7592 client registration management: read and delete only

**Status:** Accepted · 2026-09-10 · CONF-8.2 (read/delete implemented by CONF-4.3, Sprint 3)

## Context

RFC 7591 dynamic registration returns a `registration_client_uri` and a
`registration_access_token`. RFC 7592 defines what a client does with them:
`GET` to read its registration, `PUT` to update it, `DELETE` to deregister.

Before Sprint 3, WeldForge returned the URI in every registration response and
served nothing there: a 404 handed out inside a success response. CONF-4.3
added a hashed registration access token (`V52`) and the `GET` and `DELETE`
endpoints on `/t/{slug}/oauth2/register/{client_id}`. Every failure there
returns the same 403 with no detail, so a caller cannot use the endpoint to
learn which client ids exist.

## Decision

Support RFC 7592 **read and delete**. Do **not** support **update** (`PUT`).
Changes to a registered client go through the tenant admin API
(`/api/admin/oidc/clients`) or the admin portal.

## Reasoning

- **Update is where the risk is.** An RFC 7592 `PUT` replaces the client's
  metadata wholesale. That includes `redirect_uris`, the single most
  security-sensitive field a client has, on the authority of a bearer token
  the client holds. On a platform where registration is open (a product
  question still unresolved), self-service redirect changes would let anyone
  holding a leaked registration access token repoint a client's authorization
  codes.
- **Read and delete close the actual defect.** The complaint was a URI that
  404'd. Read lets a client confirm its registration; delete lets it clean up
  after itself. Neither can widen what the client is allowed to do.
- **Admins already have a controlled path** for legitimate changes, and it is
  audited.

## Consequences

- A client library that calls `PUT` on the registration URI gets a 405. Its
  owner has to ask a tenant admin, or re-register.
- Discovery does not advertise update capability. RFC 7592 has no discovery
  field for it, so this is stated in the onboarding guide.

## Reversal conditions

Implement `PUT` if any of these happens:

- the decision on open registration lands on "closed" (authenticated or
  admin-initiated only), which removes the leaked-token scenario;
- updates are restricted to fields that cannot redirect a code
  (`client_name`, `logo_uri`, contacts), with `redirect_uris` changes still
  admin-only;
- a customer's automation depends on it and accepts that restriction.
