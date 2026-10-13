# What an MCP client needs from WeldForge

**Status:** research and design. The Built column is kept current as items ship; items
1, 2 and 3 of the order in §8 are now in production.
**Written:** 2026-10-12. **Last updated:** 2026-10-13.
**Sources read:** the Model Context Protocol specification revision **2026-07-28**
(`basic/authorization`, `.../authorization-server-discovery`, `.../client-registration`),
RFC 8414, RFC 8693, RFC 8707, RFC 9207, RFC 9728, and the
`draft-ietf-oauth-client-id-metadata-document-00` referenced by the spec.
**Prompted by:** counter.shot's `WELDFORGE-HANDOVER.md` §3 and §14, relayed by that
project's session. This document is WeldForge's own reading of the specification, not a
restatement of the hand-over, and it disagrees with the hand-over in four places.

---

## 1. Who must do what

MCP splits the work across three parties, and most of the hard requirements land on the
two that are not us. Getting this wrong wastes effort, so it is first.

| Role | Who, here | Carries |
|---|---|---|
| Authorization server | **WeldForge** | OAuth 2.1, metadata discovery, issuing tokens |
| Resource server ("MCP server") | **counter.shot's agent-service** | RFC 9728 metadata, `WWW-Authenticate`, audience validation |
| MCP client | the outside assistant | RFC 8707 `resource`, PKCE, RFC 9207 `iss` validation |

Normative requirements placed on the **authorization server** by the 2026-07-28 revision,
in full:

1. **MUST** implement OAuth 2.1 for confidential and public clients.
2. **MUST** provide *at least one* of RFC 8414 metadata **or** OpenID Connect Discovery 1.0.
3. **SHOULD** support Client ID Metadata Documents.
4. **MAY** support Dynamic Client Registration — which is **deprecated**.
5. **SHOULD** include `iss` on authorization responses (RFC 9207); any server that does
   **MUST** advertise `authorization_response_iss_parameter_supported`.

That is the whole list. Everything else counter.shot needs from us follows from what its
own connector must do, not from a requirement on us.

---

## 2. Where WeldForge stands today

| Item | Required of us | Built |
|---|---|---|
| OAuth 2.1 core (PKCE S256, exact redirect match, rotation) | MUST | **Yes** |
| A discovery document per tenant | MUST (one of two) | **Yes**, OIDC Discovery |
| Discovery reachable at the URLs a client tries | implied by the MUST | **Yes** — PR #148, `sha-04ef2dd` |
| RFC 9207 `iss` + advertisement | SHOULD | **Yes**, already |
| `code_challenge_methods_supported: ["S256"]` | — | **Yes** |
| Resource indicators (RFC 8707) | not on us, but see §4 | **Yes**, opt-in — PR #149, `sha-f64102c` |
| Client ID Metadata Documents | SHOULD | **No** |
| Dynamic Client Registration | MAY, deprecated | Built, off, instance-wide |
| Token exchange (RFC 8693) | not on us, but see §5 | **No** |
| Scope descriptions | not in the spec at all | **Yes** — PR #150 |

---

## 3. Discovery: the one real defect

Our tenant issuer has a path component:

```
https://counteract-studios.sso.weldforge.org/t/counteract-studios
```

For a path-bearing issuer the specification requires a client to try three URLs **in this
order** and stop at the first metadata document:

| # | URL | Today |
|---|---|---|
| 1 | `/.well-known/oauth-authorization-server/t/counteract-studios` | **200 `text/html`** |
| 2 | `/.well-known/openid-configuration/t/counteract-studios` | **200 `text/html`** |
| 3 | `/t/counteract-studios/.well-known/openid-configuration` | 200 `application/json` |

The first two serve the admin portal. The ingress routes only `/api`, `/t/`, `/saml2`,
`/scim` and `/health` to the backend and sends everything else to the SPA, so every
well-known path outside `/t/` is a 200 that means nothing.

This is the same shape as two defects already on record here: `/actuator/**` answering
200 as HTML, and `/api/auth/**` answering 200 to a bogus app key. **A 200 from this
estate is not evidence that an endpoint exists.** Any conformance probe that checks
status codes will report RFC 8414 as live.

A careful client parses, fails, and falls through to #3. A strict one stops. We should not
be relying on which kind we meet.

**Decision: serve the documents, do not merely 404 them.** 404ing all the way to #3 is
within spec and is the smaller change, but it leaves us failing the first URL every client
tries, forever, for two extra round trips. Serving RFC 8414 metadata at #1 also closes
the "at least one of" MUST with the mechanism the spec names first.

Three parts:

- `/.well-known/oauth-authorization-server/t/{slug}` → RFC 8414 metadata.
- `/.well-known/openid-configuration/t/{slug}` → the existing OIDC document.
- The ingress must route `/.well-known/` to the backend. **That change is in the
  infrastructure repository**, and the application change is inert without it.

The `issuer` in every document must stay byte-identical to the issuer the client used to
build the URL, or the client must reject it. Our existing document already satisfies
this; the new URLs must not drift from it.

---

## 4. Resource indicators (RFC 8707) — WF3

**Where the hand-over overstates.** It calls this "a hard requirement" on us. It is not:
the specification puts `MUST` on the *client* to send `resource`, and on the *MCP server*
to validate that a token's audience is itself. It places no requirement on the
authorization server at all, and states that clients must send the parameter "regardless
of whether authorization servers support it".

**Why we should build it anyway.** The connector MUST reject any token not issued for it.
Today every token's `aud` is the requesting client's id, hard-coded
(`OidcTokenService.java:144`, `:191`). The connector would have to treat its own
`client_id` as its audience, which works only while one client maps to one resource, and
silently stops being true the moment counter.shot's services become a second resource —
which is precisely their plan. So: build it, because the design counter.shot needs cannot
be expressed without it, not because a MUST compels us.

**Hard constraint on the shape.** `aud` has a live dependant: the IntelliSuite tenant's
`intelli-accounting` client requires `aud` to be literally the client id, recorded in this
repo's project memory as a thing not to break. Resource indicators must therefore be
strictly opt-in per request: no `resource` parameter, no change in behaviour, not for any
client and not for any tenant. The hand-over already assumes this; it is written here
because the constraint is invisible from counter.shot's side.

Design:

- `resource` accepted on `/authorize` and `/token`, repeatable per RFC 8707.
- Registered per client, as an allow-list. A `resource` outside it fails `invalid_target`
  (RFC 8693 §2.2.2 and RFC 8707 §2 both name it).
- When present and permitted, `aud` becomes the resource; when absent, `aud` stays the
  client id, unchanged.
- The authorization request's `resource` is bound to the code and must match at the token
  request, or the token request fails.

---

## 5. Token exchange (RFC 8693) — WF5

**Where the hand-over overstates, again.** It says token exchange is "now required by the
protocol itself". What the specification actually forbids is *passthrough*: an MCP server
"**MUST NOT** pass through the token it received", and a token used at an upstream API
"is a separate token, issued by the upstream authorization server". Token exchange is one
way to obtain that separate token. It is a good way, and probably the right one here. It
is not mandated, and we should not record it as a compliance obligation when it is a
design choice.

**Two divergences from the hand-over's wire shape, both of which favour the RFC.**
counter.shot asked to be told if WeldForge will differ, and it will:

1. **Error codes.** The hand-over maps "the person's sign-in no longer stands" to
   `invalid_grant`. RFC 8693 §2.2.2 says `invalid_request` **MUST** be used when the
   `subject_token` is invalid or unacceptable under policy, and `invalid_target`
   **SHOULD** be used for an unissuable `resource`. It does not define `invalid_grant` for
   this endpoint. We should follow the RFC, which means the stand-in's mapping changes.
2. **The `act` claim.** The hand-over proposes `act: {"client_id": "countershot-agents"}`.
   RFC 8693 §4.1 does not forbid it — members of `act` are simply "claims that identify the
   actor" — but it discusses identification in terms of `iss` and `sub`, and every library
   that reads `act` looks for `sub`. Recommend `act: {"sub": "countershot-agents"}`, with
   `client_id` alongside it if counter.shot wants it. Costs them nothing now and avoids an
   interop surprise later.

**The prerequisite that is not WF5.** counter.shot expects an exchanged token to live
about 60 seconds. There is no per-client or per-grant access-token lifetime:
`OidcClient` carries `refresh_token_ttl_s` only, and the access lifetime resolves from the
tenant then the instance (`OidcTokenService.resolveAccessTtlSeconds`). The shortcut —
dropping the tenant's access TTL — would apply to every client in the tenant including the
admin portal's own sessions. A per-grant lifetime is separate work and comes first.

**Policy, unchanged from the hand-over and agreed:** a per-client "may act for people"
flag, default off; requested scope within both the subject token's scope and the client's
registered scopes; refusal for another tenant's token, a deleted user, withdrawn consent,
or an already-delegated subject token. A security review before it is switched on.

---

## 6. Scopes in words — WF6

Not an MCP requirement. It is a consent-quality requirement, and it is ours regardless of
counter.shot: the screen currently prints raw scope strings as list items
(`OidcAuthorizationController.renderConsent`), so a person approving `board.view` is
approving a string. For WF5 especially, the consent screen is the only place a person
agrees to be acted for, and "card.decide" is not a sentence anyone can consent to.

Design: a registered scope per tenant with a description per language (English and German
asked for), shown on the consent screen, and listed in `scopes_supported`. First scope
needed: `board.view`.

**Shipped** in PR #150 (`V66`). As built:

- `oidc_scopes` is **per tenant, not per client**. A scope means one thing inside a
  tenant, and a tenant routinely hosts several clients; registering the meaning once is
  what stops two clients explaining the same permission two different ways.
- Descriptions are a JSONB map of language tag to text. Resolution tries the full tag,
  then its primary subtag, then English, then nothing — so `de-AT` finds a `de`
  description and a tenant writes one German description, not one per region. The
  language comes from the browser's `Accept-Language`, first tag listed, q-values
  ignored.
- The consent screen shows the words **with the scope name still beside them**, so the
  person reads what they are agreeing to and a developer can still tell which scope it
  is. A scope with no registered description renders exactly as it did before, so
  registering a description for one scope does not change how the others are presented.
- `scopes_supported` unions the tenant's registered names with the standard six.
  Leaving them out would be the same untruth the rest of that document was fixed for: a
  conformant library validates its request against the list and refuses to ask for a
  scope that is missing from it.
- The registry **explains** scopes, it does not grant them. What a client may ask for is
  still the client's own registered scope list; a row here only supplies the words.
- Admin surface at `/api/admin/oidc/scopes`: `GET` list, `POST` upsert one, `PUT`
  replace the whole registry, `DELETE ?name=`. The name travels in the body or the query
  string rather than as a path segment, because an RFC 6749 scope token may legally
  contain a slash. Every write demands a tenant admin and is audited — editing these
  words changes what a person is told they are agreeing to.
- **Not built:** a portal screen. The API is the whole of it today, the same as the
  `resources` list from #149. Worth doing before a tenant other than counter.shot needs
  it.

Note the interaction with the spec: `scopes_supported` on the **resource** is the MCP
server's document, not ours, and the spec tells resource servers to keep it minimal and
to drive the rest through `WWW-Authenticate` scope challenges. Ours stays the
authorization server's list.

---

## 7. Client ID Metadata Documents — WF7b

**This is where I would push back hardest on sequencing.**

It is a **SHOULD**, not a MUST, and it rests on
`draft-ietf-oauth-client-id-metadata-document-**00**` — the first published revision of an
unapproved IETF draft. Building it means an identity provider fetching an
attacker-supplied HTTPS URL during an authorization request and trusting the JSON it
finds. The spec's own security section is about exactly that. The required defences are
not optional detail: SSRF protection against private and link-local addresses and
redirects to them, a response size cap, a timeout, cache-header handling, and showing the
redirect host on the consent screen so a person can see where they are being sent.

That is a meaningful amount of security-sensitive surface for a draft that may change
before it is an RFC, on an identity provider that is also in the middle of an OpenID
certification effort.

**Recommendation:** do it, but last, and deliberately — after the discovery fix, resource
indicators and scope descriptions, which are all smaller, standards-stable, and useful on
their own. If counter.shot needs a client before then, pre-registration is the specified
and supported answer (`client-registration` §Pre-registration), it is what every other
tenant here already uses, and it needs nothing new from us.

Dynamic Client Registration should not be switched on to fill the gap. It is deprecated by
the spec, our implementation is instance-wide rather than per tenant, and turning it on
would let anyone on the internet create clients in any tenant.

---

## 8. Order

| # | Item | Why here | Size |
|---|---|---|---|
| 1 | ~~Discovery at the path-inserted URLs (§3)~~ **done, #148** | Blocks every client. Standards-stable. Needs the infra repo too | Small |
| 2 | ~~Resource indicators (§4)~~ **done, #149** | Everything about audiences depends on it. Opt-in, so no blast radius | Medium |
| 3 | ~~Scope descriptions (§6)~~ **done, #150** | Consent quality, ours anyway, prerequisite for honest WF5 consent | Medium |
| 4 | Per-grant access-token lifetime (§5) | Prerequisite of WF5, useful alone | Small–medium |
| 5 | Client ID Metadata Documents (§7) | SHOULD, draft-00, SSRF surface | Medium |
| 6 | Token exchange (§5) | The large one. Security review before switch-on | Large |

counter.shot can build and test against a pre-registered client as soon as **1** lands.

---

## 9. What we owe counter.shot

Told to that session already: the two overstatements in §4 and §5, the `invalid_request`
and `act.sub` divergences in §5, the 60-second lifetime constraint, and that their
stand-in handles `POST /t/<slug>/token` while the real endpoint is
`/t/<slug>/oauth2/token`.

Still to tell them, once decided: whether `resource` values are per region and tenant as
they propose, and the final `act` shape.
