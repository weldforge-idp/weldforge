# Administering OIDC clients

How a relying party is registered, corrected and retired, and which fields
cannot be changed once a client exists.

Audience: whoever operates a WeldForge tenant. Everything here is reachable
from the admin portal's **Tenants** page, under the tenant's own row, and from
`/api/admin/oidc/clients` for anything scripted.

---

## The short version

| Task | How |
|---|---|
| Register a client | Tenants → the tenant's row → *Register a new OIDC client* |
| Correct one | the **edit** (pencil) action on its row |
| New secret | the **rotate** action — confidential clients only |
| Retire one | the **delete** action |

Registration is the only step with a decision in it. The rest is mechanical.

---

## Public or confidential

This is the field that determines everything else, and it cannot be changed
afterwards.

**Confidential** — the app has a server that can keep a secret. It
authenticates to the token endpoint with `client_secret_basic`. Server-rendered
web apps and backend services.

**Public** — the app cannot keep a secret, because its code is on the user's
device. Browser SPAs and native apps. PKCE is forced on and no secret is issued;
one is generated internally and never surfaced, because there is nowhere safe
to put it.

Choosing wrongly means creating a new client. Flipping the flag is refused: a
confidential client turned public would silently lose secret authentication,
and a public one turned confidential would be handed a secret the app has no
way to use.

---

## Web origins — required for browser clients

**A public client whose redirect URI is a real `http(s)` host must register a
web origin.** Registration is refused without one.

The refusal is deliberate, and it is protecting you from a much worse failure.
A browser client runs the entire flow with `fetch`: discovery, JWKS, the PKCE
token exchange. All of those are cross-origin to the tenant's OIDC endpoints,
and the CORS allow-list is built from the tenant's clients' `webOrigins`.
Register none and every one of those calls is blocked — and a browser reports
a blocked fetch as a generic network error, so the symptom is a **sign-in
button that does nothing at all**, with nothing in any log on either side.

That is not hypothetical. `keycrypt-web` was registered without one on
2026-09-20 and its sign-in was inert for two days before anyone traced it to
CORS.

The portal derives the origin from the redirect URI when you leave the field
blank, so the common case needs no typing. Set it explicitly when the app is
served from somewhere other than its redirect URI's origin.

**Native clients are exempt, correctly.** An RFC 8252 app redirects to a
loopback address or a private-use scheme, makes no cross-origin browser calls,
and has no origin to register. Production holds several such clients.

---

## Redirect URIs

Compared exactly, with one exception.

**Loopback redirect URIs ignore the port**, per RFC 8252 §7.3, because a native
app asks the OS for an ephemeral port at sign-in and cannot know it in advance.
This applies to the **IP literals only** — `127.0.0.1` and `[::1]` — never to
`localhost`. A hostname can be redirected elsewhere by a hosts-file entry, a
DNS search domain or a hostile resolver, which would send the authorization
code off the machine. A client registering `http://localhost:3000/cb` still
works; it just gets exact matching, port included, and an ephemeral-port client
will never authenticate.

Register `http://127.0.0.1/callback` — no port — as the tidy way to say "any
ephemeral port on this path".

Everything else is compared exactly: scheme, host, path and query. The path is
compared raw and not normalised, so `/cb/../evil` does not match `/cb`.

---

## Post-logout redirect URIs

Where RP-initiated logout is allowed to return the user. Registering none means
the client cannot pass a `post_logout_redirect_uri` at all: the request is
refused with `invalid_request` and the user is left on an error page rather
than back in the app.

Register the exact URI the app will send. A bare origin and the same origin
with a path are different values, and the `/callback` your app already uses for
sign-in is not automatically allowed for sign-out.

---

## Refresh-token lifetime

Resolution is **client → tenant → instance default**.

Leave it blank to inherit. Set it only when this client genuinely differs from
the others on the tenant — a native app that has to work offline for a
fortnight, for example, when the browser clients beside it should not.

Before this field existed the only lever was the instance-wide default, so one
consumer's requirement moved every session on the deployment, vault sessions
included.

---

## What cannot be changed

Three fields are refused on update. Each would invalidate tokens already
issued, so each means a new client:

- **`client_id`** — it is the `aud` of every token in circulation and the
  identifier every deployed consumer has configured.
- **`client_secret`** — rotation has its own action, deliberately. Folding it
  into a general edit would make every configuration change a potential outage.
- **public / confidential** — see above.

**Deleting and recreating is not a workaround.** It mints a new secret, and it
drops the refresh-token families bound to the old row, so every signed-in user
is logged out. Prefer the edit action; when you genuinely need a new client,
plan the cutover.

---

## Scopes and grant types

Scopes are enforced only when the client registers a non-empty list, in which
case a request is restricted to that list plus the standard OIDC scopes
(`openid`, `profile`, `email`, `address`, `phone`, `offline_access`), which are
always permitted.

**Grant types are per client and matter at registration.** A refresh token is
issued on code exchange only when the client's own `grant_types` contains
`refresh_token` — handing one to a client that never asked for it widens the
blast radius of a leak for nothing. Add it up front for any app that needs to
stay signed in.

---

## Roles in tokens

A token carries a `roles` claim: the user's single WeldForge role, plus
`SUPERADMIN` where it applies.

**There is no `groups` claim.** SCIM groups and group-to-role mappings exist,
but they map an upstream IdP group onto a WeldForge role during provisioning
and are never emitted as a claim. A relying party with its own role model
usually names a WeldForge role after what it needs (`myapp:admin`) and reads
`roles`.

Two limits to design around: a user holds **one** role, so a scheme needing
several strings does not fit; and the role is tenant-global, so every relying
party in that tenant sees it. A multi-valued `groups` claim sourced from SCIM
membership is on the backlog — see
`docs/security/hardening-backlog.md`.

---

## Customising the login and password-reset forms

Every tenant's auth pages can be branded so they feel native to the adopter's
site. Set it in the admin portal under **Tenants → Branding**, or with
`PUT /api/admin/tenants/{id}` carrying a `branding` JSON object.

Supported `tenants.branding` keys: `logoUrl`, `primaryColor`,
`primaryDarkColor`, `accentColor`, `bgColor`, `bg2Color`, `textColor`,
`displayFont`, `sansFont`, `tagline`, `eyebrow`, `headline`, `ctaLabel`, plus
`displayName`.

Per-tenant feature toggles: `registrationEnabled`, `passwordRecoveryEnabled`,
`emailVerificationRequired`, `returnToCallerEnabled`.

**The tenant slug determines the auth URL.** Each tenant lives at its own
subdomain —
`https://{slug}.sso.weldforge.org/{login,forgot-password,reset-password,register,verify-email}`
— so browsers and third-party password managers treat each tenant as a distinct
site. The legacy `?tenant=<slug>` query-parameter form was removed; see
`docs/auth-url-spec.md`. The path prefix `/t/{slug}/...` is reserved for
OIDC and SAML deep-link endpoints and stays on the apex host.
