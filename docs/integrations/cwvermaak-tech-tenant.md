# The `cwvermaak-tech` tenant — one login for the in-house apps

`cwvermaak-tech` is the shared WeldForge tenant for the in-house applications under
`CWVermaak/Tech`. One identity signs in to all of them.

| | |
|---|---|
| Deployed issuer | `https://sso.weldforge.org/t/cwvermaak-tech` |
| Local issuer | `http://lvh.me:8076/t/cwvermaak-tech` |
| Hosted login (local) | `http://cwvermaak-tech.lvh.me:8076/login/` |
| Provisioning | `weldforge/scripts/provision-cwvermaak-tech-local.sh` |

## Who is in it, and who deliberately is not

**In:** CastForge, KeyCrypt, NoteForge, Clepsydra, Sentinel — internal tooling, used by
the same handful of people.

**Out, on purpose:** Wellspring (`wellspring`), Lyceum (`lyceum`) and Oggend-Boodskap
(`oggendboodskap`) each keep their own tenant. They serve their own end users, and
multi-tenancy is precisely the thing that keeps those user populations out of ours.
Wellspring in particular has its own admin, its own `SUPERADMIN` role and a running local
stack; folding it in would mix populations and break its provisioning for no benefit.

**Needs nothing:** SignalForge is a multi-tenant resource server that resolves the issuer
per request from `WELDFORGE_ISSUER_BASE`, so it already accepts this tenant's tokens
without a client of its own.

## Registered clients

| Client | Type | Grants | Redirect URI | PKCE |
|---|---|---|---|---|
| `castforge-console` | confidential | authorization_code, refresh_token | `http://localhost:8090/login/oauth2/code/weldforge` | yes |
| `castforge-edge` | confidential | client_credentials | — | no |
| `clepsydra` | confidential | authorization_code, client_credentials | `http://localhost:8080/login/oauth2/code/weldforge` | yes |
| `keycrypt` | confidential | authorization_code, refresh_token, client_credentials | `http://localhost:8081/login/oauth2/code/weldforge` | yes |
| `keycrypt-web` | **public** | authorization_code, refresh_token | `http://localhost:5173/callback` | yes |
| `keycrypt-desktop` | **public** | authorization_code, refresh_token | `http://127.0.0.1/callback` | yes |
| `noteforge` | confidential | authorization_code, client_credentials | `http://localhost:8088/login/oauth2/code/weldforge` | yes |
| `sentinel` | confidential | authorization_code, refresh_token | `http://localhost:3000/login/oauth2/code/weldforge` | yes |

Redirect URIs are **exact-match**, so the deployed clients need their own entries. The
one exception is a loopback IP URI, where the port is ignored (RFC 8252 §7.3) — see
*Native apps and the loopback port* below. That is why `keycrypt-desktop` registers
`http://127.0.0.1/callback` with no port.

## The rule that decides client ids: `aud` is the client id

WeldForge stamps `aud` with the client id, and it has **no `resource` or `audience` request
parameter**. A relying party that validates an expected audience therefore constrains what
its client may be called:

- KeyCrypt validates `keycrypt.oidc.expected-audience`, so its backend client is
  `keycrypt` — not `keycrypt-auth`.
- NoteForge validates `noteforge.weldforge.audience`, so its client is `noteforge`.

The corollary bites when one API is called by two clients: a browser client and a backend
client necessarily present *different* audiences, and nothing on the wire can reconcile
them. KeyCrypt handles this by accepting a set — `KEYCRYPT_OIDC_EXPECTED_AUDIENCE=keycrypt,keycrypt-web`
— rather than loosening the check to "any audience". Any new service with the same shape
needs the same decision made deliberately.

Cross-app replay is blocked by this too: a `keycrypt` token presented to CastForge fails
CastForge's audience check even though both live in this tenant. Sharing a tenant is not
sharing a trust boundary.

## Native apps and the loopback port

An Electron or CLI client cannot reserve a TCP port in advance — another process may
hold it — so RFC 8252 §7.3 has it ask the OS for an ephemeral port at login and build
`http://127.0.0.1:{port}/callback` from whatever it gets. Exact matching cannot work
against that: the port differs on every run.

WeldForge therefore compares loopback IP redirect URIs **ignoring the port**, and
everything else exactly. Register the URI without a port and any port matches:

```
keycrypt-desktop → http://127.0.0.1/callback
```

The exception is deliberately narrow. It covers `127.0.0.1` and `[::1]` only, never
`localhost` — RFC 8252 §8.3 warns the *name* can resolve somewhere else entirely (a
hosts-file entry, a DNS search domain), which would hand the authorization code to
another machine. The IP literal cannot be redirected that way. Scheme, host, path and
query still have to match exactly; a client registered on `http://localhost:5173/callback`
keeps working and keeps exact matching, port included.

## Behaviour of this WeldForge worth knowing

Findings from wiring the five apps up, all verified against a running instance:

**Dynamic registration is not open.** `POST /t/{slug}/oauth2/register` is documented as
public RFC 7591, and `SecurityConfig` permits it — but `OidcClientService.create` calls
`requireTenantAdmin()`, so an anonymous relying party gets `403`. Register through
`/api/admin/oidc/clients` instead. Either the guard or the onboarding guide is wrong.

**`requirePkce` is enforced, but only after sign-in.** The check lives in
`OidcAuthorizationService.issueAuthorizationCode`, which runs once the user is
authenticated. An unauthenticated probe therefore sees a normal redirect to the login page
and looks fine. A relying party that omits `code_challenge` fails at the point a code would
be minted — which presents as a login failure rather than a configuration one. Spring adds
PKCE automatically only for *public* clients, so confidential clients need
`OAuth2AuthorizationRequestCustomizers.withPkce()` wired in explicitly.

**The token endpoint resolves the code before authenticating the client.** A bad code
returns `invalid_grant` whether or not the client secret is correct. Good design — it
denies an attacker a client-secret oracle — but it also means a client secret cannot be
verified without a genuine authorization code. For a client that also holds
`client_credentials`, exchange one and check for `invalid_client`.

**Tokens report how the user authenticated.** Access and ID tokens carry an RFC 8176
`amr` claim describing the factors the login actually exercised — `["pwd"]` for a
password alone, `["pwd","otp","mfa"]` for a TOTP or backup code, `["pwd","sms","mfa"]`,
`["pwd","hwk","mfa"]` for WebAuthn. It travels from the login through the authorization
code (and through the refresh-token family) rather than being recomputed at token time,
because enrolment says what a user *could* have used and `amr` has to say what they
*did*. A relying party can therefore require a phishing-resistant factor: KeyCrypt does
exactly this (`keycrypt.oidc.required-amr`, default `hwk,swk`). Tokens minted from a
session or refresh family that predates the column carry no `amr` at all, and self-heal
on the next login. A tenant custom claim named `amr` is dropped — config must not be
able to assert a factor the user never presented.

**A `client_credentials` token carries no `amr`,** by design: the claim describes how a
*person* proved who they are, and that grant has no person in it. A relying party that
gates on `amr` is therefore gating out machine clients — which is usually what it wants,
but it means a service-to-service caller needs a different path (KeyCrypt uses its own
§14.1.1 workload token).

**`/api/auth/register` is rate-limited per IP with an hour-long window.** Re-provisioning
that goes through it is a coin toss; seed the bootstrap admin by SQL instead.

**Client secrets are returned exactly once,** on create or rotate. The provisioning script
deletes and recreates a client rather than trying to read a secret back.

## Relying-party checklist

1. Register the client with the id its audience check expects.
2. Configure endpoints **explicitly**, not via `issuer-uri`. Spring Boot resolves
   `issuer-uri` by fetching discovery during context refresh, so the app will not boot —
   and its tests will not run — whenever WeldForge is down. Pin the issuer on the decoder
   instead of losing the check.
3. Send PKCE even from a confidential client.
4. Pin issuer *and* audience on every token you accept.
5. Keep the local env file git-ignored; the deployed default stays in `application.yml`.
6. For anything in a container, remember `lvh.me` resolves to `127.0.0.1` — the
   container's own loopback. Map it with `extra_hosts: ["lvh.me:host-gateway"]` rather
   than rewriting the issuer, which must stay byte-identical to the minted `iss`.
