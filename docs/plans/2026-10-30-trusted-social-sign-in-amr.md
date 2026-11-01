# Trusted social sign-in: an asserted `amr` for federated sessions

**Status:** IMPLEMENTED 2026-11-01 on `feat/trusted-social-sign-in-amr`.
Specified 2026-10-30 from the infrastructure session. Owning service:
`weldforge-auth`.

**What changed against the specification as written**, so the next reader is not
misled by it:

1. **The `hd` gate already half-existed.** `tenants.allowed_email_domains`
   (V63) is checked against Google's `hd` by `EmailDomainPolicy.permits`. It is
   *not* sufficient, and §3 stands — but for a reason the specification did not
   state: `permits` returns true when `hd` is **absent**, which is right for an
   email allow-list and necessary for the providers that never send one. A
   consumer Google account can be registered on any address, including one in a
   corporate domain; it carries no `hd`, so it passes that list while belonging
   to no organisation. `required_hd` is therefore a second, stricter check that
   demands *presence* and a match, implemented as
   `EmailDomainPolicy.satisfiesRequiredHostedDomain` beside the existing one.
2. **`swk` had to be added to `AuthenticationMethods`.** §5 says asserted values
   must already be defined there, while §3 and §5 both reference `swk`; it was
   not defined, because nothing this server does produces it. It is now a
   constant documented as assertable-only.
3. **The upsert validates the MERGED row, not the payload.** §5 implied
   validating the request. That is wrong for an upsert where an omitted field
   means "leave it": setting `asserted_amr=hwk` while omitting `required_hd`
   would be refused though the row already carries the gate, and — the dangerous
   one — clearing `required_hd` while omitting `asserted_amr` would pass and
   leave a stored `hwk` assertion with nothing behind it.
4. **The gate is enforced again at issue time.** §6 put it only in the upsert.
   A row can also arrive by hand, so `AuthService` re-validates and falls back
   to asserting nothing, loudly, rather than trusting the row.
5. **The admin portal needed the two fields.** §10 assumes the row is created
   "through the admin portal" but §6 listed no portal change. Added, folded
   behind an `(advanced)` disclosure with the reasoning in the UI itself.
6. **Testcontainers runs `postgres:16-alpine`, not 18.1.** §8 named 18.1, but
   all 22 integration tests in this repo pin 16 and splitting the suite across
   two Postgres majors is a worse outcome than the deviation. Raising the whole
   suite is its own change.

## Why this exists

A KeyCrypt user asked to sign in with Google instead of creating a WeldForge
account. Tracing it produced a chain that nothing in the infrastructure repo can
fix:

1. `AuthService.issueFederatedSession` mints a federated session with
   `List.of()` for `amr`, deliberately. Its javadoc: RFC 8176 has no value for
   "someone else authenticated them", and asserting `pwd` would be a claim about
   a password that was never presented. `JwtService` then omits the claim
   entirely rather than sending an empty array.
2. KeyCrypt's V9 check is `Collections.disjoint(presentedAmr, required)` against
   `hwk,swk`. The empty set is disjoint from everything, so the token is refused
   with `insufficient_auth_strength` — at login, and on every vault, secrets and
   share call after it.
3. KeyCrypt's floor cannot be lowered by configuration. `KeycryptOidcProperties`
   drops blank entries and substitutes `hwk,swk` for an empty list, so no value
   of `KEYCRYPT_OIDC_REQUIRED_AMR` turns V9 off.

So a Google sign-in completes at Google, completes at WeldForge, and fails at
KeyCrypt.

**Decision taken by Wimpie on 2026-10-30:** no passkey step-up. Google accounts
can carry MFA on Google's side and there is no wish to verify a second time. The
alternative design that was rejected is in the appendix, because 80% of its code
already exists and it is the fallback if the gate in §3 cannot be met.

## 1. What this actually changes, stated plainly

**Google does not return an `amr` claim.** Its ID token carries `iss`, `azp`,
`aud`, `sub`, `at_hash`, `email`, `email_verified`, `name`, `picture`,
`given_name`, `family_name`, `locale`, `hd` (Workspace only), `iat` and `exp`.
Nothing about how the person authenticated.

So WeldForge cannot *verify* that Google performed MFA. It can only be
*configured to assert* it. That is a legitimate trust decision — it is how
enterprise SSO skips step-up for a trusted upstream — but it must be built as
what it is:

- **per provider**, not global;
- **off by default**, so no existing tenant changes behaviour;
- **audited**, so a session carrying an asserted factor is distinguishable
  afterwards from one that verified it;
- **named honestly in the code**, `assertedAmr`, never `verifiedAmr`.

## 2. Non-goals

- Passkey step-up after federation (rejected above; see appendix).
- Any change to KeyCrypt. If this ships, KeyCrypt needs none — which is the
  point of putting the assertion in the token rather than relaxing V9.
- SAML federation. It has the same gap and should follow the same shape, but it
  is a separate change with its own scenarios.
- Removing friction entirely. A first-time user still gets provisioned and still
  consumes a seat; this removes the password and the WeldForge account creation,
  not the account itself.

## 3. The sharp edge — read before enabling this for KeyCrypt

**Two-factor is a property of a Google account, not of the Google provider.**
Asserting `hwk` on the provider asserts it for *every* user who signs in through
it, including one whose Google account has only a password. The assertion is
about a setting the user controls and can switch off, and WeldForge will never
know.

For a password manager that is not acceptable on its own. The mitigation that
makes it verifiable:

**Gate on the `hd` claim.** Google returns `hd` for Google Workspace accounts,
naming the hosted domain. Two-factor can be *enforced for that domain* in
Workspace admin, where the user cannot turn it off. Asserting a factor for
`hd = <your domain>` is then backed by a policy you control; asserting it for
`gmail.com` is backed by nothing.

Therefore this spec makes the gate structural rather than advisory: **an
`asserted_amr` containing `hwk` or `swk` is refused at the API unless
`required_hd` is also set.** If the people who need KeyCrypt access are not on a
Workspace domain with enforced 2FA, this feature should not be used for KeyCrypt
and the appendix design is the correct answer instead.

## 4. Data — one migration, additive

`V71__social_provider_asserted_amr.sql`:

```sql
ALTER TABLE tenant_social_providers
    ADD COLUMN asserted_amr VARCHAR(128),
    ADD COLUMN required_hd  VARCHAR(255);
```

Two nullable columns, no backfill, no existing row read or written. Inert until
an operator sets a value, so the build is a no-op for all seven tenants on
deploy.

**Check the number before committing.** `V68` is absent from this repo (it was
renumbered when #154 shipped `V69` first), and the production overlay's last
recorded migration is `V70`. Confirm against `flyway_schema_history` in the
production database rather than against the folder listing — the folder says
what exists, only the table says what is applied. Never edit an applied
migration.

## 5. Contract

**`TenantSocialProvider`** gains `assertedAmr` and `requiredHd`.

**`SocialProviderDto`** gains both. Validation on upsert
(`POST /api/admin/tenants/{id}/social-providers`), all returning 400:

- `asserted_amr` values must be RFC 8176 identifiers already defined in
  `AuthenticationMethods` — unknown strings are refused rather than stored and
  silently never matched.
- `pwd` is refused outright. No password was presented to this server, and the
  existing code's refusal to claim one is the behaviour being preserved, not
  the one being relaxed.
- `hwk` or `swk` without `required_hd` is refused (§3). The error message should
  say why, because this is the one rule a future reader will want to delete.

**`AuthController.tenantSocialProviders`** — the public, unauthenticated
pre-login endpoint — must not expose either field. It already redacts
`clientSecret`; these join it. A login page has no business knowing what the
server will assert.

**New `idp` claim on the access token**, naming the upstream registration that
produced the session. This is unconditional and truthful whether or not anything
is asserted, it costs nothing, and it lets any relying party make its own
decision instead of trusting ours. Add `idp` to the `claims_supported` list in
`OidcDiscoveryController` (currently `"nonce", "amr", "roles"`).

## 6. Code

1. **`TenantSocialProvider`** — two fields, following the existing column
   conventions in that entity.
2. **`TenantService.upsertProvider`** — the validation in §5.
3. **`CustomOAuth2UserService.provision`** — enforce `required_hd`. A sign-in
   whose `hd` claim is absent or does not match is refused before provisioning,
   so a personal Google account cannot create a seat on a domain-gated provider.
4. **`AuthService.issueFederatedSession`** — take the asserted `amr` list and
   pass it to `issueTokens` instead of `List.of()`. Keep the empty list as the
   default path so an unconfigured provider behaves exactly as it does today.
   The audit metadata gains `assertedAmr` and `hd`, beside the existing
   `federated: true` — an operator reading the audit log must be able to tell an
   asserted factor from a verified one.
5. **`JwtService`** — the `idp` claim, following the existing `customClaims` /
   `sessionId` overload pattern rather than a new parameter on every caller.
6. **`OAuth2LoginSuccessHandler`** — unchanged in shape. It already fails closed
   when no session is issued.

## 7. Scenarios (Given/When/Then)

Extend `weldforge-auth/src/test/resources/features/epic_c_federation.feature`.
`FederatedSessionIntegrationTest` already covers today's behaviour and must stay
green as the default-off regression guard.

- Provider with no `asserted_amr` → the session carries **no** `amr` claim.
  (Today's behaviour. If this scenario ever goes red, the feature has leaked
  into tenants that did not ask for it.)
- Provider with `asserted_amr = hwk` and `required_hd` matching the `hd` claim →
  the access token's `amr` contains `hwk`, and `idp` names the provider.
- Same provider, a sign-in whose `hd` does not match → refused, no user
  provisioned, no session.
- Same provider, a sign-in with **no** `hd` claim at all (a personal account) →
  refused.
- Upsert with `asserted_amr = pwd` → 400.
- Upsert with `asserted_amr = hwk` and no `required_hd` → 400.
- Upsert with an unregistered value → 400.
- The public `/api/auth/tenants/{slug}/social-providers` response contains
  neither field.
- The audit row for a federated login records the asserted values.

## 8. Test plan

Cucumber 8 + Testcontainers 2.x against `postgres:18.1-alpine`, per the house
stack. Unit coverage for the upsert validation; integration coverage for the
token's claims, asserting on the decoded JWT rather than on a 200.

## 9. Deploy

Staging first on the same sha, the 26/26 pre-promotion checks, then the image
tag in `apps/weldforge/overlays/production/kustomization.yaml` in the
infrastructure repo. Take and verify a dump before the migration, as every other
migration in that overlay's history records. The migration is additive, so an
image rollback leaves the columns in place and an older image ignores them.

## 10. Afterwards — the infrastructure half

Not part of this change, recorded so the handover is complete:

- Register the Google OAuth client. Redirect URI is on the **tenant** host:
  `https://cwvermaak-tech.sso.weldforge.org/login/oauth2/code/cwvermaak-tech-google`.
  Read off the live 302 for `counteract-studios`, which already runs Google —
  Google matches redirect URIs exactly and the apex form alone fails.
- Create the provider row on `cwvermaak-tech` through the admin portal, with
  `asserted_amr` and `required_hd` set.
- Verify by **decoding the issued token and reading `amr`**, not by watching the
  UI succeed. Then a real KeyCrypt sign-in end to end.
- Note the tenant is shared by the whole Tech estate, so this turns the Google
  button on for every app at once.

## Appendix: the rejected design, in case §3's gate cannot be met

Step the federated session up to a passkey, then assert `hwk` because it was
actually verified. Most of it exists already:
`AuthService.completeLoginForUpstream` keeps every gate (lockout, MFA challenge,
MFA enrolment, audit, metrics) and its javadoc says in as many words that
"SAML / OAuth2 could reuse it later".

What it would need: an `amr` helper with no `pwd` in it; the login source
carried **inside the MFA challenge token**, since that token is the only thing
surviving between the Google callback and the passkey ceremony (without it
`completeMfaLogin` stamps `pwd` on a login that had none); `completeLoginForUpstream`
parameterised, as it currently hardcodes `AuthenticationMethods.password()` and
`"source", "ldap"`; the challenge handed to the browser in a short-lived
`HttpOnly` cookie rather than a query parameter; and the portal's existing MFA
screen reached on load instead of only after a password POST.

It verifies instead of asserting, needs no `hd` gate and no trust in a setting
the user controls — at the cost of one passkey enrolment per person.
