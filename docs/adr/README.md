# Architecture decision records

Standards WeldForge considered and chose on purpose, so that an absence reads as
a decision and not an oversight (CONF-8.2). Each record names the standard, the
decision, the reasoning and the conditions that would reverse it.

| ADR | Standard | Decision |
|---|---|---|
| [0001](0001-rfc9068-jwt-access-token-profile.md) | RFC 9068 — JWT profile for OAuth 2.0 access tokens | **Declined** |
| [0002](0002-rfc9207-issuer-identification.md) | RFC 9207 — authorization server issuer identification | **Adopted** (CONF-1.4) |
| [0003](0003-rfc7592-client-registration-management.md) | RFC 7592 — dynamic client registration management | **Partially adopted:** read and delete, no update |
| [0004](0004-nist-sp-800-63b-password-policy.md) | NIST SP 800-63B §5.1.1.2 — memorized secrets | **Adopted** (CONF-7.1), with two recorded deviations |

Broader scope decisions that are not about a single standard (Spring
Authorization Server, FAPI 2.0, OIDC front- and back-channel logout, SCIM ETags)
are recorded in
[`../product/standards-conformance-backlog.md` §9](../product/standards-conformance-backlog.md).
The resulting conformance position is summarised in
[`../compliance/standards-conformance.md`](../compliance/standards-conformance.md).

**Format.** Status · Context · Decision · Consequences · Reversal conditions. Add
a record when a standard is declined, partly implemented, or implemented with a
deviation. Supersede a record rather than editing its decision.
