---
name: email identity is scoped to the tenant
description: Uniqueness is (tenant, lower(email)) — never email alone; production already has one address in two tenants
metadata:
  node_type: memory
  type: feedback
---

WeldForge is multi-tenant, so one person may hold accounts in several tenants
under the same email address. `/llms.txt` publishes this as the contract: *"The
same address may exist in another tenant."*

**Production already contains an address registered in two tenants.** A global
unique index on `users.email` would therefore fail to apply, and if forced would
break a real user.

Enforced since **V59** by `users_tenant_email_unique` on
`(tenant_id, lower(email))`. Before that, nothing stopped two rows sharing an
address inside one tenant — the application checked first, but a check-then-
insert is a race, the same shape as the single-use token bug in B-OIDC-6.

**How to apply.**

- Never scope email uniqueness globally. Tenant first, always.
- Keep `lower()`. Every lookup is case-insensitive
  (`findByTenant_SlugAndEmailIgnoreCase`), so without it `Alice@` and `alice@`
  are two rows the login path treats as one and resolves arbitrarily.
- A violation is mapped back to the documented `400 bad_request` in
  `GlobalExceptionHandler`, not a generic 409 — a caller must not get a
  different error depending on who won the race.

See [[feedback_jpa_managed_entity_clobber]] for the sibling lesson: a predicate
evaluated in application code against a stale snapshot is not a constraint.
