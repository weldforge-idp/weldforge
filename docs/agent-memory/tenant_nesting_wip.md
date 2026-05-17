---
name: Admin REST tenant-nesting refactor — WIP
description: feat/admin-rest-tenant-nesting at 1ff7451 — moves admin endpoints to /api/admin/tenants/{tenantId}/*, has a known broken state in service-accounts.component.ts
type: project
originSessionId: 2c8ec944-2f7f-4c86-a922-6989bb89938b
---
Branch `feat/admin-rest-tenant-nesting` (pushed, tracks `origin/feat/admin-rest-tenant-nesting`) is mid-refactor. Last commit: `1ff7451` — `wip(admin): nest tenant-scoped admin endpoints under /api/admin/tenants/{tenantId}`.

**Why:** Move the admin REST surface from flat `/api/admin/<resource>` URLs to nested `/api/admin/tenants/{tenantId}/<resource>`. Goal: tenantId becomes an explicit path arg instead of being inferred from TenantContext (X-Tenant-Slug + JwtAuthenticationFilter), so SUPER_ADMIN can address any tenant without a context-switch dance, and TENANT_ADMIN authorization becomes a straight `TenantAccessor.requireSameTenant(tenantId)` check on the path id.

**How to apply / where to pick up:**

Backend is green (`./mvnw compile` passes). Frontend `ng build` fails with 5 TS2554 errors — all in `weldforge-admin-portal/src/app/features/service-accounts/service-accounts.component.ts`:

- L342 `this.api.list()` — needs tenantId
- L346 `this.api.create(dto)` — needs tenantId
- L372 `this.api.rotate(s.id)` — needs tenantId
- L382 `this.api.update(s.id, {…})` — needs tenantId, id
- L397 `this.api.delete(s.id)` — needs tenantId

Source for tenantId: `TenantPickerService.outgoingTenantId()` (newly added in this commit; pairs with the existing `outgoingSlug()`). Guard against null/undefined for the first-paint case before the picker resolves.

Service Accounts component is the *only* file with broken call-sites; everything else (group-role-mapping, oidc-client, saml-idp components + services + tenants component) was already updated in `1ff7451`.

Branch is at HEAD = main + 1 commit. Backend BDD scenarios were updated for the new path shape (`epic_d_rbac.feature` + step defs).
