import { HttpContext, HttpContextToken } from '@angular/common/http';

/**
 * Which tenant an admin API call acts in.
 *
 * The backend decides the tenant of an `/api/admin/**` call from ONE selector,
 * `X-WF-Tenant`, checked against the caller's admin memberships and audited
 * (`CrossTenantSelectorFilter`). It answers with `X-WF-Acting-Tenant`, the
 * tenant the call actually ran in, and the tenant interceptor refuses a
 * response whose acting tenant is not the one it asked for.
 *
 * Why this exists: on 2026-09-11 a super-admin created an OIDC client on the
 * Tenants page under one tenant's row and it landed in their home tenant with
 * no error. The row a user is looking at must be the tenant they are editing,
 * so row-scoped screens name the tenant on every call with {@link forTenant},
 * instead of inheriting whatever the page-level picker happens to hold.
 */
export const TARGET_TENANT = new HttpContextToken<string | null>(() => null);

export const TENANT_SELECTOR_HEADER = 'X-WF-Tenant';
export const ACTING_TENANT_HEADER = 'X-WF-Acting-Tenant';

/** Request options that pin an admin call to `slug`, whatever the picker says. */
export function forTenant(slug: string | null | undefined): { context: HttpContext } {
  return { context: new HttpContext().set(TARGET_TENANT, slug ?? null) };
}
