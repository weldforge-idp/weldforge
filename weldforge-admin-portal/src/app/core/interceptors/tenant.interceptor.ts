import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { TenantPickerService } from '../services/tenant-picker.service';
import { slugFromHost } from '../services/public-host';

const TENANT_HEADER = 'X-Tenant-Slug';

/**
 * Stamps `X-Tenant-Slug` onto outbound /api/* requests so the backend's
 * TenantResolverFilter resolves to the correct `tenants` row.
 *
 * Source priority:
 *
 * 1. {@link TenantPickerService.outgoingSlug} — the SUPER_ADMIN tenant
 *    dropdown. Only emits a slug when the JWT carries `sa: true`, so a
 *    non-super-admin can't move themselves between tenants by twiddling
 *    localStorage. The backend's JwtAuthenticationFilter is the
 *    authoritative enforcement point: non-super-admin JWTs ignore the
 *    header entirely.
 *
 * 2. The current page's host: {@code {slug}.sso.weldforge.org} resolves
 *    to {@code slug}. Used by pre-login flows (login, register,
 *    forgot/reset-password, verify-email) and the public
 *    branding/social-providers/saml-providers GETs the auth shell renders
 *    before the user has a JWT. The backend resolver applies the same
 *    rule to the Host header on the request itself, but stamping the
 *    explicit header lets the SPA call the apex API host
 *    ({@code sso.weldforge.org/api/…}) and still address the right
 *    tenant. See docs/auth-url-spec.md.
 *
 * Requests with the header already set, or outside /api/, pass through.
 */
export const tenantInterceptor: HttpInterceptorFn = (req, next) => {
  if (!req.url.includes('/api/')) return next(req);
  if (req.headers.has(TENANT_HEADER)) return next(req);

  const slug = pickerSlug() ?? hostSlug();
  if (!slug) return next(req);

  return next(req.clone({ setHeaders: { [TENANT_HEADER]: slug } }));
};

function pickerSlug(): string | null {
  try {
    return inject(TenantPickerService).outgoingSlug();
  } catch {
    // inject() throws outside an injection context (very early SSR
    // bootstrap). The host fallback keeps pre-login flows working then.
    return null;
  }
}

function hostSlug(): string | null {
  if (typeof window === 'undefined' || !window.location) return null;
  return slugFromHost(window.location.host);
}
