import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { TenantPickerService } from '../services/tenant-picker.service';

const TENANT_HEADER = 'X-Tenant-Slug';
const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/;

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
 * 2. `?tenant=<slug>` on the current page URL — used by pre-login flows
 *    (login, register, forgot/reset-password, verify-email) and the
 *    public branding/social-providers/saml-providers GETs the login
 *    screen renders before the user has a JWT. These need a tenant id
 *    so the filter doesn't fall back to `default` and report "Invalid
 *    credentials" for a real user that lives in another tenant.
 *
 * Requests with the header already set, or outside /api/, pass through.
 */
export const tenantInterceptor: HttpInterceptorFn = (req, next) => {
  if (!req.url.includes('/api/')) return next(req);
  if (req.headers.has(TENANT_HEADER)) return next(req);

  const slug = pickerSlug() ?? readSlugFromUrl();
  if (!slug) return next(req);

  return next(req.clone({ setHeaders: { [TENANT_HEADER]: slug } }));
};

function pickerSlug(): string | null {
  try {
    return inject(TenantPickerService).outgoingSlug();
  } catch {
    // inject() throws outside an injection context (very early SSR
    // bootstrap). The URL fallback keeps pre-login flows working then.
    return null;
  }
}

function readSlugFromUrl(): string | null {
  if (typeof window === 'undefined' || !window.location) return null;
  const raw = new URLSearchParams(window.location.search).get('tenant');
  if (!raw) return null;
  const slug = raw.trim().toLowerCase();
  return SLUG_PATTERN.test(slug) ? slug : null;
}
