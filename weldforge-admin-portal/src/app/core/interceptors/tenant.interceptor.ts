import { HttpInterceptorFn } from '@angular/common/http';

const TENANT_HEADER = 'X-Tenant-Slug';
const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/;

/**
 * Public auth flows (login, register, refresh, forgot/reset-password,
 * verify-email, the /api/auth/tenants/{slug}/branding GET, etc.) need
 * a tenant identifier so the backend's TenantResolverFilter resolves to
 * the right `tenants` row. Without it the filter falls back to the
 * `default` tenant and looks up the user there, which fails for any
 * other tenant with "Invalid credentials" — masking the real config.
 *
 * Reads `?tenant=<slug>` from the URL the user is currently on (the
 * login/reset/forgot screens already preserve this query param when
 * routing between themselves) and stamps it into X-Tenant-Slug on
 * every /api/* request. Requests with the header already set, or
 * requests outside /api/, are left alone. After the user signs in the
 * JWT carries the tenant claim and downstream filters use that, so
 * this interceptor is mostly a pre-login concern.
 */
export const tenantInterceptor: HttpInterceptorFn = (req, next) => {
  if (!req.url.includes('/api/')) return next(req);
  if (req.headers.has(TENANT_HEADER)) return next(req);

  const slug = readSlugFromUrl();
  if (!slug) return next(req);

  return next(req.clone({ setHeaders: { [TENANT_HEADER]: slug } }));
};

function readSlugFromUrl(): string | null {
  if (typeof window === 'undefined' || !window.location) return null;
  const raw = new URLSearchParams(window.location.search).get('tenant');
  if (!raw) return null;
  const slug = raw.trim().toLowerCase();
  return SLUG_PATTERN.test(slug) ? slug : null;
}
