import { environment } from '../../../environments/environment';

const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/;
const RESERVED_LABELS = new Set(['www', 'api', 'admin', 'app', 'mail', 'static']);

/**
 * Tenant slug derived from the page's host. Mirrors the backend
 * {@code PublicHostProperties#slugFromHost} resolver in
 * {@code weldforge-auth}. Returns null for:
 *   - the apex base domain (admin portal);
 *   - reserved root labels (www, api, admin, app, mail, static);
 *   - any host not under the configured base domain;
 *   - single-label hosts (localhost, an IP, an ngrok ID, etc.).
 *
 * Used by:
 *   - {@code TenantInterceptor} to stamp X-Tenant-Slug onto /api/* requests
 *     before sign-in;
 *   - the auth-shell and pre-login auth components to load tenant branding
 *     before a JWT exists.
 *
 * See docs/auth-url-spec.md.
 */
export function slugFromHost(host: string = window.location.host): string | null {
  if (!host) return null;
  const base = (environment.publicBaseDomain ?? '').toLowerCase();
  if (!base || !base.includes('.')) return null;

  let h = host.toLowerCase();
  const colon = h.indexOf(':');
  if (colon >= 0) h = h.substring(0, colon);
  if (!h || h === base) return null;

  const suffix = '.' + base;
  if (!h.endsWith(suffix)) return null;
  const label = h.substring(0, h.length - suffix.length);
  if (!label || label.includes('.')) return null;
  if (!SLUG_PATTERN.test(label)) return null;
  if (RESERVED_LABELS.has(label)) return null;
  return label;
}

/**
 * Build the public origin for a tenant. Used to construct deep links
 * across tenant boundaries (e.g. the admin-portal explainer that shows
 * an admin where their users sign in).
 */
export function originForTenant(slug: string, scheme: string = 'https'): string {
  const base = (environment.publicBaseDomain ?? '').toLowerCase();
  if (!slug || !base) return '';
  return `${scheme}://${slug.toLowerCase()}.${base}`;
}
