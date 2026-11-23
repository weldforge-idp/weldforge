import { Injectable } from '@angular/core';

/** The non-secret tenant slug of the current session, kept for cold-load refresh naming. */
export const TENANT_HINT_KEY = 'wf_session_tenant';
/** The key older builds used to persist the access token. Purged on boot. */
const LEGACY_TOKEN_KEY = 'access_token';

/**
 * The access token, held in memory for the life of the tab and never written
 * to localStorage (WF-15).
 *
 * <p>localStorage is readable by any script running on the origin, so a single
 * XSS could read a persisted bearer token at rest and replay it from anywhere.
 * A memory-only token dies with the tab and cannot be exfiltrated from storage.
 * What survives a reload instead is the httpOnly, per-tenant refresh cookie:
 * the app silently refreshes from it (see {@code adoptCookieSession}) to put a
 * fresh token back in memory, so the user stays signed in across reloads
 * without the long-lived credential ever being at rest in script-readable
 * storage.
 *
 * <p>The one thing that does persist is the session's tenant SLUG, which is not
 * a credential. The cold-load refresh must name the tenant it is refreshing
 * (B-TEN-7), and on a reload there is no token left to read it from — so the
 * slug alone is kept.
 */
@Injectable({ providedIn: 'root' })
export class AccessTokenStore {
  private token: string | null = null;

  constructor() {
    // One-time cleanup for sessions that predate WF-15: an older build left the
    // access token in localStorage. Remove it — that is the whole point — while
    // keeping its tenant slug so the next refresh still names the right tenant.
    try {
      const legacy = localStorage.getItem(LEGACY_TOKEN_KEY);
      if (legacy) {
        const slug = tenantFromToken(legacy);
        if (slug) localStorage.setItem(TENANT_HINT_KEY, slug);
        localStorage.removeItem(LEGACY_TOKEN_KEY);
      }
    } catch {
      // Storage unavailable (private mode, blocked): nothing to clean up.
    }
  }

  get(): string | null {
    return this.token;
  }

  set(token: string): void {
    this.token = token;
    const slug = tenantFromToken(token);
    if (slug) {
      try {
        localStorage.setItem(TENANT_HINT_KEY, slug);
      } catch {
        // Best-effort: without the hint a cold-load refresh falls back to the
        // host, which on a tenant subdomain still names the tenant.
      }
    }
  }

  clear(): void {
    this.token = null;
    try {
      localStorage.removeItem(TENANT_HINT_KEY);
    } catch {
      // ignore
    }
  }

  /** The tenant slug of the current (or most recent) session, for naming a refresh. */
  tenantSlug(): string | null {
    const fromMemory = this.token ? tenantFromToken(this.token) : null;
    if (fromMemory) return fromMemory;
    try {
      return localStorage.getItem(TENANT_HINT_KEY);
    } catch {
      return null;
    }
  }
}

/** The `tenant` claim of a JWT, without verifying its signature (UI-only). */
export function tenantFromToken(token: string): string | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const claims = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    return typeof claims.tenant === 'string' && claims.tenant ? claims.tenant : null;
  } catch {
    return null;
  }
}
