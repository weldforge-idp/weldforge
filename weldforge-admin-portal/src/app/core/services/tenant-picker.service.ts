import { Injectable, signal } from '@angular/core';
import { AuthService } from './auth.service';

const STORAGE_KEY = 'wf_acting_tenant';
const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/;

/**
 * Holds the tenant slug a SUPER_ADMIN is currently "acting as" in the
 * admin portal. Drives the tenant dropdown and the X-WF-Tenant selector
 * the tenant interceptor stamps onto outbound /api/admin/** requests
 * (unless the request names its own tenant -- see core/tenant-selector.ts).
 *
 * - Initial value: the JWT's home tenant (so the very first page load
 *   behaves identically to before).
 * - Persisted to localStorage so the selection survives a refresh.
 * - Cleared on logout via {@link clear} (the auth flow already wipes
 *   localStorage; this is a defence-in-depth call site).
 *
 * Non-super-admins never set this; {@link AuthService.isSuperAdmin} gates
 * both the dropdown and {@link outgoingSlug}. The backend is the
 * authoritative gate: `CrossTenantSelectorFilter` checks the selector
 * against the caller's admin memberships (a super-admin holds a global
 * one) and answers 403 -- never a quiet fallback to the home tenant --
 * for a tenant the caller cannot administer.
 */
@Injectable({ providedIn: 'root' })
export class TenantPickerService {
  private readonly _active = signal<string | null>(this.readInitial());

  /** Slug currently selected in the dropdown (null = use the JWT home tenant). */
  readonly activeTenantSlug = this._active.asReadonly();

  /**
   * The tenant admin calls should act in -- the picker selection if
   * super-admin, else null (no selector: the JWT's home tenant).
   *
   * A plain method, deliberately NOT a computed(). `isSuperAdmin()` reads the
   * token from localStorage, which is not a signal. A computed() that saw it
   * return false even once -- evaluated before sign-in, or while a refresh
   * briefly held another session's token -- returned null without ever
   * reading `_active`, kept no dependency on it, and stayed null for the life
   * of the page while the dropdown went on showing the chosen tenant. See the
   * zoneless pitfalls in CLAUDE.md.
   */
  outgoingSlug(): string | null {
    if (!this.auth.isSuperAdmin()) return null;
    return this._active() ?? this.auth.getHomeTenantSlug();
  }

  constructor(private auth: AuthService) {}

  /** Switch the acting tenant. Validates the slug shape and rejects garbage. */
  set(slug: string | null): void {
    if (slug === null) {
      this._active.set(null);
      try { localStorage.removeItem(STORAGE_KEY); } catch {}
      return;
    }
    const normalized = slug.trim().toLowerCase();
    if (!SLUG_PATTERN.test(normalized)) return;
    this._active.set(normalized);
    try { localStorage.setItem(STORAGE_KEY, normalized); } catch {}
  }

  /** Reset to the JWT's home tenant. */
  clear(): void {
    this._active.set(null);
    try { localStorage.removeItem(STORAGE_KEY); } catch {}
  }

  private readInitial(): string | null {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      return SLUG_PATTERN.test(raw) ? raw : null;
    } catch {
      return null;
    }
  }
}
