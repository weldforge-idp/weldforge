import { Injectable, signal, computed } from '@angular/core';
import { AuthService } from './auth.service';

const STORAGE_KEY = 'wf_acting_tenant';
const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/;

/**
 * Holds the tenant slug a SUPER_ADMIN is currently "acting as" in the
 * admin portal. Drives the tenant dropdown and the X-Tenant-Slug header
 * the tenant interceptor stamps onto outbound /api/* requests.
 *
 * - Initial value: the JWT's home tenant (so the very first page load
 *   behaves identically to before).
 * - Persisted to localStorage so the selection survives a refresh.
 * - Cleared on logout via {@link clear} (the auth flow already wipes
 *   localStorage; this is a defence-in-depth call site).
 *
 * Non-super-admins never set this; the interceptor reads
 * {@link activeTenantSlug} but {@link AuthService.isSuperAdmin} gates
 * whether the dropdown is rendered, so the value can only change when
 * the JWT permits it. The backend's JwtAuthenticationFilter is the
 * authoritative gate: it only honours an X-Tenant-Slug override when
 * the JWT itself carries `sa: true`.
 */
@Injectable({ providedIn: 'root' })
export class TenantPickerService {
  private readonly _active = signal<string | null>(this.readInitial());

  /** Slug currently selected in the dropdown (null = use the JWT home tenant). */
  readonly activeTenantSlug = this._active.asReadonly();

  /**
   * The slug to actually send on outbound API calls — the picker
   * selection if super-admin, else the JWT home tenant. Null means
   * "send no override header"; the backend will then fall back to the
   * JWT's tenant claim, which is what non-super-admins want.
   */
  readonly outgoingSlug = computed(() => {
    if (!this.auth.isSuperAdmin()) return null;
    return this._active() ?? this.auth.getHomeTenantSlug();
  });

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
