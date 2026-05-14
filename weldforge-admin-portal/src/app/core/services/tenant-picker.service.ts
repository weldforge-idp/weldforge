import { Injectable, signal, computed } from '@angular/core';
import { AuthService } from './auth.service';

const STORAGE_KEY = 'wf_acting_tenant';
const STORAGE_KEY_ID = 'wf_acting_tenant_id';
const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/;

/**
 * Holds the tenant a SUPER_ADMIN is currently "acting as" in the admin
 * portal. Drives the tenant dropdown, the X-Tenant-Slug header the
 * tenant interceptor stamps onto outbound /api/* requests, and the
 * tenantId path segment used by the new nested admin REST endpoints
 * (/api/admin/tenants/{tenantId}/...).
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
  private readonly _activeSlug = signal<string | null>(this.readInitialSlug());
  private readonly _activeId   = signal<number | null>(this.readInitialId());

  /** Slug currently selected in the dropdown (null = use the JWT home tenant). */
  readonly activeTenantSlug = this._activeSlug.asReadonly();

  /** Numeric id currently selected (null = use the JWT home tenant id). */
  readonly activeTenantId = this._activeId.asReadonly();

  /**
   * The slug to actually send on outbound API calls — the picker
   * selection if super-admin, else the JWT home tenant. Null means
   * "send no override header"; the backend will then fall back to the
   * JWT's tenant claim, which is what non-super-admins want.
   */
  readonly outgoingSlug = computed(() => {
    if (!this.auth.isSuperAdmin()) return null;
    return this._activeSlug() ?? this.auth.getHomeTenantSlug();
  });

  /**
   * The tenant id to thread into nested REST URLs. Always returns a
   * concrete id when one is available — the home id for non-super
   * admins, the picker selection (or home id) for super admins.
   */
  readonly outgoingTenantId = computed<number | null>(() => {
    if (!this.auth.isSuperAdmin()) return this.auth.getHomeTenantId();
    return this._activeId() ?? this.auth.getHomeTenantId();
  });

  constructor(private auth: AuthService) {}

  /**
   * Switch the acting tenant. Both slug and id come from the same
   * tenant row in the picker dropdown, so they're set together.
   * Validates the slug shape and rejects garbage.
   */
  set(slug: string | null, id: number | null = null): void {
    if (slug === null) {
      this._activeSlug.set(null);
      this._activeId.set(null);
      try { localStorage.removeItem(STORAGE_KEY); } catch {}
      try { localStorage.removeItem(STORAGE_KEY_ID); } catch {}
      return;
    }
    const normalized = slug.trim().toLowerCase();
    if (!SLUG_PATTERN.test(normalized)) return;
    this._activeSlug.set(normalized);
    this._activeId.set(id);
    try { localStorage.setItem(STORAGE_KEY, normalized); } catch {}
    try {
      if (id != null) localStorage.setItem(STORAGE_KEY_ID, String(id));
      else localStorage.removeItem(STORAGE_KEY_ID);
    } catch {}
  }

  /** Reset to the JWT's home tenant. */
  clear(): void {
    this._activeSlug.set(null);
    this._activeId.set(null);
    try { localStorage.removeItem(STORAGE_KEY); } catch {}
    try { localStorage.removeItem(STORAGE_KEY_ID); } catch {}
  }

  private readInitialSlug(): string | null {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      return SLUG_PATTERN.test(raw) ? raw : null;
    } catch {
      return null;
    }
  }

  private readInitialId(): number | null {
    try {
      const raw = localStorage.getItem(STORAGE_KEY_ID);
      if (!raw) return null;
      const n = Number(raw);
      return Number.isFinite(n) && n > 0 ? n : null;
    } catch {
      return null;
    }
  }
}
