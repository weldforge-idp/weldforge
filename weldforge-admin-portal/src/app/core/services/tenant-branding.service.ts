import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, of, tap } from 'rxjs';
import { environment } from '../../../environments/environment';
import { slugFromHost } from './public-host';

export interface TenantBranding {
  slug: string;
  displayName: string;
  registrationEnabled: boolean;
  passwordRecoveryEnabled: boolean;
  /**
   * Identity-proofed by a platform super-admin. When false, the
   * auth-shell renders an "Unverified tenant" warning badge so users
   * can spot a look-alike tenant before typing credentials. See
   * docs/auth-url-spec.md §"Tenant identity-proofing".
   */
  verified?: boolean;
  branding?: Record<string, unknown> | null;
}

const CSS_VAR_KEYS: Record<string, string> = {
  primaryColor: '--wf-blue',
  primaryDarkColor: '--wf-blue-dim',
  accentColor: '--wf-amber',
  accentDarkColor: '--wf-amber-dim',
  bgColor: '--wf-bg',
  bg2Color: '--wf-bg-2',
  bg3Color: '--wf-bg-3',
  borderColor: '--wf-border',
  textColor: '--wf-text',
  text2Color: '--wf-text-2',
  text3Color: '--wf-text-3',
  displayFont: '--wf-display',
  sansFont: '--wf-sans',
  monoFont: '--wf-mono',
};

@Injectable({ providedIn: 'root' })
export class TenantBrandingService {
  private url = `${environment.apiBaseUrl}/api/auth/tenants`;

  readonly current = signal<TenantBranding | null>(null);
  readonly loaded = signal(false);

  constructor(private http: HttpClient) {}

  load(slug: string | null | undefined): Observable<TenantBranding | null> {
    const trimmed = (slug ?? '').trim();
    if (!trimmed) {
      this.reset();
      return of(null);
    }
    return this.http.get<TenantBranding>(`${this.url}/${encodeURIComponent(trimmed)}/branding`).pipe(
      tap(b => {
        this.current.set(b);
        this.loaded.set(true);
        this.applyToDocument(b);
      }),
      catchError(() => {
        this.reset();
        return of(null);
      })
    );
  }

  /**
   * Resolve the tenant slug from the current page URL's host. End-user
   * auth pages live on `https://{slug}.{baseDomain}/…`; the slug is the
   * leftmost label of the host. Returns null when the host is the apex
   * domain (admin portal), a reserved root label, or doesn't share the
   * configured base domain — those cases defer to the super-admin
   * tenant picker. See docs/auth-url-spec.md.
   *
   * Argument is the search string for backwards compatibility; new
   * callers should use {@link slugFromHost}.
   */
  slugFromUrl(_search: string = window.location.search): string | null {
    return this.slugFromHost();
  }

  slugFromHost(host: string = window.location.host): string | null {
    return slugFromHost(host);
  }

  private reset(): void {
    this.current.set(null);
    this.loaded.set(false);
    this.removeBrandingVars();
  }

  private applyToDocument(b: TenantBranding): void {
    this.removeBrandingVars();
    const payload = b.branding ?? {};
    const root = document.documentElement;
    for (const [key, cssVar] of Object.entries(CSS_VAR_KEYS)) {
      const v = payload[key];
      if (typeof v === 'string' && v.length > 0) {
        root.style.setProperty(cssVar, v);
      }
    }
    // `theme: "light"` toggles the .wf-light body class, which scopes the
    // light Angular Material colour theme (see styles.scss). Without this a
    // light tenant gets a light page but dark, unreadable form fields.
    document.body.classList.toggle('wf-light', payload['theme'] === 'light');
  }

  private removeBrandingVars(): void {
    const root = document.documentElement;
    for (const cssVar of Object.values(CSS_VAR_KEYS)) {
      root.style.removeProperty(cssVar);
    }
    document.body.classList.remove('wf-light');
  }
}
