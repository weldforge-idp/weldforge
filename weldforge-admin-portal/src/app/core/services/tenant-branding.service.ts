import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, of, tap } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface TenantBranding {
  slug: string;
  displayName: string;
  registrationEnabled: boolean;
  passwordRecoveryEnabled: boolean;
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

  /** Pull `tenant` from the current URL's query string. */
  slugFromUrl(search: string = window.location.search): string | null {
    const params = new URLSearchParams(search);
    const v = params.get('tenant');
    return v && v.trim() ? v.trim() : null;
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
  }

  private removeBrandingVars(): void {
    const root = document.documentElement;
    for (const cssVar of Object.values(CSS_VAR_KEYS)) {
      root.style.removeProperty(cssVar);
    }
  }
}
