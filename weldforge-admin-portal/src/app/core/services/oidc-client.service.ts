import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import { forTenant } from '../tenant-selector';

export interface OidcClient {
  id?: number;
  tenantId?: number;
  clientId: string;
  /** Returned only on create / rotate. Never persisted client-side. */
  clientSecret?: string;
  name?: string;
  redirectUris: string[];
  scopes: string[];
  grantTypes: string[];
  requirePkce?: boolean;
  /** PRD MFA-04: force MFA for every /authorize against this client. */
  requireMfa?: boolean;
  /** PRD SSO-05: step-up threshold in seconds. 0 = use tenant default. */
  maxAuthenticationAgeSeconds?: number;
  /** Browser SPA / native app: PKCE only, no secret is issued. */
  publicClient?: boolean;
}

/**
 * Every call takes the tenant it acts in. Omit it and the call acts in the
 * picker's tenant (or the home tenant) -- fine for page-level screens, wrong
 * for anything drawn under a specific tenant's row. See core/tenant-selector.ts.
 */
@Injectable({ providedIn: 'root' })
export class OidcClientService {
  private url = `${environment.apiBaseUrl}/api/admin/oidc/clients`;

  constructor(private http: HttpClient) {}

  list(tenantSlug?: string): Observable<OidcClient[]> {
    return this.http.get<OidcClient[]>(this.url, forTenant(tenantSlug));
  }

  create(client: OidcClient, tenantSlug?: string): Observable<OidcClient> {
    return this.http.post<OidcClient>(this.url, client, forTenant(tenantSlug));
  }

  rotateSecret(id: number, tenantSlug?: string): Observable<OidcClient> {
    return this.http.post<OidcClient>(`${this.url}/${id}/rotate-secret`, {}, forTenant(tenantSlug));
  }

  delete(id: number, tenantSlug?: string): Observable<void> {
    return this.http.delete<void>(`${this.url}/${id}`, forTenant(tenantSlug));
  }
}
