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
  /**
   * Browser origins ({@code scheme://host[:port]}) allowed to call this
   * tenant's OIDC endpoints cross-origin.
   *
   * REQUIRED for a public client whose redirect URI is a real http(s) host.
   * Without one every cross-origin call the browser makes is refused by CORS,
   * and a blocked fetch surfaces as a generic network error -- so the symptom
   * is a sign-in button that does nothing, with nothing in any log. The server
   * refuses such a registration outright since PR #126.
   *
   * Native clients (loopback or private-use scheme) correctly have none.
   */
  webOrigins?: string[];
  /** RP-initiated logout allow-list. Empty means the client cannot pass one. */
  postLogoutRedirectUris?: string[];
  /** Refresh-token lifetime in seconds; omit to inherit tenant, then instance. */
  refreshTokenTtlSeconds?: number | null;
  /**
   * Login-screen branding for this client, overlaying the tenant's key by key.
   * Null/absent inherits the tenant entirely; {} clears the override.
   */
  branding?: Record<string, unknown> | null;
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

  /**
   * Update a client in place. Send only the fields being changed: the server
   * leaves nulls alone, and an empty array clears that list.
   *
   * `clientId`, `clientSecret` and `publicClient` are refused by the server;
   * changing any of those means a new client.
   */
  update(id: number, patch: Partial<OidcClient>, tenantSlug?: string): Observable<OidcClient> {
    return this.http.put<OidcClient>(`${this.url}/${id}`, patch, forTenant(tenantSlug));
  }

  rotateSecret(id: number, tenantSlug?: string): Observable<OidcClient> {
    return this.http.post<OidcClient>(`${this.url}/${id}/rotate-secret`, {}, forTenant(tenantSlug));
  }

  delete(id: number, tenantSlug?: string): Observable<void> {
    return this.http.delete<void>(`${this.url}/${id}`, forTenant(tenantSlug));
  }
}
