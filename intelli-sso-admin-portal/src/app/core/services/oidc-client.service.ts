import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

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
}

@Injectable({ providedIn: 'root' })
export class OidcClientService {
  private url = `${environment.apiBaseUrl}/api/admin/oidc/clients`;

  constructor(private http: HttpClient) {}

  list(): Observable<OidcClient[]> {
    return this.http.get<OidcClient[]>(this.url);
  }

  create(client: OidcClient): Observable<OidcClient> {
    return this.http.post<OidcClient>(this.url, client);
  }

  rotateSecret(id: number): Observable<OidcClient> {
    return this.http.post<OidcClient>(`${this.url}/${id}/rotate-secret`, {});
  }

  delete(id: number): Observable<void> {
    return this.http.delete<void>(`${this.url}/${id}`);
  }
}
