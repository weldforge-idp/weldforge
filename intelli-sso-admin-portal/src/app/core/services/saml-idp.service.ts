import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface SamlIdpServiceProvider {
  id?: number;
  entityId: string;
  name?: string;
  acsUrl: string;
  sloUrl?: string;
  spCertificate?: string;
  nameIdFormat?: string;
  attributeMappings?: Record<string, string>;
  enabled?: boolean;
}

@Injectable({ providedIn: 'root' })
export class SamlIdpService {
  private url = `${environment.apiBaseUrl}/api/admin/saml/service-providers`;

  constructor(private http: HttpClient) {}

  list(): Observable<SamlIdpServiceProvider[]> {
    return this.http.get<SamlIdpServiceProvider[]>(this.url);
  }

  create(sp: SamlIdpServiceProvider): Observable<SamlIdpServiceProvider> {
    return this.http.post<SamlIdpServiceProvider>(this.url, sp);
  }

  update(id: number, sp: SamlIdpServiceProvider): Observable<SamlIdpServiceProvider> {
    return this.http.put<SamlIdpServiceProvider>(`${this.url}/${id}`, sp);
  }

  delete(id: number): Observable<void> {
    return this.http.delete<void>(`${this.url}/${id}`);
  }
}
