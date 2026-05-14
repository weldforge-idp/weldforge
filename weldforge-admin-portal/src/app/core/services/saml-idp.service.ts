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
  constructor(private http: HttpClient) {}

  private url(tenantId: number): string {
    return `${environment.apiBaseUrl}/api/admin/tenants/${tenantId}/saml/service-providers`;
  }

  list(tenantId: number): Observable<SamlIdpServiceProvider[]> {
    return this.http.get<SamlIdpServiceProvider[]>(this.url(tenantId));
  }

  create(tenantId: number, sp: SamlIdpServiceProvider): Observable<SamlIdpServiceProvider> {
    return this.http.post<SamlIdpServiceProvider>(this.url(tenantId), sp);
  }

  update(tenantId: number, id: number, sp: SamlIdpServiceProvider): Observable<SamlIdpServiceProvider> {
    return this.http.put<SamlIdpServiceProvider>(`${this.url(tenantId)}/${id}`, sp);
  }

  delete(tenantId: number, id: number): Observable<void> {
    return this.http.delete<void>(`${this.url(tenantId)}/${id}`);
  }

  importMetadata(tenantId: number, body: { metadataXml?: string; metadataUrl?: string }):
      Observable<SamlIdpServiceProvider> {
    return this.http.post<SamlIdpServiceProvider>(`${this.url(tenantId)}/import-metadata`, body);
  }
}
