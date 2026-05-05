import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export type SocialProviderType =
  | 'GOOGLE'
  | 'MICROSOFT'
  | 'GITHUB'
  | 'FACEBOOK'
  | 'APPLE'
  | 'LINKEDIN'
  | 'TWITTER';

export const SUPPORTED_PROVIDERS: SocialProviderType[] = [
  'GOOGLE', 'MICROSOFT', 'GITHUB', 'FACEBOOK', 'APPLE', 'LINKEDIN', 'TWITTER'
];

export interface Tenant {
  id: number;
  slug: string;
  name: string;
  displayName?: string;
  enabled: boolean;
  registrationEnabled?: boolean;
  passwordRecoveryEnabled?: boolean;
  emailVerificationRequired?: boolean;
  branding?: Record<string, unknown> | null;
}

export interface SocialProvider {
  id?: number;
  tenantId?: number;
  provider: SocialProviderType;
  displayName?: string;
  clientId: string;
  clientSecret?: string;
  scopes?: string;
  enabled: boolean;
  registrationId?: string;
}

export type SamlBinding = 'POST' | 'REDIRECT';

export interface SamlProvider {
  id?: number;
  tenantId?: number;
  providerKey: string;
  displayName?: string;
  idpEntityId?: string;
  idpSsoUrl?: string;
  idpSloUrl?: string;
  ssoBinding?: SamlBinding;
  /** PEM-encoded X.509 cert. Write-only on update — leave blank to keep the existing value. */
  idpSigningCertificate?: string;
  nameIdFormat?: string;
  emailAttribute?: string;
  nameAttribute?: string;
  wantAssertionsSigned?: boolean;
  wantAuthnRequestSigned?: boolean;
  enabled: boolean;
  registrationId?: string;
  loginUrl?: string;
  spMetadataUrl?: string;
}

@Injectable({ providedIn: 'root' })
export class TenantService {
  private url = `${environment.apiBaseUrl}/api/admin/tenants`;
  private publicUrl = `${environment.apiBaseUrl}/api/auth/tenants`;

  constructor(private http: HttpClient) {}

  list(): Observable<Tenant[]> {
    return this.http.get<Tenant[]>(this.url);
  }

  get(id: number): Observable<Tenant> {
    return this.http.get<Tenant>(`${this.url}/${id}`);
  }

  create(t: Partial<Tenant>): Observable<Tenant> {
    return this.http.post<Tenant>(this.url, t);
  }

  update(id: number, t: Partial<Tenant>): Observable<Tenant> {
    return this.http.put<Tenant>(`${this.url}/${id}`, t);
  }

  delete(id: number): Observable<void> {
    return this.http.delete<void>(`${this.url}/${id}`);
  }

  listProviders(tenantId: number): Observable<SocialProvider[]> {
    return this.http.get<SocialProvider[]>(`${this.url}/${tenantId}/social-providers`);
  }

  upsertProvider(tenantId: number, provider: SocialProvider): Observable<SocialProvider> {
    return this.http.post<SocialProvider>(`${this.url}/${tenantId}/social-providers`, provider);
  }

  deleteProvider(tenantId: number, provider: SocialProviderType): Observable<void> {
    return this.http.delete<void>(`${this.url}/${tenantId}/social-providers/${provider}`);
  }

  publicProviders(slug: string): Observable<SocialProvider[]> {
    return this.http.get<SocialProvider[]>(`${this.publicUrl}/${slug}/social-providers`);
  }

  // ---- SAML providers ---------------------------------------------

  listSamlProviders(tenantId: number): Observable<SamlProvider[]> {
    return this.http.get<SamlProvider[]>(`${this.url}/${tenantId}/saml-providers`);
  }

  upsertSamlProvider(tenantId: number, provider: SamlProvider): Observable<SamlProvider> {
    return this.http.post<SamlProvider>(`${this.url}/${tenantId}/saml-providers`, provider);
  }

  deleteSamlProvider(tenantId: number, providerKey: string): Observable<void> {
    return this.http.delete<void>(`${this.url}/${tenantId}/saml-providers/${providerKey}`);
  }
}
