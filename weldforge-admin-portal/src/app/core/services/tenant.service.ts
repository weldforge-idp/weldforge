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
  returnToCallerEnabled?: boolean;
  /** CONF-5.5. Advertised in IdP metadata as WantAuthnRequestsSigned. */
  samlWantAuthnRequestsSigned?: boolean;
  branding?: Record<string, unknown> | null;
  /**
   * Per-tenant password rule overrides. Null/absent inherits the deployment
   * baseline, and absent keys inherit individually.
   *
   * Overrides may only TIGHTEN the baseline — a weaker value is stored and then
   * ignored, which is why the UI shows the effective result beside it. See
   * docs/password-policy-spec.md.
   */
  passwordPolicy?: PasswordPolicyOverride | null;
}

/**
 * The writable subset of a password policy. Every field is optional: omitting
 * one inherits it from the deployment baseline.
 *
 * `breachCheckEnabled` is deliberately absent — breach screening is
 * deployment-wide, not per tenant.
 */
export interface PasswordPolicyOverride {
  minLength?: number;
  maxLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireDigit?: boolean;
  requireSymbol?: boolean;
}

/** A fully-resolved policy — the deployment baseline, or a tenant's effective rules. */
export interface ResolvedPasswordPolicy {
  minLength: number;
  maxLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireDigit: boolean;
  requireSymbol: boolean;
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

  /**
   * The deployment-wide password baseline, before any tenant override.
   * Fetched once so the UI can show an administrator why a weakening override
   * had no effect — tenant policies may only tighten.
   */
  passwordPolicyBaseline(): Observable<ResolvedPasswordPolicy> {
    return this.http.get<ResolvedPasswordPolicy>(
      `${environment.apiBaseUrl}/api/admin/password-policy/baseline`);
  }

  /**
   * A tenant's effective rules — baseline with its override applied, already
   * resolved by the server. Public endpoint, and the same one the login and
   * register forms read, so what the admin sees here is exactly what a user
   * will be told.
   */
  effectivePasswordPolicy(slug: string): Observable<ResolvedPasswordPolicy> {
    return this.http.get<ResolvedPasswordPolicy>(
      `${this.publicUrl}/${encodeURIComponent(slug)}/password-policy`);
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
