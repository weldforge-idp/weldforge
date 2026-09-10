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
  /** Verify this SP's AuthnRequest / LogoutRequest signatures against spCertificate. */
  wantAuthnRequestSigned?: boolean;
  /**
   * CONF-5.1. A pinned AuthnContextClassRef, sent verbatim instead of one
   * derived from how the user signed in. On update, '' clears the pin.
   */
  authnContextOverride?: string | null;
  /** CONF-5.4. Send the metadata entityID as Issuer instead of `{slug}-idp`. */
  useEntityIdAsIssuer?: boolean;
}

/** The legacy value every SP registered before V56 is pinned to. */
export const AUTHN_CONTEXT_PASSWORD_PROTECTED =
  'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';

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

  update(id: number, sp: Partial<SamlIdpServiceProvider>): Observable<SamlIdpServiceProvider> {
    return this.http.put<SamlIdpServiceProvider>(`${this.url}/${id}`, sp);
  }

  delete(id: number): Observable<void> {
    return this.http.delete<void>(`${this.url}/${id}`);
  }
}
