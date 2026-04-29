import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface TwilioProvider {
  id?: number;
  tenantId?: number;
  accountSid: string;
  /** Write-only. Never populated on GET. Leave blank to keep existing value on update. */
  authToken?: string;
  fromPhone: string;
  messagingServiceSid?: string;
  enabled: boolean;
  /** Read-only — indicates the stored auth token exists without revealing it. */
  authTokenSet?: boolean;
}

@Injectable({ providedIn: 'root' })
export class TenantTwilioService {
  private url = `${environment.apiBaseUrl}/api/admin/tenants`;

  constructor(private http: HttpClient) {}

  get(tenantId: number): Observable<TwilioProvider | null> {
    return this.http.get<TwilioProvider | null>(`${this.url}/${tenantId}/twilio`);
  }

  upsert(tenantId: number, provider: TwilioProvider): Observable<TwilioProvider> {
    return this.http.post<TwilioProvider>(`${this.url}/${tenantId}/twilio`, provider);
  }

  delete(tenantId: number): Observable<void> {
    return this.http.delete<void>(`${this.url}/${tenantId}/twilio`);
  }
}
