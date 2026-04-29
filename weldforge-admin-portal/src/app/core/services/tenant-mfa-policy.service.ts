import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export type MfaEnforcement = 'OPTIONAL' | 'REQUIRED' | 'RISK_ADAPTIVE';

export interface MfaPolicy {
  id?: number;
  tenantId?: number;
  enforcement: MfaEnforcement;
  gracePeriodDays: number;
  defaultStepupMaxAge: number;
}

@Injectable({ providedIn: 'root' })
export class TenantMfaPolicyService {
  private url = `${environment.apiBaseUrl}/api/admin/tenants`;

  constructor(private http: HttpClient) {}

  get(tenantId: number): Observable<MfaPolicy> {
    return this.http.get<MfaPolicy>(`${this.url}/${tenantId}/mfa-policy`);
  }

  upsert(tenantId: number, policy: MfaPolicy): Observable<MfaPolicy> {
    return this.http.post<MfaPolicy>(`${this.url}/${tenantId}/mfa-policy`, policy);
  }
}
