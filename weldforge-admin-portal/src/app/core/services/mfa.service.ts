import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export type MfaFactorType = 'TOTP' | 'WEBAUTHN';

export interface MfaFactor {
  id: number;
  type: MfaFactorType;
  label?: string;
  enabled: boolean;
  verified: boolean;
  createdAt?: string;
  lastUsedAt?: string;
}

export interface TotpEnrollResponse {
  factorId: number;
  secret: string;
  qrDataUri: string;
}

@Injectable({ providedIn: 'root' })
export class MfaService {
  private url = `${environment.apiBaseUrl}/api/auth/mfa`;

  constructor(private http: HttpClient) {}

  listFactors(): Observable<MfaFactor[]> {
    return this.http.get<MfaFactor[]>(`${this.url}/factors`);
  }

  deleteFactor(id: number): Observable<void> {
    return this.http.delete<void>(`${this.url}/factors/${id}`);
  }

  enrollTotp(label?: string): Observable<TotpEnrollResponse> {
    return this.http.post<TotpEnrollResponse>(`${this.url}/totp/enroll`, { label: label ?? '' });
  }

  activateTotp(factorId: number, code: string): Observable<MfaFactor> {
    return this.http.post<MfaFactor>(`${this.url}/totp/activate`, { factorId, code });
  }

  regenerateBackupCodes(): Observable<{ codes: string[]; remaining: number }> {
    return this.http.post<{ codes: string[]; remaining: number }>(
      `${this.url}/backup-codes/regenerate`, {});
  }

  backupCodeStatus(): Observable<{ remaining: number }> {
    return this.http.get<{ remaining: number }>(`${this.url}/backup-codes`);
  }

  selfReset(password: string): Observable<{ removed: number }> {
    return this.http.post<{ removed: number }>(`${this.url}/reset`, { password });
  }

  // ---- WebAuthn registration ceremony ------------------------------

  startWebauthnRegistration(label?: string): Observable<{ ceremonyKey: string; publicKey: string }> {
    return this.http.post<{ ceremonyKey: string; publicKey: string }>(
      `${this.url}/webauthn/registration/start`, { label: label ?? '' });
  }

  finishWebauthnRegistration(ceremonyKey: string, publicKeyCredential: string, label?: string): Observable<MfaFactor> {
    return this.http.post<MfaFactor>(
      `${this.url}/webauthn/registration/finish`,
      { ceremonyKey, publicKeyCredential, label: label ?? 'Security key' });
  }
}
