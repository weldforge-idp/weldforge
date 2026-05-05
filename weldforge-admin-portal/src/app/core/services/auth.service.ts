import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, tap } from 'rxjs';
import { environment } from '../../../environments/environment';

export type MfaFactorType = 'TOTP' | 'WEBAUTHN';

export interface AuthResponse {
  token?: string;
  expiresIn?: number;
  mfaRequired?: boolean;
  mfaChallengeToken?: string;
  availableFactors?: MfaFactorType[];
}

export interface LoginCredentials {
  identifier: string;
  password: string;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private url = `${environment.apiBaseUrl}/api/auth`;

  constructor(private http: HttpClient) {}

  isLoggedIn(): boolean {
    return !!localStorage.getItem('access_token');
  }

  login(credentials: LoginCredentials): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.url}/login`, credentials).pipe(
      tap(res => this.storeIfAccess(res))
    );
  }

  verifyMfa(body: {
    challengeToken: string;
    type: MfaFactorType;
    code?: string;
    backupCode?: string;
    webauthnResponse?: string;
  }): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.url}/mfa/verify`, body).pipe(
      tap(res => this.storeIfAccess(res))
    );
  }

  register(body: { name: string; email: string; password: string }): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.url}/register`, body).pipe(
      tap(res => this.storeIfAccess(res))
    );
  }

  forgotPassword(email: string): Observable<{ message: string }> {
    return this.http.post<{ message: string }>(`${this.url}/forgot-password`, { email });
  }

  resetPassword(token: string, newPassword: string): Observable<{ message: string }> {
    return this.http.post<{ message: string }>(`${this.url}/reset-password`, { token, newPassword });
  }

  verifyEmail(token: string): Observable<{ message: string }> {
    return this.http.post<{ message: string }>(`${this.url}/verify-email`, { token });
  }

  resendVerification(email: string): Observable<{ message: string }> {
    return this.http.post<{ message: string }>(`${this.url}/resend-verification`, { email });
  }

  logout(): void {
    localStorage.removeItem('access_token');
  }

  getAccessToken(): string | null {
    return localStorage.getItem('access_token');
  }

  private storeIfAccess(res: AuthResponse) {
    if (res && res.token && !res.mfaRequired) {
      localStorage.setItem('access_token', res.token);
    }
  }
}
