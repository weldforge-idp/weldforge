import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, of, tap } from 'rxjs';
import { environment } from '../../../environments/environment';
import { TokenRefreshScheduler } from './token-refresh.scheduler';

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

  constructor(
    private http: HttpClient,
    private scheduler: TokenRefreshScheduler,
  ) {
    // If a token is already in localStorage (page reload while logged
    // in, or new tab opened with a live session), schedule the next
    // proactive refresh immediately so the user doesn't see a 401
    // round-trip on their first request.
    const existing = this.getAccessToken();
    if (existing) this.scheduler.scheduleFromToken(existing);
  }

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

  /**
   * Hit POST /api/auth/logout-all to revoke the refresh-token family
   * server-side (so the cookie left in the browser cannot be used to
   * silently rotate a new session), then cancel the proactive refresh
   * timer and clear the local access token. We don't wait on the
   * network call's result before clearing local state — if it fails
   * (network down, server already revoked the family) we still want
   * the user logged out client-side.
   *
   * /logout-all kills every session for the user, not just the current
   * one. That's the right primitive for an admin portal: clicking
   * Logout there is unambiguous "I want to be signed out everywhere".
   */
  logout(): Observable<unknown> {
    const obs = this.http
      .post(`${this.url}/logout-all`, null, { withCredentials: true })
      .pipe(catchError(() => of(null)));
    this.scheduler.cancel();
    localStorage.removeItem('access_token');
    return obs;
  }

  getAccessToken(): string | null {
    return localStorage.getItem('access_token');
  }

  /**
   * Decode the JWT payload (no signature verification — that happens
   * server-side; this is only ever used to drive UI gating). Returns
   * null if the token is missing or unparseable.
   */
  getJwtClaims(): JwtClaims | null {
    const token = this.getAccessToken();
    if (!token) return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    try {
      const json = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
      return JSON.parse(json) as JwtClaims;
    } catch {
      return null;
    }
  }

  /** True when the JWT carries `sa: true` or `adm: SUPER_ADMIN`. */
  isSuperAdmin(): boolean {
    const c = this.getJwtClaims();
    if (!c) return false;
    return c.sa === true || c.adm === 'SUPER_ADMIN';
  }

  /** The tenant slug the JWT was issued against (the user's "home" tenant). */
  getHomeTenantSlug(): string | null {
    return this.getJwtClaims()?.tenant ?? null;
  }

  /** The numeric tenant id the JWT was issued against. */
  getHomeTenantId(): number | null {
    return this.getJwtClaims()?.tid ?? null;
  }

  private storeIfAccess(res: AuthResponse) {
    if (res && res.token && !res.mfaRequired) {
      localStorage.setItem('access_token', res.token);
      this.scheduler.scheduleFromToken(res.token);
    }
  }
}

interface JwtClaims {
  sub?: string;
  tenant?: string;
  tid?: number;
  sa?: boolean;
  adm?: 'NONE' | 'READ_ONLY' | 'TENANT_ADMIN' | 'SUPER_ADMIN';
  exp?: number;
  iat?: number;
}
