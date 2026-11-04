import { describe, it, expect, beforeEach, vi } from 'vitest';
import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Router } from '@angular/router';

import { authInterceptor } from './auth.interceptor';
import { TokenRefreshScheduler } from '../services/token-refresh.scheduler';
import { resetSharedRefresh } from '../session-refresh';
import { environment } from '../../../environments/environment';

/**
 * B-AUTH-6 (F61). The interceptor treats a 401 on an unlisted path as an
 * expired session: it refreshes, replays, fails again, clears the token and
 * navigates to /login?reason=session_expired.
 *
 * That is right for an expired token and wrong for an endpoint that
 * re-verifies the account password inside the request, where a 401 is a
 * verdict on what the user just typed. /api/auth/mfa/reset was a live
 * instance — F60 made it answer 401 for a wrong password or a wrong factor
 * code, so the "Password or code incorrect" message it added to the security
 * panel could never render: the user was signed out first and told their
 * session had expired.
 *
 * These tests pin both halves: the two password-re-verifying endpoints pass
 * their 401 through untouched, and an ordinary API path still refreshes — so
 * the allowlist cannot quietly grow into "never refresh anything".
 */
describe('authInterceptor: a 401 that means "wrong credential", not "expired session"', () => {
  let http: HttpClient;
  let ctl: HttpTestingController;
  let navigate: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    localStorage.clear();
    localStorage.setItem('access_token', 'a-live-token');
    resetSharedRefresh();
    navigate = vi.fn();

    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        { provide: Router, useValue: { navigate, url: '/security' } },
        { provide: TokenRefreshScheduler, useValue: { cancel: vi.fn(), scheduleFromToken: vi.fn() } },
      ],
    });
    http = TestBed.inject(HttpClient);
    ctl = TestBed.inject(HttpTestingController);
  });

  for (const path of ['/api/auth/change-password', '/api/auth/mfa/reset']) {
    it(`passes a 401 from ${path} to the caller without refreshing or signing out`, async () => {
      const seen: number[] = [];
      http.post(`${environment.apiBaseUrl}${path}`, {}).subscribe({
        next: () => expect.unreachable('should have errored'),
        error: e => seen.push(e.status),
      });

      ctl.expectOne(`${environment.apiBaseUrl}${path}`).flush(
        { error: 'unauthorized', detail: 'Current password is incorrect' },
        { status: 401, statusText: 'Unauthorized' },
      );

      // The verdict reaches the component, which is what lets it show a
      // message instead of the user being bounced to the login screen.
      expect(seen).toEqual([401]);
      // No refresh was attempted, and the session survived.
      ctl.expectNone(`${environment.apiBaseUrl}/api/auth/refresh`);
      expect(navigate).not.toHaveBeenCalled();
      expect(localStorage.getItem('access_token')).toBe('a-live-token');
    });
  }

  it('still refreshes and replays a 401 on an ordinary API path', async () => {
    const url = `${environment.apiBaseUrl}/api/admin/users`;
    http.get(url).subscribe({ next: () => {}, error: () => {} });

    ctl.expectOne(url).flush(
      { error: 'unauthorized', detail: 'Authentication required' },
      { status: 401, statusText: 'Unauthorized' },
    );

    // The guard against the allowlist growing into "never refresh anything":
    // an unlisted path must still try to renew the session.
    ctl.expectOne(`${environment.apiBaseUrl}/api/auth/refresh`);
  });

  it('does not touch a 423 at all, so a locked account is never read as session expiry', async () => {
    const url = `${environment.apiBaseUrl}/api/auth/mfa/reset`;
    const seen: number[] = [];
    http.post(url, {}).subscribe({ next: () => {}, error: e => seen.push(e.status) });

    ctl.expectOne(url).flush(
      { error: 'account_locked', detail: 'Too many failed attempts.', retryAfterSeconds: 900 },
      { status: 423, statusText: 'Locked' },
    );

    expect(seen).toEqual([423]);
    ctl.expectNone(`${environment.apiBaseUrl}/api/auth/refresh`);
    expect(navigate).not.toHaveBeenCalled();
  });
});
