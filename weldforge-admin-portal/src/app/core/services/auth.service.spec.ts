import { describe, it, expect, beforeEach, vi } from 'vitest';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { AuthService, AuthResponse } from './auth.service';
import { TokenRefreshScheduler } from './token-refresh.scheduler';

/**
 * Unit tests for the AuthService login flow — with extra attention to the
 * MFA-required branch, which must NOT store an access token in localStorage
 * (that would defeat the second-factor step).
 */
describe('AuthService', () => {
  let http: { post: any; get: any; delete: any };
  let scheduler: { scheduleFromToken: any; cancel: any };
  let service: AuthService;

  beforeEach(() => {
    http = { post: vi.fn(), get: vi.fn(), delete: vi.fn() };
    scheduler = { scheduleFromToken: vi.fn(), cancel: vi.fn() };
    service = new AuthService(
      http as unknown as HttpClient,
      scheduler as unknown as TokenRefreshScheduler,
    );
    localStorage.clear();
  });

  describe('login', () => {
    it('stores the access token on a plain success response', () => {
      const response: AuthResponse = { token: 'tok-123', expiresIn: 300 };
      http.post.mockReturnValue(of(response));

      let observed: AuthResponse | undefined;
      service.login({ identifier: 'alice@acme.test', password: 'secret' })
        .subscribe(r => (observed = r));

      expect(observed).toEqual(response);
      expect(localStorage.getItem('access_token')).toBe('tok-123');
      expect(service.isLoggedIn()).toBe(true);
    });

    it('does NOT store an access token when MFA is required', () => {
      // Critical security invariant: when the backend says "mfaRequired",
      // the returned payload is a challenge token, not an access token.
      // Storing it would let the user bypass the second factor.
      const response: AuthResponse = {
        mfaRequired: true,
        mfaChallengeToken: 'challenge-xyz',
        availableFactors: ['TOTP'],
      };
      http.post.mockReturnValue(of(response));

      service.login({ identifier: 'alice@acme.test', password: 'secret' }).subscribe();

      expect(localStorage.getItem('access_token')).toBeNull();
      expect(service.isLoggedIn()).toBe(false);
    });
  });

  describe('verifyMfa', () => {
    it('stores the access token returned after successful MFA', () => {
      const response: AuthResponse = { token: 'tok-after-mfa', expiresIn: 300 };
      http.post.mockReturnValue(of(response));

      service.verifyMfa({
        challengeToken: 'challenge-xyz',
        type: 'TOTP',
        code: '123456',
      }).subscribe();

      expect(localStorage.getItem('access_token')).toBe('tok-after-mfa');
      expect(service.isLoggedIn()).toBe(true);
    });
  });

  describe('logout', () => {
    it('clears local state synchronously and posts /logout-all to revoke the refresh family', () => {
      // /logout-all returns a count of revoked refresh tokens; logout
      // ignores the body but still has to subscribe so the request goes
      // out, which the AppComponent click handler does.
      http.post.mockReturnValue(of({ refreshTokensRevoked: 2 }));
      localStorage.setItem('access_token', 'stale');

      service.logout().subscribe();

      expect(localStorage.getItem('access_token')).toBeNull();
      expect(service.isLoggedIn()).toBe(false);
      expect(scheduler.cancel).toHaveBeenCalled();
      // First arg = URL, second = body (null), third = options.
      expect(http.post.mock.calls[0][0]).toMatch(/\/api\/auth\/logout-all$/);
    });

    it('still clears local state if /logout-all fails (offline, server already revoked)', () => {
      http.post.mockReturnValue({
        pipe: () => ({ subscribe: () => undefined }),
      });
      localStorage.setItem('access_token', 'stale');

      // Should not throw even when the http call errors.
      expect(() => service.logout().subscribe()).not.toThrow();
      expect(localStorage.getItem('access_token')).toBeNull();
    });
  });

  describe('hasAdminAccess', () => {
    /** An unsigned JWT; the portal never verifies signatures. */
    const token = (claims: Record<string, unknown>) => {
      const b64 = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
      return `${b64({ alg: 'HS512' })}.${b64(claims)}.sig`;
    };

    it.each([
      { claims: { adm: 'SUPER_ADMIN' }, expected: true },
      { claims: { sa: true }, expected: true },
      { claims: { adm: 'TENANT_ADMIN' }, expected: true },
      { claims: { adm: 'READ_ONLY' }, expected: true },
      { claims: { adm: 'NONE' }, expected: false },
      { claims: { sa: false, adm: 'NONE' }, expected: false },
      { claims: {}, expected: false },
    ])('$claims -> $expected', ({ claims, expected }) => {
      localStorage.setItem('access_token', token(claims));
      expect(service.hasAdminAccess()).toBe(expected);
    });

    it('is false with no session at all', () => {
      localStorage.clear();
      expect(service.hasAdminAccess()).toBe(false);
    });
  });
});
