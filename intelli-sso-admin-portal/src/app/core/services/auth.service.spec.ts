import { describe, it, expect, beforeEach, vi } from 'vitest';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { AuthService, AuthResponse } from './auth.service';

/**
 * Unit tests for the AuthService login flow — with extra attention to the
 * MFA-required branch, which must NOT store an access token in localStorage
 * (that would defeat the second-factor step).
 */
describe('AuthService', () => {
  let http: { post: any; get: any; delete: any };
  let service: AuthService;

  beforeEach(() => {
    http = { post: vi.fn(), get: vi.fn(), delete: vi.fn() };
    service = new AuthService(http as unknown as HttpClient);
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
    it('clears the stored access token', () => {
      localStorage.setItem('access_token', 'stale');
      service.logout();
      expect(localStorage.getItem('access_token')).toBeNull();
      expect(service.isLoggedIn()).toBe(false);
    });
  });
});
