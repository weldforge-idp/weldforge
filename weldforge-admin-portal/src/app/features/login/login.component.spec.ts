import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router } from '@angular/router';
import { of } from 'rxjs';
import { signal } from '@angular/core';

import { LoginComponent } from './login.component';
import { AuthService } from '../../core/services/auth.service';
import { TenantBrandingService } from '../../core/services/tenant-branding.service';
import { ExternalNavigator } from '../../core/external-navigator';

/**
 * The FIRST component spec in this codebase — the conventions here are meant to
 * be copied, so they are kept deliberately plain: no helper module, no shared
 * harness, just overridden providers.
 *
 * WHY THIS EXISTS
 * `login.component` carried an open redirect: it assigned `window.location.href`
 * straight from an attacker-supplied query parameter. #75 fixed the decision and
 * unit-tested it via `resolvePostAuthTarget`; these specs cover the part unit
 * tests cannot — that the component actually consults that decision on the paths
 * a real user takes.
 *
 * DRIVEN THROUGH THE PUBLIC ENTRY POINTS ON PURPOSE.
 * `goToApp()` is private and reached only from `submitCredentials()` (password
 * login) and `submitMfa()` (after a TOTP challenge). Calling it directly with a
 * cast would leave exactly the gap this file is meant to close: nothing would
 * notice if a future edit stopped calling it, or redirected some other way after
 * a successful login. So every case below authenticates the way a user does.
 *
 * The redirect is asserted through `ExternalNavigator`, which exists as a
 * testing seam — assigning `window.location.href` is not observable in jsdom.
 *
 * BASE DOMAIN: assertions run against `environment.publicBaseDomain`, which is
 * 'localhost' in the environment file used by tests. Hence localhost
 * continuations; a real `sso.weldforge.org` authorize URL would correctly be
 * REJECTED against that base.
 */

function b64url(s: string): string {
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** https, on the configured base domain -> accepted by safeOidcReturnUrl. */
const LEGITIMATE = 'https://localhost/t/acme/oauth2/authorize?client_id=app';

describe('LoginComponent — post-authentication redirect', () => {
  let externalNav: { go: ReturnType<typeof vi.fn> };
  let router: { navigate: ReturnType<typeof vi.fn> };
  let auth: { login: ReturnType<typeof vi.fn>; verifyMfa: ReturnType<typeof vi.fn> };

  /** Builds the component with the given URL query parameters. */
  function componentWith(queryParams: Record<string, string>): LoginComponent {
    TestBed.resetTestingModule();
    externalNav = { go: vi.fn() };
    router = { navigate: vi.fn() };
    auth = {
      // A successful password login: token present, no MFA required.
      login: vi.fn().mockReturnValue(of({ token: 'test-token' })),
      verifyMfa: vi.fn().mockReturnValue(of({ token: 'test-token' })),
    };

    TestBed.configureTestingModule({
      imports: [LoginComponent],
      providers: [
        { provide: AuthService, useValue: auth },
        {
          provide: TenantBrandingService,
          useValue: { current: signal(null), slugFromHost: () => null, load: () => of(null) },
        },
        { provide: Router, useValue: router },
        { provide: ExternalNavigator, useValue: externalNav },
        { provide: ActivatedRoute, useValue: { snapshot: { queryParams } } },
      ],
    });
    return TestBed.createComponent(LoginComponent).componentInstance as LoginComponent;
  }

  /** Authenticate the way a user does: username + password. */
  function logIn(queryParams: Record<string, string> = {}): void {
    componentWith(queryParams).submitCredentials();
  }

  describe('refuses to leave the origin', () => {
    it('for a hostile continuation', () => {
      // The exact attack #75 closed: attacker-supplied oidcReturnTo pointing
      // off-site, redirecting the victim the instant they authenticate.
      logIn({ oidcReturnTo: b64url('https://evil.example/phish') });

      expect(externalNav.go).not.toHaveBeenCalled();
      expect(router.navigate).toHaveBeenCalledWith(['/tenants']);
    });

    it('for a lookalike host', () => {
      logIn({ oidcReturnTo: b64url('https://localhost.evil.example/phish') });

      expect(externalNav.go).not.toHaveBeenCalled();
      expect(router.navigate).toHaveBeenCalledWith(['/tenants']);
    });

    it('for a non-https continuation', () => {
      logIn({ oidcReturnTo: b64url('http://localhost/t/acme/oauth2/authorize') });

      expect(externalNav.go).not.toHaveBeenCalled();
      expect(router.navigate).toHaveBeenCalledWith(['/tenants']);
    });

    it('for a protocol-relative returnUrl', () => {
      logIn({ returnUrl: '//evil.example' });

      expect(externalNav.go).not.toHaveBeenCalled();
      expect(router.navigate).toHaveBeenCalledWith(['/tenants']);
    });
  });

  describe('completes the flow it is supposed to', () => {
    it('returns the user to the calling application after password login', () => {
      logIn({ oidcReturnTo: b64url(LEGITIMATE) });

      expect(externalNav.go).toHaveBeenCalledWith(LEGITIMATE);
      expect(router.navigate).not.toHaveBeenCalled();
    });

    it('returns the user to the calling application after MFA', () => {
      // Second entry point: goToApp() is also reached from submitMfa(), so the
      // continuation must survive a TOTP challenge as well.
      const c = componentWith({ oidcReturnTo: b64url(LEGITIMATE) });
      (c as unknown as { challengeToken: string | null }).challengeToken = 'challenge';
      c.submitMfa();

      expect(auth.verifyMfa).toHaveBeenCalled();
      expect(externalNav.go).toHaveBeenCalledWith(LEGITIMATE);
    });

    it('honours an in-app returnUrl', () => {
      logIn({ returnUrl: '/tenants/42/users' });

      expect(router.navigate).toHaveBeenCalledWith(['/tenants/42/users']);
      expect(externalNav.go).not.toHaveBeenCalled();
    });

    it('falls back to the portal when there is no continuation', () => {
      logIn();

      expect(externalNav.go).not.toHaveBeenCalled();
      expect(router.navigate).toHaveBeenCalledWith(['/tenants']);
    });
  });

  describe('degrades safely', () => {
    it('sends the user to the portal on malformed base64 rather than throwing', () => {
      expect(() => logIn({ oidcReturnTo: '!!!not-base64!!!' })).not.toThrow();

      expect(externalNav.go).not.toHaveBeenCalled();
      expect(router.navigate).toHaveBeenCalledWith(['/tenants']);
    });

    it('does not redirect at all when MFA is still outstanding', () => {
      // mfaRequired and no token: authentication is incomplete, so nothing
      // should navigate anywhere yet.
      const c = componentWith({ oidcReturnTo: b64url(LEGITIMATE) });
      auth.login.mockReturnValue(of({ mfaRequired: true, mfaChallengeToken: 'c', availableFactors: [] }));
      c.submitCredentials();

      expect(externalNav.go).not.toHaveBeenCalled();
      expect(router.navigate).not.toHaveBeenCalled();
    });
  });
});
