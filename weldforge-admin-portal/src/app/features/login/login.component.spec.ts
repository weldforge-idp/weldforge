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
 * be copied, so they are kept deliberately plain: no TestBed helper module, no
 * shared harness, just overridden providers.
 *
 * WHY THIS EXISTS
 * `login.component.goToApp()` carried an open redirect: it assigned
 * `window.location.href` straight from an attacker-supplied query parameter.
 * The decision was fixed in #75 and unit-tested via `resolvePostAuthTarget`, but
 * the *wiring* was not — nothing proved the component actually consults that
 * decision, or that a hostile continuation fails to leave the origin. The
 * absence of any component-test infrastructure is precisely why the bug lived
 * as long as it did, so the coverage gap was the real defect.
 *
 * The redirect is asserted through `ExternalNavigator`, which exists as a
 * testing seam: `window.location.href` assignment is not observable in jsdom.
 *
 * base domain: the spec relies on `environment.publicBaseDomain`, which is
 * 'localhost' in the dev environment file used by tests. The continuations
 * below are therefore localhost URLs — a real authorize URL on
 * sso.weldforge.org would (correctly) be rejected against that base.
 */

function b64url(s: string): string {
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** https, on the configured base domain -> accepted by safeOidcReturnUrl. */
const LEGITIMATE = 'https://localhost/t/acme/oauth2/authorize?client_id=app';
/** Somewhere else entirely -> must be refused. */
const HOSTILE = 'https://evil.example/phish';

describe('LoginComponent — post-authentication redirect', () => {
  let externalNav: { go: ReturnType<typeof vi.fn> };
  let router: { navigate: ReturnType<typeof vi.fn> };
  let queryParams: Record<string, string>;

  function createComponent() {
    TestBed.configureTestingModule({
      imports: [LoginComponent],
      providers: [
        { provide: AuthService, useValue: { login: vi.fn(), verifyMfa: vi.fn() } },
        {
          provide: TenantBrandingService,
          useValue: { current: signal(null), slugFromHost: () => null, load: () => of(null) },
        },
        { provide: Router, useValue: router },
        { provide: ExternalNavigator, useValue: externalNav },
        { provide: ActivatedRoute, useValue: { snapshot: { queryParams, queryParamMap: new Map() } } },
      ],
    });
    return TestBed.createComponent(LoginComponent).componentInstance as LoginComponent;
  }

  /** goToApp is private; the security behaviour is what is under test, not its visibility. */
  function goToApp(c: LoginComponent) {
    (c as unknown as { goToApp: () => void }).goToApp();
  }

  beforeEach(() => {
    TestBed.resetTestingModule();
    externalNav = { go: vi.fn() };
    router = { navigate: vi.fn() };
    queryParams = {};
  });

  it('does NOT leave the origin for a hostile continuation', () => {
    // The exact attack #75 closed: an attacker-supplied oidcReturnTo pointing
    // off-site, redirecting the victim the moment they authenticate.
    queryParams = { oidcReturnTo: b64url(HOSTILE) };
    goToApp(createComponent());

    expect(externalNav.go).not.toHaveBeenCalled();
    expect(router.navigate).toHaveBeenCalledWith(['/tenants']);
  });

  it('does NOT leave the origin for a lookalike host', () => {
    queryParams = { oidcReturnTo: b64url('https://localhost.evil.example/phish') };
    goToApp(createComponent());

    expect(externalNav.go).not.toHaveBeenCalled();
    expect(router.navigate).toHaveBeenCalledWith(['/tenants']);
  });

  it('returns the user to the calling application for a legitimate continuation', () => {
    queryParams = { oidcReturnTo: b64url(LEGITIMATE) };
    goToApp(createComponent());

    expect(externalNav.go).toHaveBeenCalledWith(LEGITIMATE);
    expect(router.navigate).not.toHaveBeenCalled();
  });

  it('falls back to the portal when there is no continuation', () => {
    goToApp(createComponent());

    expect(externalNav.go).not.toHaveBeenCalled();
    expect(router.navigate).toHaveBeenCalledWith(['/tenants']);
  });

  it('honours an in-app returnUrl but refuses a protocol-relative one', () => {
    queryParams = { returnUrl: '/tenants/42/users' };
    goToApp(createComponent());
    expect(router.navigate).toHaveBeenCalledWith(['/tenants/42/users']);

    TestBed.resetTestingModule();
    router = { navigate: vi.fn() };
    externalNav = { go: vi.fn() };
    queryParams = { returnUrl: '//evil.example' };
    goToApp(createComponent());
    expect(router.navigate).toHaveBeenCalledWith(['/tenants']);
    expect(externalNav.go).not.toHaveBeenCalled();
  });

  it('malformed base64 degrades to the portal rather than throwing', () => {
    queryParams = { oidcReturnTo: '!!!not-base64!!!' };
    expect(() => goToApp(createComponent())).not.toThrow();
    expect(externalNav.go).not.toHaveBeenCalled();
    expect(router.navigate).toHaveBeenCalledWith(['/tenants']);
  });
});
