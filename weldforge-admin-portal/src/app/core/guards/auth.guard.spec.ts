import { TestBed } from '@angular/core/testing';
import { Router, UrlTree } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { of, throwError, firstValueFrom, isObservable, Observable } from 'rxjs';

import { authGuard } from './auth.guard';
import { AuthService } from '../services/auth.service';
import { ExternalNavigator } from '../external-navigator';
import { stashOidcContinuation } from '../oidc-continuation';
import { TokenRefreshScheduler } from './../services/token-refresh.scheduler';
import { environment } from '../../../environments/environment';

function token(claims: Record<string, unknown>): string {
  const b64 = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${b64({ alg: 'HS512' })}.${b64(claims)}.sig`;
}

const LOGIN_TREE = { __urlTree: '/login' } as unknown as UrlTree;

/**
 * 2026-10-12: signing in with Google looped. The OAuth2 callback 302s, so the
 * SPA never sees a response body and localStorage stays empty -- while the
 * session cookies are set and the session is perfectly good. The guard sent
 * the user to /login, they signed in with Google again, and round it went,
 * with no error logged on either side.
 */
describe('authGuard', () => {
  let router: { createUrlTree: ReturnType<typeof vi.fn> };
  let post: ReturnType<typeof vi.fn>;
  let externalNav: { go: ReturnType<typeof vi.fn> };

  // The guard reads the continuation stash on every path now, so a value left
  // by one spec would steer the next. Cleared here rather than in run(),
  // because the specs that use it stash before calling run().
  beforeEach(() => sessionStorage.clear());

  function run(opts: { storedToken?: string; refresh?: Observable<unknown> }) {
    localStorage.clear();
    if (opts.storedToken) localStorage.setItem('access_token', opts.storedToken);
    TestBed.resetTestingModule();
    router = { createUrlTree: vi.fn().mockReturnValue(LOGIN_TREE) };
    externalNav = { go: vi.fn() };
    post = vi.fn().mockReturnValue(opts.refresh ?? of(null));
    TestBed.configureTestingModule({
      providers: [
        AuthService,
        { provide: HttpClient, useValue: { post, get: vi.fn() } },
        { provide: TokenRefreshScheduler, useValue: { scheduleFromToken: vi.fn(), cancel: vi.fn() } },
        { provide: Router, useValue: router },
        { provide: ExternalNavigator, useValue: externalNav },
      ],
    });
    return TestBed.runInInjectionContext(
        () => authGuard({} as never, { url: '/tenants' } as never));
  }

  async function settle(result: unknown) {
    return isObservable(result) ? await firstValueFrom(result) : result;
  }

  it('lets a stored session straight through, with no extra request', () => {
    const result = run({ storedToken: token({ adm: 'SUPER_ADMIN' }) });

    expect(result).toBe(true);
    expect(post).not.toHaveBeenCalled();
  });

  it('adopts a cookie-only session instead of bouncing to login', async () => {
    const fresh = token({ adm: 'NONE', tenant: 'counteract-studios' });
    const result = await settle(run({ refresh: of({ token: fresh, expiresIn: 900 }) }));

    expect(result).toBe(true);
    // The whole point: the token is now in hand, so the next navigation is
    // not another round trip and not another trip through Google.
    expect(localStorage.getItem('access_token')).toBe(fresh);
  });

  it('goes to login, keeping the destination, when there is no session at all', async () => {
    const result = await settle(run({ refresh: throwError(() => ({ status: 401 })) }));

    expect(result).toBe(LOGIN_TREE);
    expect(router.createUrlTree).toHaveBeenCalledWith(['/login'], { queryParams: { returnUrl: '/tenants' } });
    expect(localStorage.getItem('access_token')).toBeNull();
  });

  it('treats a refresh that answers without a token as signed out', async () => {
    const result = await settle(run({ refresh: of({ expiresIn: 900 }) }));

    expect(result).toBe(LOGIN_TREE);
  });

  describe('resuming an interrupted OIDC flow', () => {
    // Built from the configured base domain, because that is what the guard
    // validates against -- it takes no baseDomain argument, so a hard-coded
    // production host would only pass by coincidence of configuration.
    const AUTHORIZE =
        `https://${environment.publicBaseDomain}/t/counteract-studios/oauth2/authorize?client_id=counter-shot`;
    const enc = (u: string) => btoa(u).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    beforeEach(() => sessionStorage.clear());

    it('sends a social sign-in back to the application it started from', async () => {
      // Started at counter.shot, bounced here, signed in with Google. The
      // provider cannot carry the continuation, so the login screen left it
      // in sessionStorage before redirecting.
      stashOidcContinuation(enc(AUTHORIZE));
      const result = await settle(run({ refresh: of({ token: token({}), expiresIn: 900 }) }));

      expect(externalNav.go).toHaveBeenCalledWith(AUTHORIZE);
      // The navigation is cancelled: the browser is leaving.
      expect(result).toBe(false);
    });

    it('resumes even when a token from an earlier sign-in is still in localStorage', async () => {
      // The production failure of 2026-10-12. localStorage is per origin, not
      // per tab: he had signed in on this host an hour earlier and never
      // logged out, so the guard saw a token the moment Google sent him back
      // and let him through before anything looked at the stash. He landed on
      // the portal instead of counter.shot, with no error anywhere.
      stashOidcContinuation(enc(AUTHORIZE));
      const result = run({ storedToken: token({ adm: 'SUPER_ADMIN' }) });

      expect(externalNav.go).toHaveBeenCalledWith(AUTHORIZE);
      expect(result).toBe(false);
      // Still no round trip: the session in hand is a perfectly good one.
      expect(post).not.toHaveBeenCalled();
    });

    it('renders the portal normally when no flow was interrupted', async () => {
      const result = await settle(run({ refresh: of({ token: token({}), expiresIn: 900 }) }));

      expect(externalNav.go).not.toHaveBeenCalled();
      expect(result).toBe(true);
    });

    it('does not leave the origin for a continuation naming a foreign host', async () => {
      sessionStorage.setItem('wf_oidc_continuation',
          JSON.stringify({ raw: enc('https://evil.example/phish'), at: Date.now() }));
      const result = await settle(run({ refresh: of({ token: token({}), expiresIn: 900 }) }));

      expect(externalNav.go).not.toHaveBeenCalled();
      expect(result).toBe(true);
    });
  });
});
