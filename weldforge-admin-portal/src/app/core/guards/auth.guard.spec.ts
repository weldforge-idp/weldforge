import { TestBed } from '@angular/core/testing';
import { Router, UrlTree } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { of, throwError, firstValueFrom, isObservable, Observable } from 'rxjs';

import { authGuard } from './auth.guard';
import { AuthService } from '../services/auth.service';
import { TokenRefreshScheduler } from './../services/token-refresh.scheduler';

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

  function run(opts: { storedToken?: string; refresh?: Observable<unknown> }) {
    localStorage.clear();
    if (opts.storedToken) localStorage.setItem('access_token', opts.storedToken);
    TestBed.resetTestingModule();
    router = { createUrlTree: vi.fn().mockReturnValue(LOGIN_TREE) };
    post = vi.fn().mockReturnValue(opts.refresh ?? of(null));
    TestBed.configureTestingModule({
      providers: [
        AuthService,
        { provide: HttpClient, useValue: { post, get: vi.fn() } },
        { provide: TokenRefreshScheduler, useValue: { scheduleFromToken: vi.fn(), cancel: vi.fn() } },
        { provide: Router, useValue: router },
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
});
