import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';

import { adminGuard } from './admin.guard';
import { AuthService } from '../services/auth.service';
import { TokenRefreshScheduler } from './../services/token-refresh.scheduler';
import { HttpClient } from '@angular/common/http';

/** An unsigned JWT with the given claims -- the portal never verifies signatures. */
function token(claims: Record<string, unknown>): string {
  const b64 = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${b64({ alg: 'HS512' })}.${b64(claims)}.sig`;
}

/**
 * 2026-09-13: a signed-in account with no admin role saw the whole admin nav
 * and learned it had no access from an "Access denied" toast on every page.
 * The server refused correctly; the portal should not have offered the pages.
 */
describe('adminGuard', () => {
  let router: { navigate: ReturnType<typeof vi.fn> };

  function runWith(claims: Record<string, unknown> | null): boolean {
    localStorage.clear();
    if (claims) localStorage.setItem('access_token', token(claims));
    TestBed.resetTestingModule();
    router = { navigate: vi.fn() };
    TestBed.configureTestingModule({
      providers: [
        AuthService,
        { provide: HttpClient, useValue: { post: vi.fn(), get: vi.fn() } },
        { provide: TokenRefreshScheduler, useValue: { scheduleFromToken: vi.fn(), cancel: vi.fn() } },
        { provide: Router, useValue: router },
      ],
    });
    return TestBed.runInInjectionContext(
      () => adminGuard({} as never, {} as never)) as boolean;
  }

  it.each([
    { claims: { adm: 'SUPER_ADMIN' }, allowed: true },
    { claims: { sa: true }, allowed: true },
    { claims: { adm: 'TENANT_ADMIN' }, allowed: true },
    { claims: { adm: 'READ_ONLY' }, allowed: true },
    { claims: { adm: 'NONE' }, allowed: false },
    { claims: { sa: false }, allowed: false },
    { claims: {}, allowed: false },
  ])('adm=$claims.adm sa=$claims.sa -> allowed=$allowed', ({ claims, allowed }) => {
    expect(runWith(claims)).toBe(allowed);
  });

  it('sends a non-admin to its own Security page, not to login', () => {
    expect(runWith({ adm: 'NONE' })).toBe(false);
    expect(router.navigate).toHaveBeenCalledWith(['/security']);
  });

  it('does not let a session with no token through', () => {
    expect(runWith(null)).toBe(false);
  });
});
