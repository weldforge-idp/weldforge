import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import { Subject, firstValueFrom, of } from 'rxjs';

import {
  RefreshResponse,
  refreshSession,
  resetSharedRefresh,
  sharedRefresh,
  storedSessionTenant,
} from './session-refresh';
import { tenantInterceptor } from './interceptors/tenant.interceptor';
import { TenantPickerService } from './services/tenant-picker.service';
import { AuthService } from './services/auth.service';
import { environment } from '../../environments/environment';

/** An unsigned JWT with the given payload -- the portal never verifies signatures. */
function token(claims: Record<string, unknown>): string {
  const b64 = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${b64({ alg: 'HS512' })}.${b64(claims)}.sig`;
}

/**
 * B-TEN-7: a refresh names the tenant of the session it renews. The backend
 * keeps one refresh cookie per tenant and answers only for the tenant the
 * request names; on the apex, where the portal runs, nothing else names it.
 */
describe('refreshSession', () => {
  const URL = `${environment.apiBaseUrl}/api/auth/refresh`;
  let http: HttpClient;
  let ctl: HttpTestingController;

  beforeEach(() => {
    localStorage.clear();
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [
        // With the real tenant interceptor, so the header survives it.
        provideHttpClient(withInterceptors([tenantInterceptor])),
        provideHttpClientTesting(),
        { provide: TenantPickerService, useValue: { outgoingSlug: () => 'picked-elsewhere' } },
        { provide: AuthService, useValue: { getHomeTenantSlug: () => null } },
      ],
    });
    http = TestBed.inject(HttpClient);
    ctl = TestBed.inject(HttpTestingController);
  });

  afterEach(() => ctl.verify());

  it("names the stored session's tenant, sends cookies, and ignores the picker", () => {
    localStorage.setItem('access_token', token({ tenant: 'cwvermaak-tech', exp: 1 }));

    refreshSession(http).subscribe();

    const req = ctl.expectOne(URL);
    expect(req.request.method).toBe('POST');
    expect(req.request.withCredentials).toBe(true);
    expect(req.request.headers.get('X-Tenant-Slug')).toBe('cwvermaak-tech');
    expect(req.request.headers.has('X-WF-Tenant')).toBe(false);
    req.flush({ token: 't', expiresIn: 300 });
  });

  it('sends no tenant when there is no stored session (the host decides)', () => {
    refreshSession(http).subscribe();

    const req = ctl.expectOne(URL);
    expect(req.request.headers.has('X-Tenant-Slug')).toBe(false);
    req.flush({ token: 't', expiresIn: 300 });
  });

  it('reads the tenant from an expired token too -- that is when we refresh', () => {
    localStorage.setItem('access_token', token({ tenant: 'leap', exp: 1 }));
    expect(storedSessionTenant()).toBe('leap');
  });

  it('tolerates garbage in storage', () => {
    localStorage.setItem('access_token', 'not-a-jwt');
    expect(storedSessionTenant()).toBeNull();
    localStorage.setItem('access_token', 'a.@@@.c');
    expect(storedSessionTenant()).toBeNull();
    localStorage.setItem('access_token', token({ tenant: 42 }));
    expect(storedSessionTenant()).toBeNull();
  });
});

/**
 * The refresh cookie is single-use and rotates. A second concurrent
 * redemption is read by the server as theft, and it revokes the whole
 * family -- killing the session the winning rotation just created. That is
 * deliberate (B-AUTH-6) and is not going to change, so the client's job is
 * to never redeem it twice at once.
 *
 * Production, 2026-10-12, 20ms apart, straight after a Google sign-in:
 *   11:40:13.264  Refresh token reuse detected: family 336c90b1 revoked
 *   11:40:13.284  auth.refresh.rotate  SUCCESS
 *   11:40:13.466  jwt_session_terminated
 */
describe('sharedRefresh', () => {
  let post: ReturnType<typeof vi.fn>;
  let http: HttpClient;

  beforeEach(() => {
    resetSharedRefresh();
    localStorage.clear();
    post = vi.fn();
    http = { post } as unknown as HttpClient;
  });

  it('redeems the cookie once however many callers ask at the same moment', async () => {
    const server = new Subject<RefreshResponse>();
    post.mockReturnValue(server);

    const callers = [sharedRefresh(http), sharedRefresh(http), sharedRefresh(http)]
        .map(o => firstValueFrom(o));

    expect(post).toHaveBeenCalledTimes(1);

    server.next({ token: 'fresh', expiresIn: 900 });
    server.complete();

    expect(await Promise.all(callers)).toEqual([
      { token: 'fresh', expiresIn: 900 },
      { token: 'fresh', expiresIn: 900 },
      { token: 'fresh', expiresIn: 900 },
    ]);
  });

  it('starts the request even if nobody subscribes to the returned observable', () => {
    post.mockReturnValue(new Subject<RefreshResponse>());

    sharedRefresh(http);

    expect(post).toHaveBeenCalledTimes(1);
  });

  it('redeems again once the previous one has finished', async () => {
    post.mockReturnValue(of({ token: 'first', expiresIn: 900 }));
    await firstValueFrom(sharedRefresh(http));

    post.mockReturnValue(of({ token: 'second', expiresIn: 900 }));
    const again = await firstValueFrom(sharedRefresh(http));

    expect(post).toHaveBeenCalledTimes(2);
    expect(again.token).toBe('second');
  });

  it('gives every waiting caller the same failure, and does not wedge', async () => {
    const server = new Subject<RefreshResponse>();
    post.mockReturnValue(server);

    const a = firstValueFrom(sharedRefresh(http)).catch(e => e);
    const b = firstValueFrom(sharedRefresh(http)).catch(e => e);
    server.error({ status: 401 });

    expect(await a).toEqual({ status: 401 });
    expect(await b).toEqual({ status: 401 });

    // A failed refresh must not leave the door latched shut.
    post.mockReturnValue(of({ token: 'later', expiresIn: 900 }));
    expect((await firstValueFrom(sharedRefresh(http))).token).toBe('later');
  });
});
