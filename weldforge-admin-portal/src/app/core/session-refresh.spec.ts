import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import { refreshSession, storedSessionTenant } from './session-refresh';
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
