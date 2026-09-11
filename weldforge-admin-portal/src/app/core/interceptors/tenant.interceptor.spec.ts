import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TestBed } from '@angular/core/testing';
import { HttpClient, HttpErrorResponse, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import { tenantInterceptor } from './tenant.interceptor';
import { TenantPickerService } from '../services/tenant-picker.service';
import { AuthService } from '../services/auth.service';
import { forTenant } from '../tenant-selector';

/**
 * The 2026-09-11 incident: an admin write aimed at another tenant carried no
 * selector and landed in the home tenant with a 200. These pin down which
 * tenant each call names, and that a response from any other tenant is an
 * error, not a success.
 */
describe('tenantInterceptor', () => {
  let http: HttpClient;
  let ctl: HttpTestingController;
  let picked: string | null;

  beforeEach(() => {
    picked = null;
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([tenantInterceptor])),
        provideHttpClientTesting(),
        { provide: TenantPickerService, useValue: { outgoingSlug: () => picked } },
        { provide: AuthService, useValue: { getHomeTenantSlug: () => 'default' } },
      ],
    });
    http = TestBed.inject(HttpClient);
    ctl = TestBed.inject(HttpTestingController);
  });

  afterEach(() => ctl.verify());

  const ADMIN = '/api/admin/oidc/clients';

  describe('which tenant an admin call names', () => {
    it("sends the request's own tenant, whatever the picker says", () => {
      picked = 'intellisuite';
      http.post(ADMIN, {}, forTenant('cwvermaak-tech')).subscribe();

      const req = ctl.expectOne(ADMIN);
      expect(req.request.headers.get('X-WF-Tenant')).toBe('cwvermaak-tech');
      req.flush({});
    });

    it('falls back to the picker for page-level calls', () => {
      picked = 'intellisuite';
      http.get(ADMIN).subscribe();

      const req = ctl.expectOne(ADMIN);
      expect(req.request.headers.get('X-WF-Tenant')).toBe('intellisuite');
      req.flush([]);
    });

    it('sends no selector when there is neither (non-super-admin): the JWT decides', () => {
      http.get(ADMIN).subscribe();

      const req = ctl.expectOne(ADMIN);
      expect(req.request.headers.has('X-WF-Tenant')).toBe(false);
      expect(req.request.headers.has('X-Tenant-Slug')).toBe(false);
      req.flush([]);
    });

    it('never uses the legacy X-Tenant-Slug channel for admin calls', () => {
      picked = 'intellisuite';
      http.get(ADMIN).subscribe();

      const req = ctl.expectOne(ADMIN);
      expect(req.request.headers.has('X-Tenant-Slug')).toBe(false);
      req.flush([]);
    });
  });

  describe('non-admin calls', () => {
    it('do not carry the picker: acting-as is an admin concept', () => {
      picked = 'intellisuite';
      http.post('/api/auth/login', {}).subscribe();

      const req = ctl.expectOne('/api/auth/login');
      expect(req.request.headers.has('X-WF-Tenant')).toBe(false);
      expect(req.request.headers.get('X-Tenant-Slug')).not.toBe('intellisuite');
      req.flush({});
    });

    it('keep an X-Tenant-Slug the caller set explicitly', () => {
      http.get('/api/auth/tenants/leap/branding', { headers: { 'X-Tenant-Slug': 'leap' } }).subscribe();

      const req = ctl.expectOne('/api/auth/tenants/leap/branding');
      expect(req.request.headers.get('X-Tenant-Slug')).toBe('leap');
      req.flush({});
    });

    it('leave non-API URLs alone', () => {
      picked = 'intellisuite';
      http.get('/assets/config.json').subscribe();

      const req = ctl.expectOne('/assets/config.json');
      expect(req.request.headers.keys()).toEqual([]);
      req.flush({});
    });
  });

  describe('the acting-tenant echo', () => {
    function call(target: string | null, acting: string | null) {
      let ok: unknown;
      let failed: HttpErrorResponse | undefined;
      http.post(ADMIN, {}, target ? forTenant(target) : {}).subscribe({
        next: v => (ok = v),
        error: e => (failed = e),
      });
      ctl.expectOne(ADMIN).flush({ id: 10 }, {
        headers: acting ? { 'X-WF-Acting-Tenant': acting } : {},
      });
      return { ok, failed };
    }

    it('passes a response from the tenant that was named', () => {
      const { ok, failed } = call('cwvermaak-tech', 'cwvermaak-tech');
      expect(failed).toBeUndefined();
      expect(ok).toEqual({ id: 10 });
    });

    it('turns a response from another tenant into a 409 tenant_mismatch', () => {
      const { ok, failed } = call('cwvermaak-tech', 'default');
      expect(ok).toBeUndefined();
      expect(failed?.status).toBe(409);
      expect(failed?.error.error).toBe('tenant_mismatch');
      expect(failed?.error.detail).toContain("'default'");
      expect(failed?.error.detail).toContain("'cwvermaak-tech'");
    });

    it('without a selector, expects the home tenant', () => {
      expect(call(null, 'default').failed).toBeUndefined();
      expect(call(null, 'intellisuite').failed?.status).toBe(409);
    });

    it('compares case-insensitively', () => {
      expect(call('cwvermaak-tech', 'CWVermaak-Tech').failed).toBeUndefined();
    });

    it('tolerates a backend that does not echo yet', () => {
      expect(call('cwvermaak-tech', null).failed).toBeUndefined();
    });
  });
});
