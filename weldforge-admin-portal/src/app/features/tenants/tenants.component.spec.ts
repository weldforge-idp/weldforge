import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { MatSnackBar } from '@angular/material/snack-bar';
import { of } from 'rxjs';
import { provideAngularQuery, QueryClient } from '@tanstack/angular-query-experimental';

import { TenantsComponent } from './tenants.component';
import { TenantService, Tenant } from '../../core/services/tenant.service';
import { TenantTwilioService } from '../../core/services/tenant-twilio.service';
import { TenantMfaPolicyService } from '../../core/services/tenant-mfa-policy.service';
import { TenantPickerService } from '../../core/services/tenant-picker.service';
import { AuthService } from '../../core/services/auth.service';
import { tenantInterceptor } from '../../core/interceptors/tenant.interceptor';
import { environment } from '../../../environments/environment';

/**
 * Handover requirement 3 (2026-09-11): the OIDC clients and SAML SPs drawn
 * under a tenant's row belong to THAT tenant -- listed, created, rotated and
 * deleted with its slug on the wire, whatever the page-level picker says.
 *
 * Runs the real OidcClientService / SamlIdpService through the real tenant
 * interceptor, so these assert what actually leaves the browser.
 */
describe('TenantsComponent — row-scoped OIDC clients and SAML SPs', () => {
  const OIDC = `${environment.apiBaseUrl}/api/admin/oidc/clients`;
  const SPS = `${environment.apiBaseUrl}/api/admin/saml/service-providers`;
  const rowA: Tenant = { id: 1, slug: 'default', name: 'Default', enabled: true };
  const rowB: Tenant = { id: 9, slug: 'cwvermaak-tech', name: 'CW Vermaak Tech', enabled: true };

  let ctl: HttpTestingController;
  let snack: { open: ReturnType<typeof vi.fn> };
  let picked: string | null;

  type Row = Tenant & Record<string, unknown>;
  type Exposed = {
    ngOnInit(): void;
    tenants(): Row[];
    loadProviders(t: Row): void;
    oidcClientsFor(t: Row): { clientId: string }[];
    samlSpsFor(t: Row): { entityId: string }[];
    createOidcClient(t: Row): void;
    removeOidcClient(t: Row, c: { id?: number; clientId: string }): void;
    rotateOidcSecret(t: Row, c: { id?: number; clientId: string }): void;
    createSamlIdpSp(t: Row): void;
    newOidcClientId: string;
    newOidcRedirects: string;
    newOidcPublic: boolean;
    samlIdpDraft: { entityId: string; acsUrl: string };
  };

  function create(): Exposed {
    TestBed.resetTestingModule();
    snack = { open: vi.fn() };
    TestBed.configureTestingModule({
      imports: [TenantsComponent],
      providers: [
        provideHttpClient(withInterceptors([tenantInterceptor])),
        provideHttpClientTesting(),
        provideAngularQuery(new QueryClient()),
        {
          provide: TenantService, useValue: {
            list: vi.fn().mockReturnValue(of([rowA, rowB])),
            listProviders: vi.fn().mockReturnValue(of([])),
            listSamlProviders: vi.fn().mockReturnValue(of([])),
          },
        },
        { provide: TenantTwilioService, useValue: { get: vi.fn().mockReturnValue(of(null)) } },
        { provide: TenantMfaPolicyService, useValue: { get: vi.fn().mockReturnValue(of(null)) } },
        { provide: TenantPickerService, useValue: { outgoingSlug: () => picked } },
        { provide: AuthService, useValue: { getHomeTenantSlug: () => 'default', isSuperAdmin: () => true } },
        { provide: MatSnackBar, useValue: snack },
      ],
    });
    TestBed.overrideProvider(MatSnackBar, { useValue: snack });
    ctl = TestBed.inject(HttpTestingController);
    const c = TestBed.createComponent(TenantsComponent).componentInstance as unknown as Exposed;
    c.ngOnInit();
    return c;
  }

  beforeEach(() => {
    // The page-level picker points somewhere else entirely.
    picked = 'intellisuite';
    vi.spyOn(window, 'alert').mockImplementation(() => {});
    vi.spyOn(window, 'confirm').mockReturnValue(true);
  });

  afterEach(() => {
    ctl.verify();
    vi.restoreAllMocks();
  });

  const row = (c: Exposed, slug: string) => c.tenants().find(t => t.slug === slug)!;
  const acting = (slug: string) => ({ headers: { 'X-WF-Acting-Tenant': slug } });

  /** Expand a row and answer its two list calls. */
  function expand(c: Exposed, t: Row, clients: object[] = [], sps: object[] = []) {
    c.loadProviders(t);
    const list = ctl.expectOne(r => r.url === OIDC && r.method === 'GET');
    expect(list.request.headers.get('X-WF-Tenant')).toBe(t.slug);
    list.flush(clients, acting(t.slug));
    const spList = ctl.expectOne(r => r.url === SPS && r.method === 'GET');
    expect(spList.request.headers.get('X-WF-Tenant')).toBe(t.slug);
    spList.flush(sps, acting(t.slug));
  }

  it('loads nothing tenant-scoped on init -- only when a row is expanded', () => {
    create();
    ctl.expectNone(OIDC);
    ctl.expectNone(SPS);
  });

  it('keeps each row\'s lists apart', () => {
    const c = create();
    expand(c, row(c, 'default'), [{ id: 10, clientId: 'wf_client_stray' }]);
    expand(c, row(c, 'cwvermaak-tech'), [{ id: 11, clientId: 'keycrypt' }], [{ id: 3, entityId: 'urn:sp' }]);

    expect(c.oidcClientsFor(row(c, 'default')).map(x => x.clientId)).toEqual(['wf_client_stray']);
    expect(c.oidcClientsFor(row(c, 'cwvermaak-tech')).map(x => x.clientId)).toEqual(['keycrypt']);
    expect(c.samlSpsFor(row(c, 'default'))).toEqual([]);
    expect(c.samlSpsFor(row(c, 'cwvermaak-tech')).map(x => x.entityId)).toEqual(['urn:sp']);
  });

  it("creates an OIDC client in row B's tenant, regardless of the picker", () => {
    const c = create();
    const b = row(c, 'cwvermaak-tech');
    expand(c, b);
    c.newOidcClientId = 'keycrypt';
    c.newOidcRedirects = 'https://keycrypt.cwvermaak.tech/login/oauth2/code/weldforge';

    c.createOidcClient(b);

    const req = ctl.expectOne(r => r.url === OIDC && r.method === 'POST');
    expect(req.request.headers.get('X-WF-Tenant')).toBe('cwvermaak-tech');
    expect(req.request.body.clientId).toBe('keycrypt');
    expect(req.request.body.publicClient).toBe(false);
    expect(req.request.body.requirePkce).toBe(true);
    req.flush({ id: 12, clientId: 'keycrypt', clientSecret: 's3cret' }, acting('cwvermaak-tech'));

    expect(c.oidcClientsFor(b).map(x => x.clientId)).toEqual(['keycrypt']);
    expect(c.oidcClientsFor(row(c, 'default'))).toEqual([]);
    expect(window.alert).toHaveBeenCalledWith(expect.stringContaining('created in cwvermaak-tech'));
    expect(window.alert).toHaveBeenCalledWith(expect.stringContaining('s3cret'));
  });

  it('a public client is sent as public, with PKCE forced on, and no secret is shown', () => {
    const c = create();
    const b = row(c, 'cwvermaak-tech');
    expand(c, b);
    c.newOidcPublic = true;
    c.newOidcRedirects = 'https://spa.example/cb';

    c.createOidcClient(b);

    const req = ctl.expectOne(r => r.url === OIDC && r.method === 'POST');
    expect(req.request.body.publicClient).toBe(true);
    expect(req.request.body.requirePkce).toBe(true);
    req.flush({ id: 13, clientId: 'wf_client_x', publicClient: true }, acting('cwvermaak-tech'));

    const shown = (window.alert as unknown as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(shown).toContain('No secret was issued');
    expect(shown).not.toContain('undefined');
  });

  it('a create answered from another tenant is an error, and nothing is added to the row', () => {
    const c = create();
    const b = row(c, 'cwvermaak-tech');
    expand(c, b);
    c.newOidcRedirects = 'https://x.example/cb';

    c.createOidcClient(b);

    ctl.expectOne(r => r.url === OIDC && r.method === 'POST')
      .flush({ id: 14, clientId: 'wf_client_y', clientSecret: 's' }, acting('default'));

    expect(c.oidcClientsFor(b)).toEqual([]);
    expect(window.alert).not.toHaveBeenCalled();
    expect(snack.open).toHaveBeenCalledWith(expect.stringContaining("ran in tenant 'default'"), expect.anything(), expect.anything());
  });

  it("rotates and deletes in the row's tenant", () => {
    const c = create();
    const b = row(c, 'cwvermaak-tech');
    expand(c, b, [{ id: 11, clientId: 'keycrypt' }]);

    c.rotateOidcSecret(b, { id: 11, clientId: 'keycrypt' });
    const rotate = ctl.expectOne(`${OIDC}/11/rotate-secret`);
    expect(rotate.request.headers.get('X-WF-Tenant')).toBe('cwvermaak-tech');
    rotate.flush({ id: 11, clientId: 'keycrypt', clientSecret: 'new' }, acting('cwvermaak-tech'));

    c.removeOidcClient(b, { id: 11, clientId: 'keycrypt' });
    const del = ctl.expectOne(`${OIDC}/11`);
    expect(del.request.method).toBe('DELETE');
    expect(del.request.headers.get('X-WF-Tenant')).toBe('cwvermaak-tech');
    del.flush(null, acting('cwvermaak-tech'));

    expect(c.oidcClientsFor(b)).toEqual([]);
  });

  it("registers a SAML SP in the row's tenant", () => {
    const c = create();
    const b = row(c, 'cwvermaak-tech');
    expand(c, b);
    c.samlIdpDraft.entityId = 'urn:keycrypt';
    c.samlIdpDraft.acsUrl = 'https://keycrypt.example/acs';

    c.createSamlIdpSp(b);

    const req = ctl.expectOne(r => r.url === SPS && r.method === 'POST');
    expect(req.request.headers.get('X-WF-Tenant')).toBe('cwvermaak-tech');
    req.flush({ id: 4, entityId: 'urn:keycrypt', acsUrl: 'https://keycrypt.example/acs' }, acting('cwvermaak-tech'));
    expect(c.samlSpsFor(b).map(x => x.entityId)).toEqual(['urn:keycrypt']);
  });
});
