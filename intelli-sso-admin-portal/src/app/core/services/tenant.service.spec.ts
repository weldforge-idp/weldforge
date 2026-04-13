import { describe, it, expect, beforeEach, vi } from 'vitest';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { TenantService, Tenant, SocialProvider, SamlProvider } from './tenant.service';

describe('TenantService', () => {
  let http: { post: any; get: any; delete: any; put: any };
  let service: TenantService;

  beforeEach(() => {
    http = { post: vi.fn(), get: vi.fn(), delete: vi.fn(), put: vi.fn() };
    service = new TenantService(http as unknown as HttpClient);
  });

  describe('list', () => {
    it('fetches all tenants', () => {
      const tenants: Tenant[] = [
        { id: 1, slug: 'acme', name: 'Acme Corp', enabled: true },
      ];
      http.get.mockReturnValue(of(tenants));

      let observed: Tenant[] | undefined;
      service.list().subscribe(r => (observed = r));

      expect(http.get).toHaveBeenCalledWith(expect.stringContaining('/api/admin/tenants'));
      expect(observed).toEqual(tenants);
    });
  });

  describe('create', () => {
    it('posts a new tenant', () => {
      const created: Tenant = { id: 2, slug: 'beta', name: 'Beta Inc', enabled: true };
      http.post.mockReturnValue(of(created));

      let observed: Tenant | undefined;
      service.create({ slug: 'beta', name: 'Beta Inc' }).subscribe(r => (observed = r));

      expect(http.post).toHaveBeenCalledWith(
        expect.stringContaining('/api/admin/tenants'),
        { slug: 'beta', name: 'Beta Inc' }
      );
      expect(observed).toEqual(created);
    });
  });

  describe('delete', () => {
    it('sends a DELETE request for the given tenant id', () => {
      http.delete.mockReturnValue(of(undefined));

      service.delete(3).subscribe();

      expect(http.delete).toHaveBeenCalledWith(expect.stringContaining('/api/admin/tenants/3'));
    });
  });

  describe('listProviders', () => {
    it('fetches social providers for a tenant', () => {
      const providers: SocialProvider[] = [
        { provider: 'GOOGLE', clientId: 'goog-123', enabled: true },
      ];
      http.get.mockReturnValue(of(providers));

      let observed: SocialProvider[] | undefined;
      service.listProviders(5).subscribe(r => (observed = r));

      expect(http.get).toHaveBeenCalledWith(
        expect.stringContaining('/api/admin/tenants/5/social-providers')
      );
      expect(observed).toEqual(providers);
    });
  });

  describe('upsertProvider', () => {
    it('posts a social provider config for the tenant', () => {
      const provider: SocialProvider = { provider: 'GITHUB', clientId: 'gh-abc', enabled: true };
      const saved: SocialProvider = { ...provider, id: 10, tenantId: 5 };
      http.post.mockReturnValue(of(saved));

      let observed: SocialProvider | undefined;
      service.upsertProvider(5, provider).subscribe(r => (observed = r));

      expect(http.post).toHaveBeenCalledWith(
        expect.stringContaining('/api/admin/tenants/5/social-providers'),
        provider
      );
      expect(observed).toEqual(saved);
    });
  });

  describe('listSamlProviders', () => {
    it('fetches SAML providers for a tenant', () => {
      const providers: SamlProvider[] = [
        { providerKey: 'okta', enabled: true },
      ];
      http.get.mockReturnValue(of(providers));

      let observed: SamlProvider[] | undefined;
      service.listSamlProviders(8).subscribe(r => (observed = r));

      expect(http.get).toHaveBeenCalledWith(
        expect.stringContaining('/api/admin/tenants/8/saml-providers')
      );
      expect(observed).toEqual(providers);
    });
  });

  describe('upsertSamlProvider', () => {
    it('posts a SAML provider config for the tenant', () => {
      const provider: SamlProvider = { providerKey: 'azure-ad', enabled: true };
      const saved: SamlProvider = { ...provider, id: 20, tenantId: 8 };
      http.post.mockReturnValue(of(saved));

      let observed: SamlProvider | undefined;
      service.upsertSamlProvider(8, provider).subscribe(r => (observed = r));

      expect(http.post).toHaveBeenCalledWith(
        expect.stringContaining('/api/admin/tenants/8/saml-providers'),
        provider
      );
      expect(observed).toEqual(saved);
    });
  });
});
