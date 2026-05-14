import { describe, it, expect, beforeEach, vi } from 'vitest';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { SamlIdpService, SamlIdpServiceProvider } from './saml-idp.service';

const TENANT_ID = 11;

describe('SamlIdpService', () => {
  let http: { post: any; get: any; delete: any; put: any };
  let service: SamlIdpService;

  beforeEach(() => {
    http = { post: vi.fn(), get: vi.fn(), delete: vi.fn(), put: vi.fn() };
    service = new SamlIdpService(http as unknown as HttpClient);
  });

  describe('list', () => {
    it('fetches all SAML service providers for the given tenant', () => {
      const sps: SamlIdpServiceProvider[] = [
        { entityId: 'https://sp.test/metadata', acsUrl: 'https://sp.test/acs', name: 'Test SP' },
      ];
      http.get.mockReturnValue(of(sps));

      let observed: SamlIdpServiceProvider[] | undefined;
      service.list(TENANT_ID).subscribe(r => (observed = r));

      expect(http.get).toHaveBeenCalledWith(
        expect.stringContaining(`/api/admin/tenants/${TENANT_ID}/saml/service-providers`),
      );
      expect(observed).toEqual(sps);
    });
  });

  describe('create', () => {
    it('posts a new service provider to the tenant-scoped URL', () => {
      const input: SamlIdpServiceProvider = {
        entityId: 'https://new-sp.test/metadata',
        acsUrl: 'https://new-sp.test/acs',
        name: 'New SP',
      };
      const created = { ...input, id: 1, enabled: true };
      http.post.mockReturnValue(of(created));

      let observed: SamlIdpServiceProvider | undefined;
      service.create(TENANT_ID, input).subscribe(r => (observed = r));

      expect(http.post).toHaveBeenCalledWith(
        expect.stringContaining(`/api/admin/tenants/${TENANT_ID}/saml/service-providers`),
        input,
      );
      expect(observed).toEqual(created);
    });
  });

  describe('update', () => {
    it('sends a PUT request to the tenant-scoped URL with the updated service provider', () => {
      const updated: SamlIdpServiceProvider = {
        entityId: 'https://sp.test/metadata',
        acsUrl: 'https://sp.test/acs-v2',
        name: 'Updated SP',
      };
      http.put.mockReturnValue(of({ ...updated, id: 5 }));

      service.update(TENANT_ID, 5, updated).subscribe();

      expect(http.put).toHaveBeenCalledWith(
        expect.stringContaining(`/api/admin/tenants/${TENANT_ID}/saml/service-providers/5`),
        updated,
      );
    });
  });

  describe('delete', () => {
    it('sends a DELETE request to the tenant-scoped endpoint for the given service provider id', () => {
      http.delete.mockReturnValue(of(undefined));

      service.delete(TENANT_ID, 12).subscribe();

      expect(http.delete).toHaveBeenCalledWith(
        expect.stringContaining(`/api/admin/tenants/${TENANT_ID}/saml/service-providers/12`),
      );
    });
  });

  describe('importMetadata', () => {
    it('posts to the tenant-scoped import-metadata endpoint', () => {
      const parsed: SamlIdpServiceProvider = {
        entityId: 'https://parsed.test', acsUrl: 'https://parsed.test/acs', name: 'Parsed',
      };
      http.post.mockReturnValue(of(parsed));

      let observed: SamlIdpServiceProvider | undefined;
      service.importMetadata(TENANT_ID, { metadataXml: '<xml/>' }).subscribe(r => (observed = r));

      expect(http.post).toHaveBeenCalledWith(
        expect.stringContaining(`/api/admin/tenants/${TENANT_ID}/saml/service-providers/import-metadata`),
        { metadataXml: '<xml/>' },
      );
      expect(observed).toEqual(parsed);
    });
  });
});
