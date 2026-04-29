import { describe, it, expect, beforeEach, vi } from 'vitest';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { SamlIdpService, SamlIdpServiceProvider } from './saml-idp.service';

describe('SamlIdpService', () => {
  let http: { post: any; get: any; delete: any; put: any };
  let service: SamlIdpService;

  beforeEach(() => {
    http = { post: vi.fn(), get: vi.fn(), delete: vi.fn(), put: vi.fn() };
    service = new SamlIdpService(http as unknown as HttpClient);
  });

  describe('list', () => {
    it('fetches all SAML service providers', () => {
      const sps: SamlIdpServiceProvider[] = [
        { entityId: 'https://sp.test/metadata', acsUrl: 'https://sp.test/acs', name: 'Test SP' },
      ];
      http.get.mockReturnValue(of(sps));

      let observed: SamlIdpServiceProvider[] | undefined;
      service.list().subscribe(r => (observed = r));

      expect(http.get).toHaveBeenCalledWith(expect.stringContaining('/api/admin/saml/service-providers'));
      expect(observed).toEqual(sps);
    });
  });

  describe('create', () => {
    it('posts a new service provider', () => {
      const input: SamlIdpServiceProvider = {
        entityId: 'https://new-sp.test/metadata',
        acsUrl: 'https://new-sp.test/acs',
        name: 'New SP',
      };
      const created = { ...input, id: 1, enabled: true };
      http.post.mockReturnValue(of(created));

      let observed: SamlIdpServiceProvider | undefined;
      service.create(input).subscribe(r => (observed = r));

      expect(http.post).toHaveBeenCalledWith(
        expect.stringContaining('/api/admin/saml/service-providers'),
        input
      );
      expect(observed).toEqual(created);
    });
  });

  describe('update', () => {
    it('sends a PUT request with the updated service provider', () => {
      const updated: SamlIdpServiceProvider = {
        entityId: 'https://sp.test/metadata',
        acsUrl: 'https://sp.test/acs-v2',
        name: 'Updated SP',
      };
      http.put.mockReturnValue(of({ ...updated, id: 5 }));

      service.update(5, updated).subscribe();

      expect(http.put).toHaveBeenCalledWith(
        expect.stringContaining('/api/admin/saml/service-providers/5'),
        updated
      );
    });
  });

  describe('delete', () => {
    it('sends a DELETE request for the given service provider id', () => {
      http.delete.mockReturnValue(of(undefined));

      service.delete(12).subscribe();

      expect(http.delete).toHaveBeenCalledWith(
        expect.stringContaining('/api/admin/saml/service-providers/12')
      );
    });
  });
});
