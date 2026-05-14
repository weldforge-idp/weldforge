import { describe, it, expect, beforeEach, vi } from 'vitest';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { OidcClientService, OidcClient } from './oidc-client.service';

const TENANT_ID = 42;

describe('OidcClientService', () => {
  let http: { post: any; get: any; delete: any; put: any };
  let service: OidcClientService;

  beforeEach(() => {
    http = { post: vi.fn(), get: vi.fn(), delete: vi.fn(), put: vi.fn() };
    service = new OidcClientService(http as unknown as HttpClient);
  });

  describe('list', () => {
    it('fetches all OIDC clients for the given tenant', () => {
      const clients: OidcClient[] = [
        { clientId: 'web-app', redirectUris: ['http://localhost/cb'], scopes: ['openid'], grantTypes: ['authorization_code'] },
      ];
      http.get.mockReturnValue(of(clients));

      let observed: OidcClient[] | undefined;
      service.list(TENANT_ID).subscribe(r => (observed = r));

      expect(http.get).toHaveBeenCalledWith(expect.stringContaining(`/api/admin/tenants/${TENANT_ID}/oidc/clients`));
      expect(observed).toEqual(clients);
    });
  });

  describe('create', () => {
    it('posts a new OIDC client to the tenant-scoped URL and returns the created resource with secret', () => {
      const input: OidcClient = {
        clientId: 'new-app',
        redirectUris: ['https://app.test/callback'],
        scopes: ['openid', 'profile'],
        grantTypes: ['authorization_code'],
        requirePkce: true,
      };
      const created: OidcClient = { ...input, id: 1, clientSecret: 'secret-abc' };
      http.post.mockReturnValue(of(created));

      let observed: OidcClient | undefined;
      service.create(TENANT_ID, input).subscribe(r => (observed = r));

      expect(http.post).toHaveBeenCalledWith(
        expect.stringContaining(`/api/admin/tenants/${TENANT_ID}/oidc/clients`),
        input
      );
      expect(observed!.clientSecret).toBe('secret-abc');
    });
  });

  describe('rotateSecret', () => {
    it('posts to the tenant-scoped rotate-secret endpoint and returns the updated client', () => {
      const rotated: OidcClient = {
        id: 1, clientId: 'web-app', clientSecret: 'new-secret',
        redirectUris: [], scopes: [], grantTypes: [],
      };
      http.post.mockReturnValue(of(rotated));

      let observed: OidcClient | undefined;
      service.rotateSecret(TENANT_ID, 1).subscribe(r => (observed = r));

      expect(http.post).toHaveBeenCalledWith(
        expect.stringContaining(`/api/admin/tenants/${TENANT_ID}/oidc/clients/1/rotate-secret`),
        {}
      );
      expect(observed!.clientSecret).toBe('new-secret');
    });
  });

  describe('delete', () => {
    it('sends a DELETE request to the tenant-scoped endpoint for the given client id', () => {
      http.delete.mockReturnValue(of(undefined));

      service.delete(TENANT_ID, 99).subscribe();

      expect(http.delete).toHaveBeenCalledWith(
        expect.stringContaining(`/api/admin/tenants/${TENANT_ID}/oidc/clients/99`),
      );
    });
  });
});
