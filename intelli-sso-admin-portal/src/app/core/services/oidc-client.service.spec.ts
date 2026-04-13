import { describe, it, expect, beforeEach, vi } from 'vitest';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { OidcClientService, OidcClient } from './oidc-client.service';

describe('OidcClientService', () => {
  let http: { post: any; get: any; delete: any; put: any };
  let service: OidcClientService;

  beforeEach(() => {
    http = { post: vi.fn(), get: vi.fn(), delete: vi.fn(), put: vi.fn() };
    service = new OidcClientService(http as unknown as HttpClient);
  });

  describe('list', () => {
    it('fetches all OIDC clients', () => {
      const clients: OidcClient[] = [
        { clientId: 'web-app', redirectUris: ['http://localhost/cb'], scopes: ['openid'], grantTypes: ['authorization_code'] },
      ];
      http.get.mockReturnValue(of(clients));

      let observed: OidcClient[] | undefined;
      service.list().subscribe(r => (observed = r));

      expect(http.get).toHaveBeenCalledWith(expect.stringContaining('/api/admin/oidc/clients'));
      expect(observed).toEqual(clients);
    });
  });

  describe('create', () => {
    it('posts a new OIDC client and returns the created resource with secret', () => {
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
      service.create(input).subscribe(r => (observed = r));

      expect(http.post).toHaveBeenCalledWith(
        expect.stringContaining('/api/admin/oidc/clients'),
        input
      );
      expect(observed!.clientSecret).toBe('secret-abc');
    });
  });

  describe('rotateSecret', () => {
    it('posts to the rotate-secret endpoint and returns the updated client', () => {
      const rotated: OidcClient = {
        id: 1, clientId: 'web-app', clientSecret: 'new-secret',
        redirectUris: [], scopes: [], grantTypes: [],
      };
      http.post.mockReturnValue(of(rotated));

      let observed: OidcClient | undefined;
      service.rotateSecret(1).subscribe(r => (observed = r));

      expect(http.post).toHaveBeenCalledWith(
        expect.stringContaining('/api/admin/oidc/clients/1/rotate-secret'),
        {}
      );
      expect(observed!.clientSecret).toBe('new-secret');
    });
  });

  describe('delete', () => {
    it('sends a DELETE request for the given client id', () => {
      http.delete.mockReturnValue(of(undefined));

      service.delete(99).subscribe();

      expect(http.delete).toHaveBeenCalledWith(expect.stringContaining('/api/admin/oidc/clients/99'));
    });
  });
});
