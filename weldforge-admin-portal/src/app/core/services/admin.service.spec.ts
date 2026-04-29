import { describe, it, expect, beforeEach, vi } from 'vitest';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { AdminService, User, Role } from './admin.service';

describe('AdminService', () => {
  let http: { post: any; get: any; delete: any; put: any };
  let service: AdminService;

  beforeEach(() => {
    http = { post: vi.fn(), get: vi.fn(), delete: vi.fn(), put: vi.fn() };
    service = new AdminService(http as unknown as HttpClient);
  });

  describe('getUsers', () => {
    it('fetches all users from the admin API', () => {
      const users: User[] = [
        { id: 1, email: 'alice@test.com', name: 'Alice', provider: 'LOCAL', providerId: '1' },
      ];
      http.get.mockReturnValue(of(users));

      let observed: User[] | undefined;
      service.getUsers().subscribe(r => (observed = r));

      expect(http.get).toHaveBeenCalledWith(expect.stringContaining('/api/admin/users'));
      expect(observed).toEqual(users);
    });
  });

  describe('getRoles', () => {
    it('fetches all roles from the admin API', () => {
      const roles: Role[] = [{ id: 1, name: 'ADMIN', description: 'Administrator' }];
      http.get.mockReturnValue(of(roles));

      let observed: Role[] | undefined;
      service.getRoles().subscribe(r => (observed = r));

      expect(http.get).toHaveBeenCalledWith(expect.stringContaining('/api/admin/roles'));
      expect(observed).toEqual(roles);
    });
  });

  describe('createRole', () => {
    it('posts a new role to the admin API', () => {
      const created: Role = { id: 5, name: 'EDITOR', description: 'Can edit' };
      http.post.mockReturnValue(of(created));

      let observed: Role | undefined;
      service.createRole({ name: 'EDITOR', description: 'Can edit' }).subscribe(r => (observed = r));

      expect(http.post).toHaveBeenCalledWith(
        expect.stringContaining('/api/admin/roles'),
        { name: 'EDITOR', description: 'Can edit' }
      );
      expect(observed).toEqual(created);
    });
  });

  describe('deleteUser', () => {
    it('sends a DELETE request for the given user id', () => {
      http.delete.mockReturnValue(of(undefined));

      service.deleteUser(42).subscribe();

      expect(http.delete).toHaveBeenCalledWith(expect.stringContaining('/api/admin/users/42'));
    });
  });

  describe('resetUserMfa', () => {
    it('posts to the reset-mfa endpoint and returns the removed count', () => {
      http.post.mockReturnValue(of({ removed: 3 }));

      let removed = 0;
      service.resetUserMfa(7).subscribe(r => (removed = r.removed));

      expect(http.post).toHaveBeenCalledWith(
        expect.stringContaining('/api/admin/users/7/reset-mfa'),
        {}
      );
      expect(removed).toBe(3);
    });
  });
});
