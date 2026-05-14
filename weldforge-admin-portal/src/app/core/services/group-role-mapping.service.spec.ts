import { describe, it, expect, beforeEach, vi } from 'vitest';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { GroupRoleMappingService, GroupRoleMapping } from './group-role-mapping.service';

const TENANT_ID = 7;

describe('GroupRoleMappingService', () => {
  let http: { post: any; get: any; delete: any; put: any };
  let service: GroupRoleMappingService;

  beforeEach(() => {
    http = { post: vi.fn(), get: vi.fn(), delete: vi.fn(), put: vi.fn() };
    service = new GroupRoleMappingService(http as unknown as HttpClient);
  });

  describe('list', () => {
    it('fetches all group-role mappings for the given tenant', () => {
      const mappings: GroupRoleMapping[] = [
        { id: 1, scimGroupId: 10, scimGroupName: 'Engineering', roleId: 2, roleName: 'DEVELOPER', priority: 1 },
      ];
      http.get.mockReturnValue(of(mappings));

      let observed: GroupRoleMapping[] | undefined;
      service.list(TENANT_ID).subscribe(r => (observed = r));

      expect(http.get).toHaveBeenCalledWith(
        expect.stringContaining(`/api/admin/tenants/${TENANT_ID}/group-role-mappings`),
      );
      expect(observed).toEqual(mappings);
    });
  });

  describe('create', () => {
    it('posts a new mapping to the tenant-scoped URL and returns the created resource', () => {
      const input: Partial<GroupRoleMapping> = { scimGroupId: 10, roleId: 2, priority: 1 };
      const created: GroupRoleMapping = { id: 5, scimGroupId: 10, roleId: 2, priority: 1 };
      http.post.mockReturnValue(of(created));

      let observed: GroupRoleMapping | undefined;
      service.create(TENANT_ID, input).subscribe(r => (observed = r));

      expect(http.post).toHaveBeenCalledWith(
        expect.stringContaining(`/api/admin/tenants/${TENANT_ID}/group-role-mappings`),
        input,
      );
      expect(observed).toEqual(created);
    });
  });

  describe('delete', () => {
    it('sends a DELETE request to the tenant-scoped endpoint for the given mapping id', () => {
      http.delete.mockReturnValue(of(undefined));

      service.delete(TENANT_ID, 5).subscribe();

      expect(http.delete).toHaveBeenCalledWith(
        expect.stringContaining(`/api/admin/tenants/${TENANT_ID}/group-role-mappings/5`),
      );
    });
  });
});
