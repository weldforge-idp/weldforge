import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface GroupRoleMapping {
  id?: number;
  scimGroupId: number;
  scimGroupName?: string;
  roleId: number;
  roleName?: string;
  priority: number;
}

@Injectable({ providedIn: 'root' })
export class GroupRoleMappingService {
  constructor(private http: HttpClient) {}

  private url(tenantId: number): string {
    return `${environment.apiBaseUrl}/api/admin/tenants/${tenantId}/group-role-mappings`;
  }

  list(tenantId: number): Observable<GroupRoleMapping[]> {
    return this.http.get<GroupRoleMapping[]>(this.url(tenantId));
  }

  create(tenantId: number, mapping: Partial<GroupRoleMapping>): Observable<GroupRoleMapping> {
    return this.http.post<GroupRoleMapping>(this.url(tenantId), mapping);
  }

  delete(tenantId: number, id: number): Observable<void> {
    return this.http.delete<void>(`${this.url(tenantId)}/${id}`);
  }
}
