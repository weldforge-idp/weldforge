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
  private apiUrl = `${environment.apiBaseUrl}/api/admin/group-role-mappings`;

  constructor(private http: HttpClient) {}

  list(): Observable<GroupRoleMapping[]> {
    return this.http.get<GroupRoleMapping[]>(this.apiUrl);
  }

  create(mapping: Partial<GroupRoleMapping>): Observable<GroupRoleMapping> {
    return this.http.post<GroupRoleMapping>(this.apiUrl, mapping);
  }

  delete(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`);
  }
}
