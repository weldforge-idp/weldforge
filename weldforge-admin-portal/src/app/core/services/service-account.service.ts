import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export type AdminRole = 'NONE' | 'READ_ONLY' | 'TENANT_ADMIN' | 'SUPER_ADMIN';

export interface ServiceAccount {
  id: number;
  name: string;
  description?: string;
  /** Returned only on create/rotate — the raw `wf_svc_*` token. */
  token?: string;
  tokenPrefix: string;
  adminRole: AdminRole;
  enabled: boolean;
  expiresAt?: string;
  createdAt?: string;
  lastUsedAt?: string;
}

export interface CreateServiceAccountDto {
  name: string;
  description?: string;
  adminRole: AdminRole;
  enabled?: boolean;
  expiresAt?: string;
}

export interface UpdateServiceAccountDto {
  description?: string;
  enabled?: boolean;
  adminRole?: AdminRole;
  expiresAt?: string;
}

@Injectable({ providedIn: 'root' })
export class ServiceAccountApi {
  private http = inject(HttpClient);
  private url = `${environment.apiBaseUrl}/api/admin/service-accounts`;

  list(): Observable<ServiceAccount[]> {
    return this.http.get<ServiceAccount[]>(this.url);
  }

  create(dto: CreateServiceAccountDto): Observable<ServiceAccount> {
    return this.http.post<ServiceAccount>(this.url, dto);
  }

  update(id: number, dto: UpdateServiceAccountDto): Observable<ServiceAccount> {
    return this.http.put<ServiceAccount>(`${this.url}/${id}`, dto);
  }

  rotate(id: number): Observable<ServiceAccount> {
    return this.http.post<ServiceAccount>(`${this.url}/${id}/rotate`, {});
  }

  delete(id: number): Observable<void> {
    return this.http.delete<void>(`${this.url}/${id}`);
  }
}
