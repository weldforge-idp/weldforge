import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export type AdminRole = 'NONE' | 'READ_ONLY' | 'TENANT_ADMIN' | 'SUPER_ADMIN';

export interface ServiceAccount {
  id: number;
  name: string;
  description?: string;
  /** Slug of the tenant this service account is scoped to. */
  tenantSlug?: string;
  /** Human-readable name of the scoping tenant. */
  tenantName?: string;
  /** Returned only on create/rotate — the raw `wf_svc_*` token. */
  token?: string;
  tokenPrefix: string;
  adminRole: AdminRole;
  enabled: boolean;
  expiresAt?: string;
  createdAt?: string;
  lastUsedAt?: string;
}

/**
 * Requested token lifetime. 0 means the token never expires; omitting both
 * fields leaves an existing expiry alone.
 */
export interface TokenLifetime {
  expiresInDays?: number;
  expiresInHours?: number;
}

export interface CreateServiceAccountDto extends TokenLifetime {
  name: string;
  description?: string;
  adminRole: AdminRole;
  enabled?: boolean;
  expiresAt?: string;
}

export interface UpdateServiceAccountDto extends TokenLifetime {
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

  /**
   * Mint a fresh token. Pass a lifetime to reset the expiry at the same time;
   * omit it to keep whatever the account already has.
   *
   * Rotating an already-expired account without a lifetime is refused by the
   * server, because it would hand back another token that cannot authenticate.
   */
  rotate(id: number, lifetime?: TokenLifetime): Observable<ServiceAccount> {
    return this.http.post<ServiceAccount>(`${this.url}/${id}/rotate`, lifetime ?? {});
  }

  delete(id: number): Observable<void> {
    return this.http.delete<void>(`${this.url}/${id}`);
  }
}
