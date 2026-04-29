import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface AuditEvent {
  id: number;
  tenantSlug?: string;
  actorUserId?: number;
  actorEmail?: string;
  actorIsSuperAdmin?: boolean;
  eventType: string;
  targetType?: string;
  targetId?: string;
  outcome: 'SUCCESS' | 'FAILURE' | 'DENIED';
  metadata?: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
  createdAt: string;
}

export interface AuditPage {
  content: AuditEvent[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
}

export interface AuditFilter {
  eventType?: string;
  actorEmail?: string;
  since?: string;
  until?: string;
  page?: number;
  size?: number;
}

@Injectable({ providedIn: 'root' })
export class AuditService {
  private url = `${environment.apiBaseUrl}/api/admin/audit`;

  constructor(private http: HttpClient) {}

  search(filter: AuditFilter): Observable<AuditPage> {
    let params = new HttpParams();
    Object.entries(filter).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') params = params.set(k, String(v));
    });
    return this.http.get<AuditPage>(this.url, { params });
  }

  exportCsvUrl(filter: AuditFilter): string {
    const query = new URLSearchParams();
    Object.entries(filter).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') query.set(k, String(v));
    });
    const qs = query.toString();
    return `${this.url}/export.csv${qs ? '?' + qs : ''}`;
  }
}
