import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';

export interface RefreshResponse {
  token: string;
  expiresIn: number;
}

/**
 * The tenant of the session in local storage -- the one a refresh renews.
 * Read straight from the token, expired or not: an expired access token is
 * exactly when we refresh, and it still names its tenant.
 */
export function storedSessionTenant(): string | null {
  try {
    const token = localStorage.getItem('access_token');
    if (!token) return null;
    const payload = token.split('.')[1];
    if (!payload) return null;
    const claims = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    return typeof claims.tenant === 'string' && claims.tenant ? claims.tenant : null;
  } catch {
    return null;
  }
}

/**
 * POST /api/auth/refresh for THIS session's tenant (B-TEN-7).
 *
 * The backend keeps one refresh cookie per tenant and answers a refresh only
 * for the tenant the request names. On a tenant's own subdomain the host
 * names it; on the apex -- where this portal runs -- nothing does, and a
 * refresh would fall to `default`. So name it: the tenant of the session we
 * hold. Without that, a tenant admin signed in on the apex could not refresh,
 * and before the backend fix a refresh here could come back as whichever
 * tenant the browser had signed in to last.
 */
export function refreshSession(http: HttpClient): Observable<RefreshResponse> {
  const tenant = storedSessionTenant();
  return http.post<RefreshResponse>(
    `${environment.apiBaseUrl}/api/auth/refresh`,
    null,
    {
      withCredentials: true,
      ...(tenant ? { headers: { 'X-Tenant-Slug': tenant } } : {}),
    },
  );
}
