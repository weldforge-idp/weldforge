import { HttpClient } from '@angular/common/http';
import { Observable, ReplaySubject, take } from 'rxjs';
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

/**
 * One in-flight refresh at a time, shared by every caller in this tab.
 *
 * The refresh token is single-use and rotates, and the server treats a
 * second redemption of the same token as theft: it revokes the whole
 * family, which kills the session that the winning rotation just created.
 * That is the correct behaviour (B-AUTH-6) and must not be softened. It
 * means the rule lives here: never redeem the cookie twice at once.
 *
 * Observed in production on 2026-10-12, 20ms apart, after a Google sign-in:
 *
 *   11:40:13.264  Refresh token reuse detected: family 336c90b1 revoked
 *   11:40:13.284  auth.refresh.rotate  SUCCESS
 *   11:40:13.466  jwt_session_terminated
 *
 * Two callers raced -- the auth guard adopting the cookie session and the
 * interceptor retrying a 401 -- the loser's failed claim revoked the family,
 * and the session died a fifth of a second after being issued. The
 * interceptor already collapsed its own concurrent 401s this way; the guard
 * was simply outside it. Going through one door is what makes that
 * structural rather than a matter of who calls what.
 */
let inFlight$: ReplaySubject<RefreshResponse> | null = null;

export function sharedRefresh(http: HttpClient): Observable<RefreshResponse> {
  if (inFlight$) return inFlight$.pipe(take(1));

  const subject = new ReplaySubject<RefreshResponse>(1);
  inFlight$ = subject;

  // Subscribed here, not left cold: the request must be made once no matter
  // how many callers end up waiting on it, including none.
  refreshSession(http).subscribe({
    next: res => {
      subject.next(res);
      subject.complete();
      inFlight$ = null;
    },
    error: err => {
      subject.error(err);
      inFlight$ = null;
    },
  });

  return subject.pipe(take(1));
}

/** Test seam: drop any shared refresh so one spec cannot leak into the next. */
export function resetSharedRefresh(): void {
  inFlight$ = null;
}
