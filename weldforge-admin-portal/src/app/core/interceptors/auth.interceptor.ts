import {
  HttpClient,
  HttpContext,
  HttpContextToken,
  HttpErrorResponse,
  HttpEvent,
  HttpHandlerFn,
  HttpInterceptorFn,
  HttpRequest,
} from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, Observable, ReplaySubject, switchMap, take, throwError } from 'rxjs';

import { environment } from '../../../environments/environment';

// x-app-authorization is injected by the nginx reverse proxy on the
// admin.weldforge.org vhost using a value read from the
// sso-frontend-app-key k8s Secret at container startup. The SPA must
// NEVER carry the value — see SECURITY_AUDIT_2026-04-15.md CRITICAL-1.
//
// 401 handling has three layers:
//
//   1. If the failing call is /api/auth/refresh, /api/auth/login,
//      /api/auth/register, /api/auth/mfa/verify, /api/auth/forgot-password,
//      /api/auth/reset-password, or /api/auth/verify-email: pass the
//      401 straight through. Those are pre-auth endpoints — a 401 there
//      means "bad credentials" / "expired refresh token", not "session
//      expired", and the form/UI needs to render it.
//
//   2. Otherwise (admin/user/role/scim/... calls), assume the access
//      JWT just lapsed (it's a 5-minute token by default). Fire one
//      POST /api/auth/refresh, which reads the rotating refresh_token
//      cookie and returns a new access JWT + rotates the cookie.
//      Replay the original request with the new bearer.
//
//   3. If the refresh call itself 401s — meaning the refresh-token
//      family was revoked, the user is genuinely logged out, or
//      something stole the cookie and triggered the theft-detection
//      path on the server — clear the local access token, redirect to
//      /login?reason=session_expired&returnUrl=... and propagate the
//      original 401 so the calling component can show a generic error
//      instead of hanging.
//
// Concurrency: if N requests fire and all get 401 around the same
// moment (very common — a route activation triggers several
// queries), they share a single in-flight refresh via the
// module-scoped ReplaySubject. The first 401 starts /refresh; the
// others wait for the same emission and use the new token to replay.
// One /refresh, N replays.
//
// Loop guard: every retry sets SKIP_REFRESH_RETRY on the cloned
// request's HttpContext. If the retried request also 401s, the
// interceptor sees the flag, skips refresh, and treats it as a real
// auth failure (redirect to login). Without this guard a perpetually-
// invalid token would loop the SPA forever.

const SKIP_REFRESH_RETRY = new HttpContextToken<boolean>(() => false);

/** Endpoints whose 401 means "bad credentials", not "session expired". */
const PRE_AUTH_PATHS = [
  '/api/auth/login',
  '/api/auth/refresh',
  '/api/auth/register',
  '/api/auth/mfa/verify',
  '/api/auth/forgot-password',
  '/api/auth/reset-password',
  '/api/auth/verify-email',
  '/api/auth/resend-verification',
];

/** Shared across the module so concurrent 401s collapse onto one /refresh. */
let refreshInFlight$: ReplaySubject<string> | null = null;

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const router = inject(Router);
  const http = inject(HttpClient);

  const authed = withBearer(req);

  return next(authed).pipe(
    catchError((err: unknown) => {
      if (!(err instanceof HttpErrorResponse) || err.status !== 401) {
        return throwError(() => err);
      }
      if (!req.url.includes('/api/')) {
        return throwError(() => err);
      }
      if (PRE_AUTH_PATHS.some(p => req.url.includes(p))) {
        return throwError(() => err);
      }
      if (req.context.get(SKIP_REFRESH_RETRY)) {
        // Retried-with-new-token request also failed → genuine auth
        // failure. Clear local state and bounce to login.
        localStorage.removeItem('access_token');
        router.navigate(['/login'], {
          queryParams: { returnUrl: router.url, reason: 'session_expired' },
        });
        return throwError(() => err);
      }

      return refreshAndReplay(req, next, http, router);
    }),
  );
};

function withBearer(req: HttpRequest<unknown>): HttpRequest<unknown> {
  const token = localStorage.getItem('access_token');
  if (!token) return req;
  return req.clone({ setHeaders: { Authorization: `Bearer ${token}` } });
}

function refreshAndReplay(
  req: HttpRequest<unknown>,
  next: HttpHandlerFn,
  http: HttpClient,
  router: Router,
): Observable<HttpEvent<unknown>> {
  // Another concurrent 401 has already kicked off /refresh — wait
  // for it and replay with whatever token it produces (or propagate
  // its failure).
  if (refreshInFlight$) {
    return refreshInFlight$.pipe(
      take(1),
      switchMap(newToken => next(replay(req, newToken))),
    );
  }

  const subject = new ReplaySubject<string>(1);
  refreshInFlight$ = subject;

  return http
    .post<{ token: string; expiresIn: number }>(
      `${environment.apiBaseUrl}/api/auth/refresh`,
      null,
      { withCredentials: true },
    )
    .pipe(
      switchMap(res => {
        localStorage.setItem('access_token', res.token);
        subject.next(res.token);
        subject.complete();
        refreshInFlight$ = null;
        return next(replay(req, res.token));
      }),
      catchError(refreshErr => {
        subject.error(refreshErr);
        refreshInFlight$ = null;
        localStorage.removeItem('access_token');
        router.navigate(['/login'], {
          queryParams: { returnUrl: router.url, reason: 'session_expired' },
        });
        return throwError(() => refreshErr);
      }),
    );
}

function replay(req: HttpRequest<unknown>, token: string): HttpRequest<unknown> {
  return req.clone({
    setHeaders: { Authorization: `Bearer ${token}` },
    context: (req.context ?? new HttpContext()).set(SKIP_REFRESH_RETRY, true),
  });
}
