import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';

// x-app-authorization is injected by the nginx reverse proxy on the
// admin.weldforge.org vhost using a value read from the
// sso-frontend-app-key k8s Secret at container startup. The SPA must
// NEVER carry the value — see SECURITY_AUDIT_2026-04-15.md CRITICAL-1.
//
// On a 401 from /api/** we clear the stored access token and route to
// /login. This makes JWT expiry behave gracefully — without it, the
// query layer surfaces the rejected request as a parse error or
// blanks the page (the symptom that broke the Service Accounts list
// view on 2026-05-10 when the user's 5-minute access JWT lapsed).
//
// The login endpoint itself (/api/auth/**) is excluded — a 401 there
// is a bad-credentials response that the login form needs to render,
// not an expired-session signal.
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const router = inject(Router);
  const token = localStorage.getItem('access_token');

  const authed = token
    ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
    : req;

  return next(authed).pipe(
    catchError((err: unknown) => {
      if (err instanceof HttpErrorResponse
          && err.status === 401
          && req.url.includes('/api/')
          && !req.url.includes('/api/auth/')) {
        localStorage.removeItem('access_token');
        router.navigate(['/login'], {
          queryParams: { returnUrl: router.url, reason: 'session_expired' }
        });
      }
      return throwError(() => err);
    })
  );
};
