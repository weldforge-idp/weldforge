import { HttpInterceptorFn } from '@angular/common/http';

// x-app-authorization is injected by the nginx reverse proxy on the
// admin.weldforge.org vhost using a value read from the
// sso-frontend-app-key k8s Secret at container startup. The SPA must
// NEVER carry the value — see SECURITY_AUDIT_2026-04-15.md CRITICAL-1.
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const token = localStorage.getItem('access_token');
  if (!token) {
    return next(req);
  }
  return next(req.clone({
    setHeaders: {
      Authorization: `Bearer ${token}`
    }
  }));
};
