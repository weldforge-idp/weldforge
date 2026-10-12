import { CanActivateFn, Router } from '@angular/router';
import { inject } from '@angular/core';
import { map } from 'rxjs';
import { AuthService } from '../services/auth.service';
import { ExternalNavigator } from '../external-navigator';
import { takeOidcContinuation } from '../oidc-continuation';

/**
 * Signed out goes to /login, keeping where you were headed.
 *
 * "Signed out" is not the same as "no token in this tab". A social sign-in
 * lands here straight off the OAuth2 callback's redirect, so the session
 * cookies are set and localStorage is empty -- see adoptCookieSession. Asking
 * the server before giving up is what stops that becoming a sign-in loop.
 *
 * Adopting a cookie session is also the one moment that identifies a social
 * landing, which is why resuming an interrupted OIDC flow happens here. A
 * person who started at a relying party and signed in with Google must end up
 * back at that application, not on the portal's own pages. The provider does
 * not carry the continuation, so the login screen left it in sessionStorage
 * before redirecting; takeOidcContinuation validates it on the way out and
 * yields it once.
 */
export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);
  const externalNav = inject(ExternalNavigator);

  if (authService.isLoggedIn()) return true;

  const toLogin = () =>
      router.createUrlTree(['/login'], { queryParams: { returnUrl: state.url } });

  return authService.adoptCookieSession().pipe(map(adopted => {
    if (!adopted) return toLogin();

    const resume = takeOidcContinuation();
    if (resume) {
      // Leaving the application: cancel this navigation rather than render a
      // page the browser is about to abandon.
      externalNav.go(resume);
      return false;
    }
    return true;
  }));
};
