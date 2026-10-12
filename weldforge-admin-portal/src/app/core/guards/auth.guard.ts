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
 * An interrupted OIDC flow resumes here too. A person who started at a
 * relying party and signed in with Google must end up back at that
 * application, not on the portal's own pages. The provider does not carry the
 * continuation, so the login screen left it in sessionStorage before
 * redirecting; takeOidcContinuation validates it on the way out and yields it
 * once.
 *
 * That resume is checked on BOTH paths, and the reason is a production
 * failure. It first hung off the adopt branch alone, on the reasoning that
 * adopting a cookie session is what identifies a social landing. It is not:
 * localStorage is per origin, not per tab, so a token from any earlier
 * sign-in on this host is still sitting there when the browser comes back
 * from Google. Verified in production on 2026-10-12 -- a rotation at 14:51:12
 * left a live token, the 14:52:40 federated login then landed on a guard that
 * returned true at once, and the log shows no refresh between them at all.
 * The stash was never read and the person stayed on the portal. Holding a
 * token says nothing about whether a flow is waiting to be finished; the
 * stash does, and it is single-use and expires in ten minutes.
 */
export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);
  const externalNav = inject(ExternalNavigator);

  const toLogin = () =>
      router.createUrlTree(['/login'], { queryParams: { returnUrl: state.url } });

  /** Signed in, by whichever route. Finish an interrupted flow before rendering. */
  const landed = () => {
    const resume = takeOidcContinuation();
    if (resume) {
      // Leaving the application: cancel this navigation rather than render a
      // page the browser is about to abandon.
      externalNav.go(resume);
      return false;
    }
    return true;
  };

  if (authService.isLoggedIn()) return landed();

  return authService.adoptCookieSession().pipe(
      map(adopted => (adopted ? landed() : toLogin())));
};
