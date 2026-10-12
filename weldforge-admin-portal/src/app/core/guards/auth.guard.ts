import { CanActivateFn, Router } from '@angular/router';
import { inject } from '@angular/core';
import { map } from 'rxjs';
import { AuthService } from '../services/auth.service';

/**
 * Signed out goes to /login, keeping where you were headed.
 *
 * "Signed out" is not the same as "no token in this tab". A social sign-in
 * lands here straight off the OAuth2 callback's redirect, so the session
 * cookies are set and localStorage is empty -- see adoptCookieSession. Asking
 * the server before giving up is what stops that becoming a sign-in loop.
 */
export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authService.isLoggedIn()) return true;

  const toLogin = () =>
      router.createUrlTree(['/login'], { queryParams: { returnUrl: state.url } });

  return authService.adoptCookieSession().pipe(map(adopted => adopted || toLogin()));
};
