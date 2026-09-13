import { CanActivateFn, Router } from '@angular/router';
import { inject } from '@angular/core';
import { AuthService } from '../services/auth.service';

/**
 * Keeps a session with no admin role off the admin pages.
 *
 * Runs after {@link authGuard}: signed out sends you to /login, signed in
 * without an admin role sends you to your own Security page. Before
 * 2026-09-13 a non-admin saw the whole admin nav and discovered its lack of
 * access from an "Access denied" toast on each page — the server refused
 * correctly, but the portal offered pages it knew the account could not use.
 *
 * Cosmetic only: the server decides. Every /api/admin/** call is authorised
 * there, so nothing here grants access to anything.
 */
export const adminGuard: CanActivateFn = () => {
  const auth = inject(AuthService);
  const router = inject(Router);

  if (auth.hasAdminAccess()) return true;

  router.navigate(['/security']);
  return false;
};
