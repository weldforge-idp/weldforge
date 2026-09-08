import { Injectable } from '@angular/core';

/**
 * Leaving the Angular application entirely — a full browser navigation to a
 * validated off-origin URL.
 *
 * <p>This exists purely as a testing seam. Assigning `window.location.href`
 * directly is not observable under jsdom (it either does nothing or raises
 * "Not implemented: navigation"), so a component that redirects that way cannot
 * have its redirect asserted. That is how the open redirect in
 * `login.component.goToApp()` survived: the decision was reachable only through
 * an unmockable global.
 *
 * <p>Injecting the navigation instead means a test can assert **that we did not
 * leave the origin** for a hostile continuation — which is the security
 * property that actually matters, and the one a unit test of the pure decision
 * function cannot cover on its own.
 *
 * <p>The URL passed here MUST already have been validated — see
 * `safeOidcReturnUrl` / `resolvePostAuthTarget` in `oidc-continuation.ts`. This
 * class deliberately performs no checking of its own: putting validation here
 * would make it easy to assume it happens and skip it at the call site.
 */
@Injectable({ providedIn: 'root' })
export class ExternalNavigator {
  go(url: string): void {
    window.location.href = url;
  }
}
