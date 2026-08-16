import { environment } from '../../environments/environment';

/**
 * The `oidcReturnTo` continuation carried through the auth screens.
 *
 * `OidcAuthorizationController` bounces an unauthenticated browser to
 * `https://{slug}.sso.weldforge.org/login/?oidcReturnTo=<base64url of the authorize URL>`.
 * Every auth screen the user can reach from there (login, register, forgot/reset password)
 * must carry that value through, and whichever screen finally authenticates the user must
 * send them back to it — otherwise the calling application never sees them again.
 *
 * Extracted here because register.component.ts dropped the continuation entirely: a user who
 * clicked "Create an account" from a calling app's sign-in was registered successfully and
 * then stranded in the portal's tenant list, with the OIDC flow abandoned.
 */

/** Read the raw (still base64url-encoded) continuation, if present. */
export function readOidcReturnTo(queryParams: { [k: string]: unknown }): string | null {
  const v = queryParams['oidcReturnTo'];
  return typeof v === 'string' && v.length > 0 ? v : null;
}

/** Query params to forward to a sibling auth screen so the continuation survives. */
export function forwardOidcParams(queryParams: { [k: string]: unknown }): Record<string, string> {
  const v = readOidcReturnTo(queryParams);
  return v ? { oidcReturnTo: v } : {};
}

/**
 * Decode the continuation and return it **only if it is safe to redirect to**.
 *
 * <p>Returns null for anything we would not hand a freshly-authenticated browser to.
 *
 * <p><b>Why the check exists.</b> The value is attacker-supplied: it arrives as a query
 * parameter, so anyone can send a victim
 * `https://{slug}.sso.weldforge.org/login/?oidcReturnTo=<base64 of https://evil.example>`.
 * Redirecting there after a successful sign-in is a textbook open redirect — and an open
 * redirect on an *identity provider* is worth more to an attacker than on an ordinary site,
 * because the victim has just been taught to trust the page that bounced them.
 *
 * <p>The legitimate value is always an authorize URL on our own base domain, so that is
 * exactly what we allow: https, and a host that is either the base domain itself or one of
 * its subdomains. Nothing else needs to work.
 */
export function safeOidcReturnUrl(
  raw: string | null,
  baseDomain: string = environment.publicBaseDomain,
): string | null {
  if (!raw) return null;

  let decoded: string;
  try {
    // base64url -> base64. atob throws on malformed input.
    decoded = atob(raw.replace(/-/g, '+').replace(/_/g, '/'));
  } catch {
    return null;
  }

  let url: URL;
  try {
    url = new URL(decoded);
  } catch {
    // Not absolute — refuse rather than guess. A relative continuation is not a case the
    // authorization controller produces.
    return null;
  }

  if (url.protocol !== 'https:') return null;

  const host = url.hostname.toLowerCase();
  const base = (baseDomain ?? '').trim().toLowerCase();
  if (!base) return null;

  // The apex itself, or any single/multi-label subdomain of it. Guard against the classic
  // suffix-match bug where "evil-sso.weldforge.org" or "sso.weldforge.org.evil.com" slips
  // through a naive endsWith().
  const ok = host === base || host.endsWith('.' + base);
  return ok ? url.toString() : null;
}
