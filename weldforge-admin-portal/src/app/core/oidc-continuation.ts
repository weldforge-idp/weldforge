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

/** Where to send a browser that has just authenticated. */
export type PostAuthTarget =
  | { kind: 'external'; url: string }
  | { kind: 'internal'; route: string };

/**
 * Decide where to send a freshly-authenticated browser.
 *
 * <p>Both inputs are attacker-supplied query parameters, so both are validated:
 *
 * <ul>
 *   <li>`oidcReturnTo` — a full off-origin redirect. Checked by {@link safeOidcReturnUrl};
 *       anything not on our own base domain over https is discarded.
 *   <li>`returnUrl` — an in-app route handed to `Router.navigate`. Angular's router will not
 *       leave the origin, so this is not an open redirect, but a protocol-relative value
 *       (`//evil.example`) is still a confusing thing to accept from a query string. Only a
 *       single-slash absolute path is allowed.
 * </ul>
 *
 * <p>Extracted so the decision is unit-testable without a TestBed: the components that call
 * it (login, register) have no component-level test coverage, and assigning
 * `window.location.href` is not observable under jsdom. Keeping the logic here means the
 * security-relevant part is tested even though the wiring is not.
 */
export function resolvePostAuthTarget(
  queryParams: { [k: string]: unknown },
  fallbackRoute: string = '/tenants',
  baseDomain?: string,
): PostAuthTarget {
  const external = safeOidcReturnUrl(
    readOidcReturnTo(queryParams),
    baseDomain ?? environment.publicBaseDomain,
  );
  if (external) return { kind: 'external', url: external };

  const raw = queryParams['returnUrl'];
  const candidate = typeof raw === 'string' ? raw.trim() : '';
  const safeRoute =
    candidate.startsWith('/') && !candidate.startsWith('//') ? candidate : fallbackRoute;
  return { kind: 'internal', route: safeRoute };
}

/**
 * The `client_id` of the OIDC request a login was bounced out of.
 *
 * Used to brand the sign-in screen for the application the person is
 * actually signing in to, rather than generically for the tenant — a tenant
 * routinely hosts several.
 *
 * Deliberately built on {@link safeOidcReturnUrl}, so a continuation naming a
 * foreign origin yields no client id at all. The id is only ever sent back to
 * our own API to ask for branding, but reading it from an unvalidated URL
 * would make this the one place that trusts the parameter everything else
 * refuses to.
 */
export function oidcClientIdFrom(raw: string | null): string | null {
  const safe = safeOidcReturnUrl(raw);
  if (!safe) return null;
  try {
    const id = new URL(safe).searchParams.get('client_id');
    return id && id.trim() ? id.trim() : null;
  } catch {
    return null;
  }
}

/**
 * Carrying the continuation across a social sign-in.
 *
 * Every other auth screen keeps `oidcReturnTo` in the URL, because it never
 * leaves this origin. A social sign-in does: the browser goes to Google and
 * comes back to `/login/oauth2/code/{registrationId}?code=…&state=…`.
 * Verified against production on 2026-10-12 -- a value put on the kickoff URL
 * reaches neither `state` nor `redirect_uri`, so it cannot come back, and
 * OAuth2LoginSuccessHandler finds no continuation and lands the user on the
 * portal. For a person who started at a relying party, that is the flow
 * abandoning them one step from the end.
 *
 * sessionStorage survives the round trip -- same origin, same tab -- and is
 * scoped to that tab, so two sign-ins in two tabs cannot take each other's
 * continuation.
 *
 * What is stored is the RAW, still-encoded value, exactly as it arrived.
 * Validation happens on the way out through {@link safeOidcReturnUrl}, so
 * storage is never a way to get an unchecked URL into a redirect: a value
 * edited in devtools is refused on read like any other.
 */
const PENDING_KEY = 'wf_oidc_continuation';

/** How long a stashed continuation stays usable. */
const PENDING_TTL_MS = 10 * 60 * 1000;

/**
 * Remember the continuation across a sign-in that leaves this origin.
 *
 * A no-op when there is nothing to carry, which also clears any stale value:
 * starting a plain sign-in must not resume someone's abandoned OIDC flow.
 */
export function stashOidcContinuation(raw: string | null): void {
  try {
    if (!raw) {
      sessionStorage.removeItem(PENDING_KEY);
      return;
    }
    sessionStorage.setItem(PENDING_KEY, JSON.stringify({ raw, at: Date.now() }));
  } catch {
    // Private mode, blocked storage, quota. The sign-in still works; it
    // just ends on the portal, which is where it ended before this existed.
  }
}

/**
 * Take back the continuation, if there is a usable one.
 *
 * Single-use and time-limited. Without both, a continuation left by an
 * abandoned sign-in would hijack an ordinary visit to the portal later in
 * the same tab.
 */
export function takeOidcContinuation(baseDomain?: string): string | null {
  let stored: string | null = null;
  try {
    stored = sessionStorage.getItem(PENDING_KEY);
    sessionStorage.removeItem(PENDING_KEY);
  } catch {
    return null;
  }
  if (!stored) return null;

  let raw: unknown;
  let at: unknown;
  try {
    ({ raw, at } = JSON.parse(stored));
  } catch {
    return null;
  }
  if (typeof raw !== 'string' || typeof at !== 'number') return null;
  if (!Number.isFinite(at) || Date.now() - at > PENDING_TTL_MS || at > Date.now()) return null;

  return safeOidcReturnUrl(raw, baseDomain ?? environment.publicBaseDomain);
}
