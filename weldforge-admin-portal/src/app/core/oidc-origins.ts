/**
 * Deriving a public client's web origins from its redirect URIs.
 *
 * The server refuses a public client whose redirect URI is a real http(s)
 * host but which registers no `webOrigins` (see
 * `OidcClientService.requireWebOriginForBrowserClients`). That guard exists
 * because the alternative failure is invisible: every cross-origin call the
 * browser makes is blocked by CORS, a blocked fetch is reported as a generic
 * network error, and the symptom is a sign-in button that does nothing.
 *
 * The origin is almost always just the redirect URI's own origin, so the form
 * derives it rather than asking an administrator to retype it. That keeps the
 * guard from becoming the thing it was meant to prevent — a registration that
 * fails for a reason the person filling in the form cannot see.
 *
 * The rule here must MATCH THE SERVER'S. If they disagree, the form either
 * sends an origin the server rejects, or omits one the server demands. Both
 * halves treat exactly the same set of redirect URIs as "a browser": http(s),
 * non-loopback.
 */

/** Hosts that mean "this machine", per RFC 8252 §7.3. */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

function isLoopback(host: string): boolean {
  return LOOPBACK_HOSTS.has(host.toLowerCase());
}

/**
 * True when this redirect URI implies a browser, and therefore needs a
 * registered origin.
 *
 * Native apps are deliberately excluded: RFC 8252 clients redirect to a
 * loopback address or a private-use scheme, make no cross-origin browser
 * calls, and correctly have no origin.
 */
export function impliesBrowser(redirectUri: string): boolean {
  let url: URL;
  try {
    url = new URL(redirectUri.trim());
  } catch {
    return false; // Not a URI we understand; let the server rule on it.
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
  return !isLoopback(url.hostname);
}

/**
 * The origins implied by a set of redirect URIs, de-duplicated and in the
 * order first seen. Non-browser redirect URIs contribute nothing, so a native
 * client yields an empty list and is left alone.
 */
export function originsFor(redirectUris: string[]): string[] {
  const out: string[] = [];
  for (const raw of redirectUris) {
    if (!impliesBrowser(raw)) continue;
    try {
      // URL.origin normalises away a default port, which is what the server
      // compares against.
      const origin = new URL(raw.trim()).origin;
      if (!out.includes(origin)) out.push(origin);
    } catch {
      // impliesBrowser already parsed it; unreachable in practice.
    }
  }
  return out;
}

/**
 * Whether this registration would be refused by the server for having no
 * origin. Used to decide when to prompt, so the form can explain the
 * requirement before the request rather than relaying a 400 afterwards.
 */
export function needsWebOrigin(isPublic: boolean, redirectUris: string[], webOrigins: string[]): boolean {
  if (!isPublic) return false;
  if (webOrigins.some(o => o.trim().length > 0)) return false;
  return redirectUris.some(impliesBrowser);
}
