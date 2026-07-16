import { forwardOidcParams, readOidcReturnTo, safeOidcReturnUrl } from './oidc-continuation';

/** base64url-encode, the way OidcAuthorizationController does (no padding). */
function enc(s: string): string {
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const BASE = 'sso.weldforge.org';
const AUTHORIZE =
  'https://sso.weldforge.org/t/intellisuite/oauth2/authorize?client_id=intelli-accounting'
  + '&redirect_uri=https%3A%2F%2Fapp.example%2Fauth%2Fcallback&response_type=code&scope=openid';

describe('oidc-continuation', () => {
  describe('readOidcReturnTo / forwardOidcParams', () => {
    it('reads the continuation when present', () => {
      expect(readOidcReturnTo({ oidcReturnTo: 'abc' })).toBe('abc');
    });

    it('returns null when absent or empty', () => {
      expect(readOidcReturnTo({})).toBeNull();
      expect(readOidcReturnTo({ oidcReturnTo: '' })).toBeNull();
    });

    it('forwards the continuation to a sibling auth screen', () => {
      expect(forwardOidcParams({ oidcReturnTo: 'abc' })).toEqual({ oidcReturnTo: 'abc' });
    });

    it('forwards nothing when there is no continuation', () => {
      // The bug this whole module exists for: register.component initialised
      // forwardQueryParams to {} and never populated it, so "Back to sign in"
      // silently dropped the OIDC flow.
      expect(forwardOidcParams({})).toEqual({});
    });
  });

  describe('safeOidcReturnUrl — accepts our own authorize URLs', () => {
    it('accepts an authorize URL on the apex', () => {
      expect(safeOidcReturnUrl(enc(AUTHORIZE), BASE)).toBe(AUTHORIZE);
    });

    it('accepts a tenant subdomain', () => {
      const u = 'https://intellisuite.sso.weldforge.org/login/';
      expect(safeOidcReturnUrl(enc(u), BASE)).toBe(u);
    });
  });

  describe('safeOidcReturnUrl — refuses open redirects', () => {
    // An open redirect on an identity provider is worth more to an attacker than on an
    // ordinary site: the victim has just been taught to trust the page that bounced them.
    it('refuses a foreign origin', () => {
      expect(safeOidcReturnUrl(enc('https://evil.example/phish'), BASE)).toBeNull();
    });

    it('refuses a lookalike prefix (evil-sso.weldforge.org)', () => {
      expect(safeOidcReturnUrl(enc('https://evil-sso.weldforge.org/x'), BASE)).toBeNull();
    });

    it('refuses a suffix-match attack (sso.weldforge.org.evil.com)', () => {
      // The naive endsWith(baseDomain) check would accept this.
      expect(safeOidcReturnUrl(enc('https://sso.weldforge.org.evil.com/x'), BASE)).toBeNull();
    });

    it('refuses a bare-domain lookalike (weldforge.org.evil.com)', () => {
      expect(safeOidcReturnUrl(enc('https://weldforge.org.evil.com/x'), BASE)).toBeNull();
    });

    it('refuses non-https schemes', () => {
      expect(safeOidcReturnUrl(enc('http://sso.weldforge.org/x'), BASE)).toBeNull();
      expect(safeOidcReturnUrl(enc('javascript:alert(1)'), BASE)).toBeNull();
      expect(safeOidcReturnUrl(enc('data:text/html,<script>alert(1)</script>'), BASE)).toBeNull();
    });

    it('refuses a relative URL rather than guessing an origin', () => {
      expect(safeOidcReturnUrl(enc('/t/intellisuite/oauth2/authorize'), BASE)).toBeNull();
    });
  });

  describe('safeOidcReturnUrl — degrades safely', () => {
    it('returns null for null/empty input', () => {
      expect(safeOidcReturnUrl(null, BASE)).toBeNull();
      expect(safeOidcReturnUrl('', BASE)).toBeNull();
    });

    it('returns null for malformed base64 rather than throwing', () => {
      expect(safeOidcReturnUrl('!!!not-base64!!!', BASE)).toBeNull();
    });

    it('returns null when no base domain is configured', () => {
      expect(safeOidcReturnUrl(enc(AUTHORIZE), '')).toBeNull();
    });

    it('is case-insensitive on host', () => {
      const u = 'https://SSO.WELDFORGE.ORG/t/x/oauth2/authorize';
      expect(safeOidcReturnUrl(enc(u), BASE)).not.toBeNull();
    });
  });
});
