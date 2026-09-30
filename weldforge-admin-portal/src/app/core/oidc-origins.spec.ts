import { describe, it, expect } from 'vitest';
import { impliesBrowser, originsFor, needsWebOrigin } from './oidc-origins';

/**
 * These rules must agree with the server's
 * `OidcClientService.requireWebOriginForBrowserClients`. If they drift, the
 * form either sends an origin the server rejects or omits one it demands —
 * and the second case is the failure this whole mechanism exists to prevent:
 * a client that registers successfully and then signs nobody in, because
 * every cross-origin call is blocked by CORS and a blocked fetch looks like
 * a generic network error.
 */
describe('oidc-origins', () => {

  describe('impliesBrowser', () => {
    it('treats a real https host as a browser client', () => {
      expect(impliesBrowser('https://clepsydra.cwvermaak.tech/callback')).toBe(true);
    });

    it('treats plain http on a real host as a browser client too', () => {
      // Not loopback, so it is a browser somewhere; the server refuses the
      // scheme separately.
      expect(impliesBrowser('http://staging.example.test/cb')).toBe(true);
    });

    it.each([
      'http://127.0.0.1/callback',
      'http://127.0.0.1:8080/callback',
      'http://localhost:3000/cb',
      'http://[::1]:1234/cb',
    ])('exempts the RFC 8252 loopback redirect %s', uri => {
      expect(impliesBrowser(uri)).toBe(false);
    });

    it('exempts a private-use scheme (native mobile app)', () => {
      expect(impliesBrowser('tech.cwvermaak.clepsydra:/oauth2redirect')).toBe(false);
    });

    it('does not throw on junk; it defers to the server', () => {
      expect(impliesBrowser('not a uri')).toBe(false);
      expect(impliesBrowser('')).toBe(false);
    });
  });

  describe('originsFor', () => {
    it('derives the origin of a browser redirect URI', () => {
      expect(originsFor(['https://app.acme.test/callback']))
          .toEqual(['https://app.acme.test']);
    });

    it('keeps a non-default port and drops a default one', () => {
      expect(originsFor(['https://app.acme.test:8443/cb'])).toEqual(['https://app.acme.test:8443']);
      expect(originsFor(['https://app.acme.test:443/cb'])).toEqual(['https://app.acme.test']);
    });

    it('de-duplicates two paths on the same origin', () => {
      expect(originsFor(['https://app.acme.test/cb', 'https://app.acme.test/silent']))
          .toEqual(['https://app.acme.test']);
    });

    it('yields nothing for a purely native client', () => {
      expect(originsFor(['http://127.0.0.1/callback', 'tech.cwvermaak.clepsydra:/oauth2redirect']))
          .toEqual([]);
    });

    it('derives only the browser half of a mixed client', () => {
      expect(originsFor(['http://127.0.0.1/cb', 'https://app.acme.test/cb']))
          .toEqual(['https://app.acme.test']);
    });
  });

  describe('needsWebOrigin', () => {
    it('is true for a public browser client with none — the KeyCrypt case', () => {
      expect(needsWebOrigin(true, ['https://keycrypt.cwvermaak.tech/callback'], [])).toBe(true);
    });

    it('is false once one is supplied', () => {
      expect(needsWebOrigin(true,
          ['https://keycrypt.cwvermaak.tech/callback'],
          ['https://keycrypt.cwvermaak.tech'])).toBe(false);
    });

    it('treats blanks as none', () => {
      expect(needsWebOrigin(true, ['https://app.acme.test/cb'], ['  '])).toBe(true);
    });

    it('is false for a confidential client, which calls the token endpoint server-side', () => {
      expect(needsWebOrigin(false, ['https://app.acme.test/cb'], [])).toBe(false);
    });

    it('is false for a native public client — these legitimately have no origin', () => {
      expect(needsWebOrigin(true, ['http://127.0.0.1/callback'], [])).toBe(false);
      expect(needsWebOrigin(true, ['tech.cwvermaak.clepsydra:/oauth2redirect'], [])).toBe(false);
    });
  });
});
