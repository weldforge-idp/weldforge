import { describe, it, expect, beforeEach, vi } from 'vitest';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { MfaService } from './mfa.service';

/**
 * Vitest specs for MfaService — focuses on the security-critical
 * branches that the WebAuthn UX wiring depends on:
 *
 *  - The start endpoint returns the ceremony key the finish call needs.
 *  - The finish endpoint accepts the credential JSON shape unchanged.
 *  - Self-reset propagates the password to the backend.
 */
describe('MfaService', () => {
  let http: { post: any; get: any; delete: any };
  let service: MfaService;

  beforeEach(() => {
    http = { post: vi.fn(), get: vi.fn(), delete: vi.fn() };
    service = new MfaService(http as unknown as HttpClient);
  });

  describe('webauthn registration', () => {
    it('start returns a ceremony key + serialised public-key options', () => {
      http.post.mockReturnValue(of({ ceremonyKey: 'enroll-42-abc', publicKey: '{"challenge":"..."}' }));

      let observed: { ceremonyKey: string; publicKey: string } | undefined;
      service.startWebauthnRegistration('YubiKey 5C').subscribe(r => (observed = r));

      expect(http.post).toHaveBeenCalledWith(
        expect.stringContaining('/api/auth/mfa/webauthn/registration/start'),
        { label: 'YubiKey 5C' }
      );
      expect(observed).toEqual({ ceremonyKey: 'enroll-42-abc', publicKey: '{"challenge":"..."}' });
    });

    it('finish round-trips the credential JSON without rewriting it', () => {
      const credentialJson = JSON.stringify({
        id: 'cred-id',
        rawId: 'raw',
        type: 'public-key',
        response: { attestationObject: 'blob', clientDataJSON: 'data' },
      });
      http.post.mockReturnValue(of({ id: 1, type: 'WEBAUTHN', enabled: true, verified: true }));

      service.finishWebauthnRegistration('enroll-42-abc', credentialJson, 'YubiKey 5C').subscribe();

      expect(http.post).toHaveBeenCalledWith(
        expect.stringContaining('/api/auth/mfa/webauthn/registration/finish'),
        {
          ceremonyKey: 'enroll-42-abc',
          publicKeyCredential: credentialJson,
          label: 'YubiKey 5C',
        }
      );
    });
  });

  describe('selfReset', () => {
    it('forwards the password to /reset and yields the removed count', () => {
      http.post.mockReturnValue(of({ removed: 2 }));

      let removed = 0;
      service.selfReset('hunter2!Strong').subscribe(r => (removed = r.removed));

      expect(http.post).toHaveBeenCalledWith(
        expect.stringContaining('/api/auth/mfa/reset'),
        { password: 'hunter2!Strong' }
      );
      expect(removed).toBe(2);
    });
  });
});
