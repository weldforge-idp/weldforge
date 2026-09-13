import { Injectable } from '@angular/core';
import { create as webauthnCreate, get as webauthnGet, supported as webauthnSupported } from '@github/webauthn-json';

/**
 * The browser half of a WebAuthn ceremony, behind an injectable seam.
 *
 * `navigator.credentials` cannot run in jsdom and cannot be stubbed with
 * module mocking under Angular's test system, so the component talks to this
 * instead — the same reason {@link ExternalNavigator} exists. What a test
 * needs to assert is the contract either side of the ceremony: what we ask the
 * server for, and what we send back.
 */
@Injectable({ providedIn: 'root' })
export class WebAuthnCeremony {
  available(): boolean {
    return typeof window !== 'undefined' && webauthnSupported();
  }

  /** Sign an assertion. `options` is the server's `publicKey` request, parsed. */
  get(options: unknown): Promise<unknown> {
    return webauthnGet(options as Parameters<typeof webauthnGet>[0]);
  }

  /** Create a credential during enrolment. */
  create(options: unknown): Promise<unknown> {
    return webauthnCreate(options as Parameters<typeof webauthnCreate>[0]);
  }
}
