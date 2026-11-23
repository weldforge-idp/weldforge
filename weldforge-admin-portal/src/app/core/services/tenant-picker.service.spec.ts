import { describe, it, expect, beforeEach, vi } from 'vitest';
import { HttpClient } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';

import { TenantPickerService } from './tenant-picker.service';
import { AuthService } from './auth.service';
import { AccessTokenStore } from './access-token-store';
import { TokenRefreshScheduler } from './token-refresh.scheduler';

/** An unsigned JWT with the given payload -- the portal never verifies signatures. */
function token(claims: Record<string, unknown>): string {
  const b64 = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${b64({ alg: 'HS512' })}.${b64(claims)}.sig`;
}

describe('TenantPickerService', () => {
  let picker: TenantPickerService;
  let store: AccessTokenStore;

  beforeEach(() => {
    localStorage.clear();
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [
        AuthService,
        { provide: HttpClient, useValue: { post: vi.fn(), get: vi.fn() } },
        { provide: TokenRefreshScheduler, useValue: { scheduleFromToken: vi.fn(), cancel: vi.fn() } },
      ],
    });
    picker = TestBed.inject(TenantPickerService);
    store = TestBed.inject(AccessTokenStore);
  });

  it('tracks the selection once a super-admin token appears (2026-09-11 regression)', () => {
    // Evaluated before sign-in: not a super-admin yet, so no selector.
    expect(picker.outgoingSlug()).toBeNull();

    store.set(token({ tenant: 'default', sa: true, adm: 'SUPER_ADMIN' }));
    picker.set('cwvermaak-tech');

    // As a memoised computed() this stayed null for the life of the page
    // while the dropdown showed cwvermaak-tech -- and the write went home.
    expect(picker.outgoingSlug()).toBe('cwvermaak-tech');
  });

  it('follows a change of selection', () => {
    store.set(token({ tenant: 'default', adm: 'SUPER_ADMIN' }));
    picker.set('leap');
    expect(picker.outgoingSlug()).toBe('leap');
    picker.set('intellisuite');
    expect(picker.outgoingSlug()).toBe('intellisuite');
  });

  it('defaults to the home tenant when nothing is picked', () => {
    store.set(token({ tenant: 'default', adm: 'SUPER_ADMIN' }));
    expect(picker.outgoingSlug()).toBe('default');
  });

  it('stops sending a selector when the token stops being super-admin', () => {
    store.set(token({ tenant: 'default', adm: 'SUPER_ADMIN' }));
    picker.set('leap');
    store.set(token({ tenant: 'default', adm: 'TENANT_ADMIN' }));
    expect(picker.outgoingSlug()).toBeNull();
  });

  it('rejects a malformed slug', () => {
    store.set(token({ tenant: 'default', adm: 'SUPER_ADMIN' }));
    picker.set('leap');
    picker.set('../evil');
    expect(picker.outgoingSlug()).toBe('leap');
  });

  /**
   * Eligibility must agree with the backend, or the portal offers a picker the
   * backend refuses (403), or hides one it would honour. The backend grants
   * cross-tenant reach through a global SUPER_ADMIN membership, which
   * GlobalSuperAdminMembership.flaggedSuperAdmin (and V57) keep in step with
   * exactly this rule: sa OR adm=SUPER_ADMIN. Same rows as its unit test.
   */
  describe.each([
    { claims: { sa: true, adm: 'SUPER_ADMIN' }, eligible: true },
    { claims: { sa: true, adm: 'NONE' }, eligible: true },
    { claims: { sa: false, adm: 'SUPER_ADMIN' }, eligible: true },
    { claims: { adm: 'SUPER_ADMIN' }, eligible: true },
    { claims: { sa: true }, eligible: true },
    { claims: { sa: false, adm: 'TENANT_ADMIN' }, eligible: false },
    { claims: { sa: false, adm: 'READ_ONLY' }, eligible: false },
    { claims: { sa: false, adm: 'NONE' }, eligible: false },
    { claims: {}, eligible: false },
  ])('eligibility for $claims', ({ claims, eligible }) => {
    it(eligible ? 'sends the picked tenant' : 'sends no selector', () => {
      store.set(token({ tenant: 'default', ...claims }));
      picker.set('leap');
      expect(TestBed.inject(AuthService).isSuperAdmin()).toBe(eligible);
      expect(picker.outgoingSlug()).toBe(eligible ? 'leap' : null);
    });
  });
});
