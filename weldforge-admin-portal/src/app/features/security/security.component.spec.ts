import { TestBed } from '@angular/core/testing';
import { MatSnackBar } from '@angular/material/snack-bar';
import { of } from 'rxjs';

import { SecurityComponent } from './security.component';
import { MfaService } from '../../core/services/mfa.service';
import { WebAuthnCeremony } from '../../core/webauthn-ceremony';

/**
 * 2026-09-13: an operator enrolled a passkey as their only factor, had no
 * backup codes, and was locked out of the account. Enrolling a first factor
 * must hand back recovery codes then and there — a tip suggesting the user
 * press another button later is not a safety net.
 */
describe('SecurityComponent — recovery codes on first enrolment', () => {
  let mfa: Record<string, ReturnType<typeof vi.fn>>;
  let ceremony: { available: () => boolean; create: ReturnType<typeof vi.fn>; get: ReturnType<typeof vi.fn> };
  let snack: { open: ReturnType<typeof vi.fn> };

  function create(remaining: number) {
    TestBed.resetTestingModule();
    mfa = {
      listFactors: vi.fn().mockReturnValue(of([])),
      backupCodeStatus: vi.fn().mockReturnValue(of({ remaining })),
      regenerateBackupCodes: vi.fn().mockReturnValue(of({ codes: ['aaaa-1111', 'bbbb-2222'], remaining: 2 })),
      startWebauthnRegistration: vi.fn().mockReturnValue(
        of({ ceremonyKey: 'ck', publicKey: JSON.stringify({ publicKey: { challenge: 'x' } }) })),
      finishWebauthnRegistration: vi.fn().mockReturnValue(of({ id: 1, type: 'WEBAUTHN' })),
      activateTotp: vi.fn().mockReturnValue(of({ id: 2, type: 'TOTP' })),
      enrollTotp: vi.fn().mockReturnValue(of({ factorId: 2, otpauthUrl: 'otpauth://x', secret: 's' })),
      deleteFactor: vi.fn().mockReturnValue(of(void 0)),
    };
    ceremony = {
      available: () => true,
      create: vi.fn(async () => ({ id: 'cred-1', type: 'public-key' })),
      get: vi.fn(),
    };
    snack = { open: vi.fn() };
    TestBed.configureTestingModule({
      imports: [SecurityComponent],
      providers: [
        { provide: MfaService, useValue: mfa },
        { provide: WebAuthnCeremony, useValue: ceremony },
        { provide: MatSnackBar, useValue: snack },
      ],
    });
    TestBed.overrideProvider(MatSnackBar, { useValue: snack });
    const fixture = TestBed.createComponent(SecurityComponent);
    fixture.detectChanges();
    return fixture.componentInstance as SecurityComponent & {
      addSecurityKey(): void; freshBackupCodes(): string[]; backupRemaining(): number;
    };
  }

  it('issues and shows recovery codes when a passkey is the first factor', async () => {
    vi.spyOn(window, 'prompt').mockReturnValue('Windows Hello');
    const c = create(0);

    c.addSecurityKey();
    await vi.waitFor(() => expect(mfa['regenerateBackupCodes']).toHaveBeenCalled());

    expect(c.freshBackupCodes()).toEqual(['aaaa-1111', 'bbbb-2222']);
    expect(c.backupRemaining()).toBe(2);
    expect(snack.open).toHaveBeenCalledWith(
      expect.stringContaining('save them now'), 'OK', expect.anything());
  });

  it('leaves existing codes alone', async () => {
    vi.spyOn(window, 'prompt').mockReturnValue('Windows Hello');
    const c = create(5);

    c.addSecurityKey();
    await vi.waitFor(() => expect(mfa['finishWebauthnRegistration']).toHaveBeenCalled());

    expect(mfa['regenerateBackupCodes']).not.toHaveBeenCalled();
    expect(c.freshBackupCodes()).toEqual([]);
  });

  it('does the same for an authenticator app', async () => {
    const c = create(0) as unknown as { activateTotp(): void; totpEnroll: { set(v: unknown): void } };
    (c as unknown as { totpEnroll: { set(v: unknown): void } }).totpEnroll.set({ factorId: 2, secret: 's', otpauthUrl: 'otpauth://x' });

    c.activateTotp();
    await vi.waitFor(() => expect(mfa['regenerateBackupCodes']).toHaveBeenCalled());
  });
});
