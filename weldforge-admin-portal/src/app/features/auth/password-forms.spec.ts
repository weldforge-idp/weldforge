import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router, convertToParamMap } from '@angular/router';
import { HttpErrorResponse } from '@angular/common/http';
import { signal } from '@angular/core';
import { of, throwError } from 'rxjs';

import { RegisterComponent } from './register.component';
import { ResetPasswordComponent } from './reset-password.component';
import { AuthService } from '../../core/services/auth.service';
import { TenantBrandingService } from '../../core/services/tenant-branding.service';
import { ExternalNavigator } from '../../core/external-navigator';

/**
 * The two forms where a user chooses a password (CONF-7.1, CONF-7.3).
 *
 * The policy is length plus breach screening, not character classes, so the
 * forms must say that up front; and when the server refuses a password, the
 * user must see its reason (the problem document's `detail`), not a generic
 * "try again" -- otherwise they retry a variation of the same breached password.
 */

const BREACHED_DETAIL =
  'Password does not meet policy: must not appear in a known data breach, and this one does; choose a different password';

const breachedProblem = () => new HttpErrorResponse({
  status: 400,
  error: {
    type: 'tag:weldforge.org,2026:problem:password_policy', title: 'Bad Request', status: 400,
    detail: BREACHED_DETAIL, error: 'password_policy', message: BREACHED_DETAIL,
    reasons: ['must not appear in a known data breach, and this one does; choose a different password'],
  },
});

const HINT = 'Use a long passphrase: a few unrelated words work well. Passwords found in known data breaches are refused.';

function brandingStub() {
  return { current: signal(null), slugFromHost: () => null, load: () => of(null) };
}

describe('RegisterComponent — password policy', () => {
  let auth: { register: ReturnType<typeof vi.fn> };

  function create() {
    TestBed.resetTestingModule();
    auth = { register: vi.fn() };
    TestBed.configureTestingModule({
      imports: [RegisterComponent],
      providers: [
        { provide: AuthService, useValue: auth },
        { provide: TenantBrandingService, useValue: brandingStub() },
        { provide: Router, useValue: { navigate: vi.fn() } },
        { provide: ExternalNavigator, useValue: { go: vi.fn() } },
        { provide: ActivatedRoute, useValue: { snapshot: { queryParams: {} } } },
      ],
    });
    const fixture = TestBed.createComponent(RegisterComponent);
    fixture.detectChanges();
    return fixture;
  }

  it('states the length-and-breach rule, not character classes', () => {
    const text = (create().nativeElement as HTMLElement).textContent ?? '';

    expect(text).toContain(HINT);
    expect(text).not.toMatch(/uppercase|symbol|digit/i);
  });

  it("shows the server's reason when the password is refused", () => {
    const fixture = create();
    auth.register.mockReturnValue(throwError(() => breachedProblem()));

    fixture.componentInstance.submit();

    expect(fixture.componentInstance.error()).toBe(BREACHED_DETAIL);
  });
});

describe('ResetPasswordComponent — password policy', () => {
  let auth: { resetPassword: ReturnType<typeof vi.fn> };

  function create() {
    TestBed.resetTestingModule();
    auth = { resetPassword: vi.fn() };
    TestBed.configureTestingModule({
      imports: [ResetPasswordComponent],
      providers: [
        { provide: AuthService, useValue: auth },
        { provide: TenantBrandingService, useValue: brandingStub() },
        { provide: Router, useValue: { navigate: vi.fn() } },
        {
          provide: ActivatedRoute,
          useValue: { snapshot: { queryParamMap: convertToParamMap({ token: 'tok' }), queryParams: { token: 'tok' } } },
        },
      ],
    });
    const fixture = TestBed.createComponent(ResetPasswordComponent);
    fixture.detectChanges();
    return fixture;
  }

  it('states the length-and-breach rule', () => {
    expect((create().nativeElement as HTMLElement).textContent ?? '').toContain(HINT);
  });

  it("shows the server's reason, not 'the link may be expired'", () => {
    const fixture = create();
    auth.resetPassword.mockReturnValue(throwError(() => breachedProblem()));
    fixture.componentInstance.newPassword = 'password1234';
    fixture.componentInstance.confirm = 'password1234';

    fixture.componentInstance.submit();

    expect(fixture.componentInstance.error()).toBe(BREACHED_DETAIL);
    expect(fixture.componentInstance.done()).toBe(false);
  });

  it('keeps the expired-link fallback for a body that explains nothing', () => {
    const fixture = create();
    auth.resetPassword.mockReturnValue(throwError(() => new HttpErrorResponse({ status: 502, error: null })));
    fixture.componentInstance.newPassword = 'correct horse battery staple';
    fixture.componentInstance.confirm = 'correct horse battery staple';

    fixture.componentInstance.submit();

    expect(fixture.componentInstance.error()).toBe('Could not reset your password. The link may be expired.');
  });
});
