import { TestBed } from '@angular/core/testing';
import { HttpErrorResponse } from '@angular/common/http';
import { signal } from '@angular/core';
import { MatSnackBar } from '@angular/material/snack-bar';
import { of, throwError } from 'rxjs';
import { provideAngularQuery, QueryClient } from '@tanstack/angular-query-experimental';

import { ServiceAccountsComponent } from './service-accounts.component';
import { ServiceAccountApi } from '../../core/services/service-account.service';
import { AuthService } from '../../core/services/auth.service';
import { TenantPickerService } from '../../core/services/tenant-picker.service';

/**
 * CONF-7.3 in the one place the portal does more than print an error: the
 * load-error summary and the action toasts must read the problem document's
 * `detail`, while the status-specific wording for 0/401/403 stays.
 */
describe('ServiceAccountsComponent — API error reporting', () => {
  let api: { list: ReturnType<typeof vi.fn>; rotate: ReturnType<typeof vi.fn> };
  let snack: { open: ReturnType<typeof vi.fn> };

  type Exposed = { errorSummary(err: unknown): string; rotate(s: unknown): void };

  function create(): Exposed {
    TestBed.resetTestingModule();
    api = { list: vi.fn().mockReturnValue(of([])), rotate: vi.fn() };
    snack = { open: vi.fn() };
    TestBed.configureTestingModule({
      imports: [ServiceAccountsComponent],
      providers: [
        provideAngularQuery(new QueryClient()),
        { provide: ServiceAccountApi, useValue: api },
        { provide: AuthService, useValue: { isSuperAdmin: () => false } },
        { provide: MatSnackBar, useValue: snack },
        { provide: TenantPickerService, useValue: { activeTenantSlug: signal('acme') } },
      ],
    });
    // The component imports MatSnackBarModule, whose own provider would shadow
    // a plain TestBed provider; override it at every level.
    TestBed.overrideProvider(MatSnackBar, { useValue: snack });
    return TestBed.createComponent(ServiceAccountsComponent).componentInstance as unknown as Exposed;
  }

  const problem = (status: number, detail: string) =>
    new HttpErrorResponse({ status, statusText: 'Server Error', error: { status, detail, message: 'legacy' } });

  it('summarises a server error with the problem detail', () => {
    expect(create().errorSummary(problem(500, 'An unexpected error occurred')))
      .toBe('HTTP 500 — An unexpected error occurred');
  });

  it('falls back to the status text when the body explains nothing', () => {
    expect(create().errorSummary(new HttpErrorResponse({ status: 502, statusText: 'Bad Gateway', error: null })))
      .toBe('HTTP 502 — Bad Gateway');
  });

  it('keeps its own wording for 0, 401 and 403', () => {
    const c = create();
    expect(c.errorSummary(new HttpErrorResponse({ status: 0 }))).toContain('Network error');
    expect(c.errorSummary(problem(401, 'Authentication required'))).toContain('Session expired');
    expect(c.errorSummary(problem(403, 'Access denied'))).toContain('do not have permission');
  });

  it('toasts the problem detail when an action fails', () => {
    const c = create();
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    api.rotate.mockReturnValue(throwError(() => problem(409, 'Service account is disabled')));

    c.rotate({ id: 3, name: 'ci', tokenPrefix: 'wf_svc_ab' });

    expect(snack.open).toHaveBeenCalledWith('Service account is disabled', 'OK', { duration: 4000 });
  });
});
