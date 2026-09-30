import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { MatSnackBar } from '@angular/material/snack-bar';
import { of, throwError } from 'rxjs';
import { provideAngularQuery, QueryClient } from '@tanstack/angular-query-experimental';

import { UsersComponent } from './users.component';
import { AdminService, User } from '../../core/services/admin.service';
import { TenantPickerService } from '../../core/services/tenant-picker.service';

/**
 * Assigning the tenant role that a relying party reads from the token.
 *
 * <p>The bug these exist to prevent: the API sends `role` as the role's NAME,
 * a plain string, while the portal's `User` interface declared it as a `Role`
 * object. So `user.role?.name` was undefined and the Role column rendered a
 * dash for every user whatever their actual role — and when the column became
 * a dropdown, `user.role?.id` was undefined too, so a correctly assigned role
 * displayed as nothing at all. TypeScript could not catch it, because the lie
 * was in the interface rather than the code.
 *
 * <p>The fix is `roleId`, sent alongside the name. These pin the binding to it.
 */
describe('UsersComponent — role assignment', () => {
  let admin: {
    getUsers: ReturnType<typeof vi.fn>;
    getRoles: ReturnType<typeof vi.fn>;
    setUserRoles: ReturnType<typeof vi.fn>;
  };
  let snack: { open: ReturnType<typeof vi.fn> };

  type Exposed = {
    setRoles(user: User, roleIds: number[]): void;
    rolesQuery: { data(): unknown };
    savingRoleFor: number | null;
  };

  const ROLES = [
    { id: 8, name: 'clepsydra:admin' },
    { id: 9, name: 'auditor' },
  ];

  function create(users: Partial<User>[] = []): Exposed {
    TestBed.resetTestingModule();
    admin = {
      getUsers: vi.fn().mockReturnValue(of(users)),
      getRoles: vi.fn().mockReturnValue(of(ROLES)),
      setUserRoles: vi.fn().mockReturnValue(
          of({ id: 3, roleId: 8, role: 'clepsydra:admin', roleIds: [8], roles: ['clepsydra:admin'] })),
    };
    snack = { open: vi.fn() };
    TestBed.configureTestingModule({
      imports: [UsersComponent],
      providers: [
        provideAngularQuery(new QueryClient()),
        { provide: AdminService, useValue: admin },
        { provide: MatSnackBar, useValue: snack },
        { provide: TenantPickerService, useValue: { activeTenantSlug: signal('cwvermaak-tech') } },
      ],
    });
    TestBed.overrideProvider(MatSnackBar, { useValue: snack });
    return TestBed.createComponent(UsersComponent).componentInstance as unknown as Exposed;
  }

  const settle = () => new Promise(resolve => setTimeout(resolve, 0));

  it('posts the chosen role ids for the user', () => {
    const c = create();
    c.setRoles({ id: 3, roleIds: [] } as unknown as User, [8]);

    expect(admin.setUserRoles).toHaveBeenCalledWith(3, [8]);
  });

  it('posts several ids -- a user may hold more than one role', () => {
    const c = create();
    c.setRoles({ id: 3, roleIds: [8] } as unknown as User, [8, 9]);

    expect(admin.setUserRoles).toHaveBeenCalledWith(3, [8, 9]);
  });

  it('posts an empty array to clear every role', () => {
    const c = create();
    c.setRoles({ id: 3, roleIds: [8] } as unknown as User, []);

    expect(admin.setUserRoles).toHaveBeenCalledWith(3, []);
  });

  it('does nothing when the set has not changed, whatever the order', () => {
    const c = create();
    // mat-select fires on open and close too. Writing here would bump
    // tokenVersion and sign the user out of their other sessions every time
    // an admin glanced at the dropdown.
    c.setRoles({ id: 3, roleIds: [8, 9] } as unknown as User, [9, 8]);

    expect(admin.setUserRoles).not.toHaveBeenCalled();
  });

  it('reads the current set from roleIds, not from a nested object', () => {
    const c = create();
    c.setRoles({ id: 3, role: 'clepsydra:admin', roleIds: [8] } as unknown as User, [8]);

    expect(admin.setUserRoles).not.toHaveBeenCalled();
  });

  it("loads the tenant's roles so the dropdown has something to offer", async () => {
    const c = create();
    await settle();

    expect(admin.getRoles).toHaveBeenCalled();
    expect(c.rolesQuery.data()).toEqual(ROLES);
  });

  it('names every applied role in the confirmation', async () => {
    const c = create();
    await settle();
    c.setRoles({ id: 3, roleIds: [] } as unknown as User, [8, 9]);

    const msg = snack.open.mock.calls[0][0] as string;
    expect(msg).toContain('clepsydra:admin');
    expect(msg).toContain('auditor');
  });

  it('releases the row and reports the failure when the write is rejected', () => {
    const c = create();
    admin.setUserRoles.mockReturnValue(throwError(() => new Error('nope')));

    c.setRoles({ id: 3, roleIds: [] } as unknown as User, [8]);

    // Left disabled, the row would be stuck for the rest of the session.
    expect(c.savingRoleFor).toBeNull();
    expect(snack.open).toHaveBeenCalledWith(
        expect.stringContaining('Failed'), 'Dismiss', expect.anything());
  });
});
