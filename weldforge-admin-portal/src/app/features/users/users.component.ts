import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatTableModule } from '@angular/material/table';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSelectModule } from '@angular/material/select';
import { MatFormFieldModule } from '@angular/material/form-field';
import { FormsModule } from '@angular/forms';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { injectQuery, injectQueryClient } from '@tanstack/angular-query-experimental';

import { AdminService, User, Role } from '../../core/services/admin.service';
import { TenantPickerComponent } from '../../shared/tenant-picker/tenant-picker.component';
import { TenantPickerService } from '../../core/services/tenant-picker.service';
import { apiErrorMessage } from '../../core/api-error';

@Component({
  selector: 'app-users',
  standalone: true,
  imports: [
    CommonModule,
    MatTableModule, MatCardModule, MatButtonModule, MatIconModule,
    MatProgressSpinnerModule, MatSnackBarModule,
    MatSelectModule, MatFormFieldModule, FormsModule,
    TenantPickerComponent,
  ],
  template: `
    <div class="wf-page">
      <header class="wf-page-header">
        <div>
          <div class="eyebrow mono">// users</div>
          <h1>Users</h1>
          <p class="sub">Everyone in this tenant. Assign the role a relying party reads from the token, or reset a user's MFA if they've lost their second factor.</p>
        </div>
      </header>

      <wf-tenant-picker></wf-tenant-picker>

      <mat-card class="wf-card">
        @if (usersQuery.isLoading()) {
          <mat-spinner diameter="32"></mat-spinner>
        } @else if (usersQuery.data(); as users) {
          <table mat-table [dataSource]="users" class="wf-table">
            <ng-container matColumnDef="email">
              <th mat-header-cell *matHeaderCellDef>Email</th>
              <td mat-cell *matCellDef="let user">{{ user.email }}</td>
            </ng-container>

            <ng-container matColumnDef="name">
              <th mat-header-cell *matHeaderCellDef>Name</th>
              <td mat-cell *matCellDef="let user">{{ user.name || '—' }}</td>
            </ng-container>

            <ng-container matColumnDef="provider">
              <th mat-header-cell *matHeaderCellDef>Provider</th>
              <td mat-cell *matCellDef="let user" class="mono">{{ user.provider }}</td>
            </ng-container>

            <!-- The role a relying party reads out of the token's roles
                 claim. Assignable here because the endpoint has always
                 existed while this page could only display the value. -->
            <ng-container matColumnDef="role">
              <th mat-header-cell *matHeaderCellDef>Role</th>
              <td mat-cell *matCellDef="let user">
                <mat-form-field appearance="outline" subscriptSizing="dynamic" class="role-select">
                  <mat-select [value]="user.roleId ?? null"
                              (selectionChange)="setRole(user, $event.value)"
                              [disabled]="savingRoleFor === user.id">
                    <mat-option [value]="null">— none —</mat-option>
                    @for (r of rolesQuery.data() ?? []; track r.id) {
                      <mat-option [value]="r.id">{{ r.name }}</mat-option>
                    }
                  </mat-select>
                </mat-form-field>
              </td>
            </ng-container>

            <ng-container matColumnDef="actions">
              <th mat-header-cell *matHeaderCellDef>Actions</th>
              <td mat-cell *matCellDef="let user" class="actions">
                <button mat-stroked-button color="warn" (click)="resetMfa(user)"
                        matTooltip="Remove all MFA factors for this user">
                  <mat-icon>lock_reset</mat-icon> Reset MFA
                </button>
              </td>
            </ng-container>

            <tr mat-header-row *matHeaderRowDef="displayedColumns"></tr>
            <tr mat-row *matRowDef="let row; columns: displayedColumns"></tr>
          </table>
        } @else {
          <p class="empty mono">// no users found</p>
        }
      </mat-card>
    </div>
  `,
  styles: [`
    :host { display: block; }
    .wf-page { padding: 8px 0 48px; }
    .wf-page-header {
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--wf-border);
    }
    .wf-page-header h1 { font-family: 'Syne', sans-serif; font-size: 28px; margin: 4px 0 6px; }
    .eyebrow {
      font-size: 11px;
      letter-spacing: 0.2em;
      text-transform: uppercase;
      color: var(--wf-amber);
    }
    .sub { color: var(--wf-text-2); font-size: 13px; margin: 0; }
    .wf-card { padding: 20px; }
    .wf-table { width: 100%; }
    .actions { text-align: right; }
    .mono { font-family: 'Space Mono', monospace; }
    .empty { color: var(--wf-text-3); padding: 24px; text-align: center; }
    /* dynamic subscript: no reserved hint line, so the select sits on the
       row's baseline instead of pushing every row taller. */
    .role-select { width: 190px; }
  `]
})
export class UsersComponent {
  private adminService = inject(AdminService);
  private snack = inject(MatSnackBar);
  private queryClient = injectQueryClient();
  private tenantPicker = inject(TenantPickerService);

  displayedColumns = ['email', 'name', 'provider', 'role', 'actions'];

  // The tenant slug is part of the query key so the list is cached and
  // refetched per tenant: when a SUPER_ADMIN switches tenant in the
  // picker, the key changes, and TanStack fetches that tenant's users.
  usersQuery = injectQuery(() => ({
    queryKey: ['users', this.tenantPicker.activeTenantSlug()],
    queryFn: () => this.adminService.getUsers().toPromise(),
  }));

  // Same tenant-scoped key shape: the roles offered must be the roles that
  // exist in the tenant being edited, not whichever were loaded first.
  rolesQuery = injectQuery(() => ({
    queryKey: ['roles', this.tenantPicker.activeTenantSlug()],
    queryFn: () => this.adminService.getRoles().toPromise(),
  }));

  /** id of the user whose role is being saved, so its select disables. */
  savingRoleFor: number | null = null;

  setRole(user: User, roleId: number | null) {
    if ((user.roleId ?? null) === roleId) return;
    this.savingRoleFor = user.id;
    this.adminService.setUserRole(user.id, roleId).subscribe({
      next: () => {
        this.savingRoleFor = null;
        const name = (this.rolesQuery.data() ?? []).find((r: Role) => r.id === roleId)?.name;
        this.snack.open(
          roleId === null
            ? `Cleared the role for ${user.email}`
            : `${user.email} is now ${name}`,
          'OK', { duration: 4000 });
        // A user holds ONE role, so the list the server returns is the truth;
        // refetch rather than patching the row and hoping they agree.
        this.queryClient.invalidateQueries({ queryKey: ['users'] });
      },
      error: err => {
        this.savingRoleFor = null;
        // Refetch so the select snaps back to the stored value rather than
        // showing a change that did not happen.
        this.queryClient.invalidateQueries({ queryKey: ['users'] });
        this.snack.open(apiErrorMessage(err, 'Failed to assign the role'),
            'Dismiss', { duration: 5000 });
      },
    });
  }

  resetMfa(user: User) {
    const confirmMsg =
      `Reset MFA for ${user.email}?\n\n`
      + `This will remove every enrolled second factor and backup code. `
      + `The user will log in with their password only on next sign-in, `
      + `and should re-enroll immediately afterwards.\n\n`
      + `This action is audit-logged.`;
    if (!confirm(confirmMsg)) return;

    this.adminService.resetUserMfa(user.id).subscribe({
      next: res => {
        this.snack.open(
          `Removed ${res.removed} MFA factor${res.removed === 1 ? '' : 's'} for ${user.email}`,
          'OK',
          { duration: 4000 }
        );
      },
      error: err => {
        console.error(err);
        this.snack.open(
          apiErrorMessage(err, 'Failed to reset MFA'),
          'Dismiss',
          { duration: 5000 }
        );
      },
    });
  }
}
