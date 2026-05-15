import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatTableModule } from '@angular/material/table';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { injectQuery, injectQueryClient } from '@tanstack/angular-query-experimental';

import { AdminService, User } from '../../core/services/admin.service';
import { TenantPickerComponent } from '../../shared/tenant-picker/tenant-picker.component';
import { TenantPickerService } from '../../core/services/tenant-picker.service';

@Component({
  selector: 'app-users',
  standalone: true,
  imports: [
    CommonModule,
    MatTableModule, MatCardModule, MatButtonModule, MatIconModule,
    MatProgressSpinnerModule, MatSnackBarModule,
    TenantPickerComponent,
  ],
  template: `
    <div class="wf-page">
      <header class="wf-page-header">
        <div>
          <div class="eyebrow mono">// users</div>
          <h1>Users</h1>
          <p class="sub">Everyone in this tenant. Reset a user's MFA here if they've lost access to their second factor.</p>
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

            <ng-container matColumnDef="role">
              <th mat-header-cell *matHeaderCellDef>Role</th>
              <td mat-cell *matCellDef="let user">{{ user.role?.name || '—' }}</td>
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
          err?.error?.message || 'Failed to reset MFA',
          'Dismiss',
          { duration: 5000 }
        );
      },
    });
  }
}
