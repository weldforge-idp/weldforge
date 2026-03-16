import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatTableModule } from '@angular/material/table';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { injectQuery } from '@tanstack/angular-query-experimental';

import { AdminService, User } from '../../core/services/admin.service';

@Component({
  selector: 'app-users',
  standalone: true,
  imports: [
    CommonModule,
    MatTableModule, MatCardModule, MatButtonModule,
    MatProgressSpinnerModule
  ],
  template: `
    <mat-card>
      <mat-card-header>
        <mat-card-title>Users Management</mat-card-title>
      </mat-card-header>

      <mat-card-content>
        <button mat-raised-button color="primary" (click)="createUser()">Add User</button>

        @if (usersQuery.isLoading()) {
          <mat-spinner></mat-spinner>
        } @else if (usersQuery.data(); as users) {
          <table mat-table [dataSource]="users">
            <ng-container matColumnDef="email">
              <th mat-header-cell *matHeaderCellDef>Email</th>
              <td mat-cell *matCellDef="let user">{{ user.email }}</td>
            </ng-container>

            <ng-container matColumnDef="name">
              <th mat-header-cell *matHeaderCellDef>Name</th>
              <td mat-cell *matCellDef="let user">{{ user.name }}</td>
            </ng-container>

            <ng-container matColumnDef="provider">
              <th mat-header-cell *matHeaderCellDef>Provider</th>
              <td mat-cell *matCellDef="let user">{{ user.provider }}</td>
            </ng-container>

            <ng-container matColumnDef="role">
              <th mat-header-cell *matHeaderCellDef>Role</th>
              <td mat-cell *matCellDef="let user">{{ user.role?.name || 'None' }}</td>
            </ng-container>

            <ng-container matColumnDef="actions">
              <th mat-header-cell *matHeaderCellDef>Actions</th>
              <td mat-cell *matCellDef="let user">
                <button mat-icon-button (click)="viewUser(user)">view</button>
              </td>
            </ng-container>

            <tr mat-header-row *matHeaderRowDef="displayedColumns"></tr>
            <tr mat-row *matRowDef="let row; columns: displayedColumns"></tr>
          </table>
        } @else {
          <p>No users found.</p>
        }
      </mat-card-content>
    </mat-card>
  `
})
export class UsersComponent {
  private adminService = inject(AdminService);

  displayedColumns = ['email', 'name', 'provider', 'role', 'actions'];

  usersQuery = injectQuery(() => ({
    queryKey: ['users'],
    queryFn: () => this.adminService.getUsers().toPromise()
  }));

  createUser() {
    // Implement form/dialog for new user creation
  }

  viewUser(user: User) {
    // Implement detail view or dialog
  }
}