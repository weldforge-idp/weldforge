import { Component, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatTableModule } from '@angular/material/table';
import { MatButtonModule } from '@angular/material/button';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatCardModule } from '@angular/material/card';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatIconModule } from '@angular/material/icon';
import { injectMutation, injectQuery } from '@tanstack/angular-query-experimental';

import { AdminService, Role } from '../../core/services/admin.service';

@Component({
  selector: 'app-roles',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatTableModule,
    MatButtonModule,
    MatInputModule,
    MatFormFieldModule,
    MatCardModule,
    MatProgressSpinnerModule,
    MatIconModule
  ],
  templateUrl: './roles.component.html'
})
export class RolesComponent {
  private adminService = inject(AdminService);

  displayedColumns = ['name', 'description', 'actions'];

  rolesQuery = injectQuery(() => ({
    queryKey: ['roles'],
    queryFn: () => this.adminService.getRoles().toPromise()
  }));

  createMutation = injectMutation(() => ({
    mutationFn: (role: Role) => this.adminService.createRole(role).toPromise(),
    onSuccess: () => this.rolesQuery.refetch()
  }));

  newRole = signal<Partial<Role>>({ name: '', description: '' });

  addRole() {
    const role = this.newRole();
    if (!role.name?.trim()) return;

    this.createMutation.mutate(role as Role);
    this.newRole.set({ name: '', description: '' });
  }
}