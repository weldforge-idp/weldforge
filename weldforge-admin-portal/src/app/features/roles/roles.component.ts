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
import { TenantPickerComponent } from '../../shared/tenant-picker/tenant-picker.component';
import { TenantPickerService } from '../../core/services/tenant-picker.service';

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
    MatIconModule,
    TenantPickerComponent,
  ],
  templateUrl: './roles.component.html',
  // `.form-row` was referenced by the template but defined nowhere in the
  // codebase, so the two inputs and the button rendered flush against each
  // other with no gap at all. Matches the grid used on the Tenants and
  // Service Accounts screens so the three forms look like one product.
  styles: [`
    .form-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)) auto;
      align-items: start;
      gap: 12px;
      margin-bottom: 20px;
    }
    /* The button sits beside inputs whose outline field reserves space for a
       hint line underneath, so without this it floats above their baseline. */
    .form-row button {
      height: 56px;
      padding: 0 24px;
      white-space: nowrap;
    }
    @media (max-width: 720px) {
      .form-row { grid-template-columns: 1fr; }
      .form-row button { width: 100%; }
    }
    table { width: 100%; margin-top: 8px; }
  `]
})
export class RolesComponent {
  private adminService = inject(AdminService);
  private tenantPicker = inject(TenantPickerService);

  displayedColumns = ['name', 'description', 'actions'];

  // Tenant slug in the key — switching tenant in the picker refetches
  // and caches roles per tenant. See UsersComponent for the rationale.
  rolesQuery = injectQuery(() => ({
    queryKey: ['roles', this.tenantPicker.activeTenantSlug()],
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