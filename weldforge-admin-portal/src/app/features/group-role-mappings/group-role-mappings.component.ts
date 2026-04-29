import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { GroupRoleMappingService, GroupRoleMapping } from '../../core/services/group-role-mapping.service';
import { AdminService, Role } from '../../core/services/admin.service';

@Component({
  selector: 'app-group-role-mappings',
  standalone: true,
  imports: [
    CommonModule, FormsModule,
    MatCardModule, MatButtonModule, MatIconModule,
    MatFormFieldModule, MatInputModule, MatSelectModule,
    MatSnackBarModule,
  ],
  template: `
    <div class="wf-page">
      <header class="wf-page-header">
        <div>
          <div class="eyebrow mono">// group-role-mappings</div>
          <h1>Group-Role Mappings</h1>
          <p class="sub">Map SCIM groups to roles for automatic role assignment. When a user belongs to a SCIM group, they inherit the mapped role based on priority.</p>
        </div>
      </header>

      <!-- Create form -->
      <mat-card class="wf-card wf-create-card">
        <h3>Add mapping</h3>
        <div class="wf-grid">
          <mat-form-field appearance="outline">
            <mat-label>SCIM Group ID</mat-label>
            <input matInput type="number" [(ngModel)]="newMapping.scimGroupId" required>
          </mat-form-field>
          <mat-form-field appearance="outline">
            <mat-label>Role</mat-label>
            <mat-select [(ngModel)]="newMapping.roleId" required>
              <mat-option *ngFor="let role of roles()" [value]="role.id">
                {{ role.name }}
              </mat-option>
            </mat-select>
          </mat-form-field>
          <mat-form-field appearance="outline">
            <mat-label>Priority</mat-label>
            <input matInput type="number" [(ngModel)]="newMapping.priority" required>
          </mat-form-field>
        </div>
        <div class="wf-actions">
          <span class="spacer"></span>
          <button mat-raised-button color="primary"
                  [disabled]="!newMapping.scimGroupId || !newMapping.roleId"
                  (click)="createMapping()">
            Create
          </button>
        </div>
      </mat-card>

      <!-- Mappings table -->
      <mat-card class="wf-card" *ngIf="mappings().length > 0">
        <table class="wf-table">
          <thead>
            <tr>
              <th>SCIM Group</th>
              <th>Role</th>
              <th>Priority</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let m of mappings()">
              <td>
                <span class="mono">{{ m.scimGroupName || ('Group #' + m.scimGroupId) }}</span>
              </td>
              <td>{{ m.roleName || ('Role #' + m.roleId) }}</td>
              <td class="mono">{{ m.priority }}</td>
              <td>
                <button mat-icon-button color="warn" (click)="deleteMapping(m)"
                        title="Remove mapping">
                  <mat-icon>delete</mat-icon>
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </mat-card>

      <!-- Empty state -->
      <div *ngIf="mappings().length === 0 && loaded()" class="empty mono">
        // no group-role mappings configured yet
      </div>
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
    .sub { color: var(--wf-text-2); font-size: 13px; margin: 0; max-width: 640px; }

    .wf-card { padding: 24px; margin-bottom: 16px; }
    .wf-create-card h3 {
      font-family: 'Syne', sans-serif;
      margin: 0 0 16px;
    }

    .wf-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
    }

    .wf-actions {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 12px;
    }
    .spacer { flex: 1 1 auto; }

    .wf-table {
      width: 100%;
      border-collapse: collapse;
      margin: 0;
      font-size: 13px;
    }
    .wf-table th, .wf-table td {
      text-align: left;
      padding: 8px 10px;
      border-bottom: 1px solid var(--wf-border);
    }
    .wf-table th {
      font-family: 'Space Mono', monospace;
      font-size: 10px;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: var(--wf-text-3);
      font-weight: 400;
    }

    .mono { font-family: 'Space Mono', monospace; }

    .empty {
      color: var(--wf-text-3);
      padding: 16px;
      text-align: center;
      border: 1px dashed var(--wf-border);
      margin: 12px 0;
    }
  `]
})
export class GroupRoleMappingsComponent implements OnInit {
  mappings = signal<GroupRoleMapping[]>([]);
  roles = signal<Role[]>([]);
  loaded = signal(false);

  newMapping: Partial<GroupRoleMapping> = { scimGroupId: undefined, roleId: undefined, priority: 0 };

  constructor(
    private mappingService: GroupRoleMappingService,
    private adminService: AdminService,
    private snack: MatSnackBar,
  ) {}

  ngOnInit() {
    this.refresh();
    this.loadRoles();
  }

  refresh() {
    this.mappingService.list().subscribe({
      next: ms => {
        this.mappings.set(ms);
        this.loaded.set(true);
      },
      error: err => this.err('Failed to load mappings', err),
    });
  }

  loadRoles() {
    this.adminService.getRoles().subscribe({
      next: rs => this.roles.set(rs),
      error: err => this.err('Failed to load roles', err),
    });
  }

  createMapping() {
    const m = this.newMapping;
    if (!m.scimGroupId || !m.roleId) return;
    this.mappingService.create(m).subscribe({
      next: created => {
        this.mappings.update(ms => [...ms, created]);
        this.newMapping = { scimGroupId: undefined, roleId: undefined, priority: 0 };
        this.ok('Mapping created');
      },
      error: err => this.err('Create failed', err),
    });
  }

  deleteMapping(m: GroupRoleMapping) {
    if (!m.id) return;
    if (!confirm(`Remove mapping for group "${m.scimGroupName || m.scimGroupId}" to role "${m.roleName || m.roleId}"?`)) return;
    this.mappingService.delete(m.id).subscribe({
      next: () => {
        this.mappings.update(ms => ms.filter(x => x.id !== m.id));
        this.ok('Mapping removed');
      },
      error: err => this.err('Delete failed', err),
    });
  }

  private ok(msg: string) { this.snack.open(msg, 'OK', { duration: 3000 }); }
  private err(msg: string, e: any) {
    console.error(msg, e);
    this.snack.open(`${msg}${e?.error?.message ? ': ' + e.error.message : ''}`, 'Dismiss', { duration: 5000 });
  }
}
