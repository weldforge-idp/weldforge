import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatIconModule } from '@angular/material/icon';
import { injectQuery, injectQueryClient } from '@tanstack/angular-query-experimental';
import { firstValueFrom } from 'rxjs';

import { AuthService } from '../../core/services/auth.service';
import { TenantPickerService } from '../../core/services/tenant-picker.service';
import { TenantService, Tenant } from '../../core/services/tenant.service';

/**
 * SUPER_ADMIN-only tenant switcher. Renders nothing for any other
 * caller (the host page should still mount the component — gating is
 * baked in here so the page templates stay simple).
 *
 * On change: writes the selected slug into TenantPickerService (which
 * the tenant interceptor reads), then invalidates the user/role query
 * caches so any visible list re-fetches against the newly-active
 * tenant. Other queries on the same page reload through the same
 * mechanism.
 */
@Component({
  selector: 'wf-tenant-picker',
  standalone: true,
  imports: [
    CommonModule, FormsModule,
    MatFormFieldModule, MatSelectModule, MatIconModule,
  ],
  template: `
    @if (auth.isSuperAdmin()) {
      <div class="wf-tenant-picker">
        <mat-icon class="picker-icon">apartment</mat-icon>
        <mat-form-field appearance="outline" subscriptSizing="dynamic">
          <mat-label>Acting as tenant</mat-label>
          <mat-select [ngModel]="active()" (ngModelChange)="onChange($event)">
            @for (t of tenants(); track t.slug) {
              <mat-option [value]="t.slug">
                {{ t.displayName || t.name }}
                <span class="slug mono">{{ t.slug }}</span>
              </mat-option>
            }
          </mat-select>
        </mat-form-field>
      </div>
    }
  `,
  styles: [`
    .wf-tenant-picker {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 16px;
    }
    .picker-icon { color: var(--wf-amber, #d4a017); }
    .slug {
      font-family: 'Space Mono', monospace;
      font-size: 11px;
      color: var(--wf-text-3, #888);
      margin-left: 8px;
    }
    mat-form-field { min-width: 280px; }
  `]
})
export class TenantPickerComponent {
  protected readonly auth = inject(AuthService);
  private readonly picker = inject(TenantPickerService);
  private readonly tenantService = inject(TenantService);
  private readonly queryClient = injectQueryClient();

  private readonly tenantsQuery = injectQuery(() => ({
    queryKey: ['tenant-picker', 'list'],
    queryFn: () => firstValueFrom(this.tenantService.list()),
    enabled: this.auth.isSuperAdmin(),
    staleTime: 60_000,
  }));

  protected tenants(): Tenant[] {
    return this.tenantsQuery.data() ?? [];
  }

  protected active(): string {
    return this.picker.activeTenantSlug() ?? this.auth.getHomeTenantSlug() ?? '';
  }

  protected onChange(slug: string): void {
    const t = this.tenants().find(x => x.slug === slug);
    this.picker.set(slug, t?.id ?? null);
    // Invalidate everything page-level — the tenant changed, so any
    // user/role/group-role-mapping list visible on the current page
    // needs to refetch under the new tenant context.
    this.queryClient.invalidateQueries();
  }
}
