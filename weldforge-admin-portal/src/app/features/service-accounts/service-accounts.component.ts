import { Component, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { firstValueFrom } from 'rxjs';

import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';

import { injectMutation, injectQuery, injectQueryClient } from '@tanstack/angular-query-experimental';

import { AuthService } from '../../core/services/auth.service';
import {
  AdminRole,
  CreateServiceAccountDto,
  ServiceAccount,
  ServiceAccountApi,
} from '../../core/services/service-account.service';
import { TenantPickerComponent } from '../../shared/tenant-picker/tenant-picker.component';
import { TenantPickerService } from '../../core/services/tenant-picker.service';

@Component({
  selector: 'app-service-accounts',
  standalone: true,
  imports: [
    CommonModule, FormsModule,
    MatButtonModule, MatCardModule, MatChipsModule, MatFormFieldModule,
    MatIconModule, MatInputModule, MatProgressSpinnerModule, MatSelectModule,
    MatSlideToggleModule, MatSnackBarModule, MatTableModule, MatTooltipModule,
    TenantPickerComponent,
  ],
  template: `
    <div class="wf-page">
      <header class="wf-page-header">
        <div>
          <div class="eyebrow mono">// api &amp; m2m</div>
          <h1>Service accounts</h1>
          <p class="sub">
            Long-lived <code>wf_svc_*</code> tokens for AI agents, CI bots and other
            machine-to-machine integrations. Carry an admin role and populate a
            Spring SecurityContext on every request — the caller is treated as a
            first-class admin for <code>&#64;PreAuthorize</code> guards.
            <a href="https://weldforge.org/agents.html#auth" target="_blank" rel="noopener">Read more</a>.
          </p>
        </div>
      </header>

      <wf-tenant-picker></wf-tenant-picker>

      @if (revealed(); as r) {
        <mat-card class="wf-token-banner">
          <div class="wf-banner-header">
            <mat-icon class="banner-icon">vpn_key</mat-icon>
            <div>
              <h3>Token for "{{ r.name }}" — shown once</h3>
              <p class="sub">
                Copy it now and store it in a secret manager. The hash is kept
                server-side; we cannot retrieve the raw token after this banner
                is dismissed. If you lose it, use <strong>Rotate</strong> to mint
                a replacement.
              </p>
            </div>
          </div>
          <pre class="token-box mono"><code>{{ r.token }}</code></pre>
          <div class="wf-actions">
            <button mat-stroked-button (click)="copyToken(r.token!)">
              <mat-icon>content_copy</mat-icon> Copy token
            </button>
            <span class="spacer"></span>
            <button mat-button (click)="revealed.set(null)">Dismiss</button>
          </div>
        </mat-card>
      }

      <mat-card class="wf-card wf-create">
        <h3 class="section-title">Create service account</h3>
        <div class="wf-grid">
          <mat-form-field appearance="outline">
            <mat-label>Name</mat-label>
            <input matInput [(ngModel)]="draft.name" placeholder="junie, ci-deploy, …" autocomplete="off">
          </mat-form-field>
          <mat-form-field appearance="outline" class="wide">
            <mat-label>Description (optional)</mat-label>
            <input matInput [(ngModel)]="draft.description"
                   placeholder="What this token is for. Shown only to admins.">
          </mat-form-field>
          <mat-form-field appearance="outline">
            <mat-label>Admin role</mat-label>
            <mat-select [(ngModel)]="draft.adminRole">
              @for (r of availableRoles(); track r) {
                <mat-option [value]="r">{{ r }}</mat-option>
              }
            </mat-select>
          </mat-form-field>
        </div>
        <div class="wf-actions">
          <span class="spacer"></span>
          <button mat-raised-button color="primary"
                  [disabled]="!canCreate() || createMutation.isPending()"
                  (click)="create()">
            {{ createMutation.isPending() ? 'Creating…' : 'Create' }}
          </button>
        </div>
      </mat-card>

      <mat-card class="wf-card">
        <h3 class="section-title">Existing tokens</h3>

        @if (listQuery.isLoading()) {
          <mat-spinner diameter="32"></mat-spinner>
        } @else if (listQuery.data(); as accounts) {
          @if (accounts.length === 0) {
            <p class="empty mono">// no service accounts in this tenant yet</p>
          } @else {
            <table mat-table [dataSource]="accounts" class="wf-table">
              <ng-container matColumnDef="name">
                <th mat-header-cell *matHeaderCellDef>Name</th>
                <td mat-cell *matCellDef="let s">
                  <div class="name">{{ s.name }}</div>
                  @if (s.description) {
                    <div class="sub">{{ s.description }}</div>
                  }
                </td>
              </ng-container>

              <ng-container matColumnDef="tenant">
                <th mat-header-cell *matHeaderCellDef>Tenant</th>
                <td mat-cell *matCellDef="let s">
                  <div>{{ s.tenantName || s.tenantSlug || '—' }}</div>
                  @if (s.tenantSlug && s.tenantName) {
                    <div class="sub mono">{{ s.tenantSlug }}</div>
                  }
                </td>
              </ng-container>

              <ng-container matColumnDef="prefix">
                <th mat-header-cell *matHeaderCellDef>Token</th>
                <td mat-cell *matCellDef="let s" class="mono prefix">{{ s.tokenPrefix }}…</td>
              </ng-container>

              <ng-container matColumnDef="role">
                <th mat-header-cell *matHeaderCellDef>Role</th>
                <td mat-cell *matCellDef="let s">
                  <mat-chip [class.role-super]="s.adminRole === 'SUPER_ADMIN'"
                            [class.role-tenant]="s.adminRole === 'TENANT_ADMIN'"
                            [class.role-read]="s.adminRole === 'READ_ONLY'">
                    {{ s.adminRole }}
                  </mat-chip>
                </td>
              </ng-container>

              <ng-container matColumnDef="enabled">
                <th mat-header-cell *matHeaderCellDef>Enabled</th>
                <td mat-cell *matCellDef="let s">
                  <mat-slide-toggle [checked]="s.enabled"
                                    (change)="toggleEnabled(s, $event.checked)">
                  </mat-slide-toggle>
                </td>
              </ng-container>

              <ng-container matColumnDef="lastUsed">
                <th mat-header-cell *matHeaderCellDef>Last used</th>
                <td mat-cell *matCellDef="let s" class="mono dim">
                  {{ s.lastUsedAt ? (s.lastUsedAt | date:'yyyy-MM-dd HH:mm') : 'never' }}
                </td>
              </ng-container>

              <ng-container matColumnDef="actions">
                <th mat-header-cell *matHeaderCellDef class="actions-col">Actions</th>
                <td mat-cell *matCellDef="let s" class="actions-col">
                  <button mat-icon-button (click)="rotate(s)"
                          matTooltip="Mint a fresh token (the old one stops working immediately).">
                    <mat-icon>autorenew</mat-icon>
                  </button>
                  <button mat-icon-button color="warn" (click)="remove(s)"
                          matTooltip="Delete this service account.">
                    <mat-icon>delete</mat-icon>
                  </button>
                </td>
              </ng-container>

              <tr mat-header-row *matHeaderRowDef="columns"></tr>
              <tr mat-row *matRowDef="let row; columns: columns"></tr>
            </table>
          }
        } @else if (listQuery.error(); as err) {
          <div class="wf-load-error">
            <mat-icon class="err-icon">error_outline</mat-icon>
            <div>
              <div class="err-title">Could not load service accounts.</div>
              <div class="err-detail mono">{{ errorSummary(err) }}</div>
              <button mat-stroked-button (click)="listQuery.refetch()">
                <mat-icon>refresh</mat-icon> Try again
              </button>
            </div>
          </div>
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
    .sub { color: var(--wf-text-2); font-size: 13px; margin: 0; max-width: 720px; }
    .sub a { color: var(--wf-blue); }

    .wf-card { padding: 20px; margin-bottom: 16px; }
    .section-title {
      font-family: 'Syne', sans-serif;
      font-size: 16px;
      margin: 0 0 16px;
    }

    .wf-create .wf-grid {
      display: grid;
      grid-template-columns: 1fr 2fr 1fr;
      gap: 12px;
    }
    .wf-create .wide { grid-column: span 1; }
    @media (max-width: 880px) {
      .wf-create .wf-grid { grid-template-columns: 1fr; }
    }

    .wf-actions {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 8px;
    }
    .spacer { flex: 1 1 auto; }

    .wf-table { width: 100%; }
    .wf-table .name { font-weight: 600; }
    .wf-table .sub { font-size: 12px; }
    .wf-table .prefix { color: var(--wf-amber); font-size: 12px; }
    .wf-table .dim { color: var(--wf-text-3); font-size: 12px; }
    .wf-table .actions-col { text-align: right; white-space: nowrap; }

    .role-super { background: rgba(232, 146, 31, 0.18) !important; color: var(--wf-amber) !important; }
    .role-tenant { background: rgba(74, 143, 245, 0.18) !important; color: var(--wf-blue) !important; }
    .role-read { background: rgba(136, 153, 204, 0.18) !important; color: var(--wf-text-2) !important; }

    .empty {
      color: var(--wf-text-3);
      padding: 24px;
      text-align: center;
      border: 1px dashed var(--wf-border);
      margin: 12px 0;
    }
    .mono { font-family: 'Space Mono', monospace; }

    /* One-time-token reveal banner */
    .wf-token-banner {
      border: 1px solid var(--wf-amber);
      background: rgba(232, 146, 31, 0.06) !important;
      padding: 16px 20px;
      margin-bottom: 16px;
    }
    .wf-banner-header {
      display: flex;
      gap: 14px;
      align-items: flex-start;
    }
    .banner-icon { color: var(--wf-amber); margin-top: 2px; }
    .wf-token-banner h3 {
      font-family: 'Syne', sans-serif;
      margin: 0 0 4px;
      font-size: 15px;
    }
    .token-box {
      background: var(--wf-bg-3);
      border: 1px solid var(--wf-border);
      padding: 12px;
      margin: 12px 0;
      overflow-x: auto;
      font-size: 12px;
    }
    .token-box code { color: var(--wf-amber); }

    .wf-load-error {
      display: flex;
      gap: 14px;
      align-items: flex-start;
      padding: 16px;
      border: 1px dashed var(--wf-border);
      background: rgba(244, 67, 54, 0.04);
      border-radius: 4px;
    }
    .wf-load-error .err-icon { color: #f44336; margin-top: 2px; }
    .wf-load-error .err-title { font-weight: 600; margin-bottom: 4px; }
    .wf-load-error .err-detail { color: var(--wf-text-3); font-size: 12px; margin-bottom: 10px; }
  `]
})
export class ServiceAccountsComponent {
  private api = inject(ServiceAccountApi);
  private auth = inject(AuthService);
  private snack = inject(MatSnackBar);
  private queryClient = injectQueryClient();
  private tenantPicker = inject(TenantPickerService);

  protected columns = ['name', 'tenant', 'prefix', 'role', 'enabled', 'lastUsed', 'actions'];

  /** Token surfaced after a successful create or rotate. Cleared on Dismiss. */
  protected revealed = signal<ServiceAccount | null>(null);

  protected draft: CreateServiceAccountDto = {
    name: '',
    description: '',
    adminRole: 'TENANT_ADMIN',
  };

  /** SUPER_ADMIN is gated server-side; mirror that in the UI so a non-super
   *  admin doesn't pick a role only to get a 403 back. */
  protected availableRoles = computed<AdminRole[]>(() => {
    const base: AdminRole[] = ['NONE', 'READ_ONLY', 'TENANT_ADMIN'];
    return this.auth.isSuperAdmin() ? [...base, 'SUPER_ADMIN'] : base;
  });

  // Plain method, NOT a computed(). The `draft` field is a non-signal
  // object mutated by [(ngModel)] on the form inputs; computed() only
  // re-runs when its tracked signals change, so wrapping this in
  // computed() would freeze its value at the construction-time snapshot
  // (name === '' → false) and never re-evaluate, leaving the Create
  // button permanently disabled. A method re-evaluates on every CD pass,
  // and ngModel triggers a CD pass on every input event, which is what
  // we want here.
  protected canCreate(): boolean {
    return !!this.draft.name?.trim() && !!this.draft.adminRole;
  }

  // Tenant slug in the key — switching tenant in the picker refetches
  // and caches the token list per tenant. The mutation invalidations
  // below pass a bare ['service-accounts'] key, which prefix-matches
  // every ['service-accounts', <slug>] entry, so they still work.
  protected listQuery = injectQuery(() => ({
    queryKey: ['service-accounts', this.tenantPicker.activeTenantSlug()],
    queryFn: () => firstValueFrom(this.api.list()),
  }));

  protected createMutation = injectMutation(() => ({
    mutationFn: (dto: CreateServiceAccountDto) => firstValueFrom(this.api.create(dto)),
    onSuccess: (sa) => {
      this.revealed.set(sa);
      this.draft = { name: '', description: '', adminRole: 'TENANT_ADMIN' };
      this.queryClient.invalidateQueries({ queryKey: ['service-accounts'] });
    },
    onError: (err: any) => this.toast(err?.error?.message || 'Failed to create service account'),
  }));

  protected create() {
    if (!this.canCreate()) return;
    const payload: CreateServiceAccountDto = {
      name: this.draft.name.trim(),
      description: this.draft.description?.trim() || undefined,
      adminRole: this.draft.adminRole,
    };
    this.createMutation.mutate(payload);
  }

  protected rotate(s: ServiceAccount) {
    const ok = confirm(
      `Rotate token for "${s.name}"?\n\n`
      + `The current token (${s.tokenPrefix}…) stops working immediately. `
      + `Anything still using the old token will get 401 until you swap in the new one.`
    );
    if (!ok) return;
    this.api.rotate(s.id).subscribe({
      next: rotated => {
        this.revealed.set(rotated);
        this.queryClient.invalidateQueries({ queryKey: ['service-accounts'] });
      },
      error: err => this.toast(err?.error?.message || 'Failed to rotate token'),
    });
  }

  protected toggleEnabled(s: ServiceAccount, enabled: boolean) {
    this.api.update(s.id, { enabled }).subscribe({
      next: () => this.queryClient.invalidateQueries({ queryKey: ['service-accounts'] }),
      error: err => {
        this.toast(err?.error?.message || `Failed to ${enabled ? 'enable' : 'disable'} token`);
        this.queryClient.invalidateQueries({ queryKey: ['service-accounts'] });
      },
    });
  }

  protected remove(s: ServiceAccount) {
    const ok = confirm(
      `Delete service account "${s.name}"?\n\n`
      + `Its token is revoked immediately. This cannot be undone.`
    );
    if (!ok) return;
    this.api.delete(s.id).subscribe({
      next: () => {
        this.toast(`Deleted "${s.name}"`);
        this.queryClient.invalidateQueries({ queryKey: ['service-accounts'] });
      },
      error: err => this.toast(err?.error?.message || 'Failed to delete service account'),
    });
  }

  protected copyToken(token: string) {
    navigator.clipboard.writeText(token).then(
      () => this.toast('Token copied to clipboard'),
      () => this.toast('Could not copy — select the text manually'),
    );
  }

  private toast(msg: string) {
    this.snack.open(msg, 'OK', { duration: 4000 });
  }

  /**
   * Render a one-line human-readable summary for the load-error panel.
   * Covers the three shapes the listQuery can fail with: a real
   * HttpErrorResponse from the backend (status + error.message), the
   * "Http failure during parsing" case that fires when the response is
   * HTML rather than JSON (which is what 401 redirect-to-login produced
   * before the backend 401 entry point shipped), and unknown shapes.
   */
  protected errorSummary(err: unknown): string {
    const e = err as { status?: number; statusText?: string; message?: string; error?: { message?: string } };
    if (typeof e?.status === 'number') {
      if (e.status === 0) return 'Network error — the server did not respond.';
      if (e.status === 401) return 'Session expired. Reload the page to log in again.';
      if (e.status === 403) return 'You do not have permission to view service accounts in this tenant.';
      const upstream = e.error?.message || e.statusText;
      return `HTTP ${e.status}${upstream ? ' — ' + upstream : ''}`;
    }
    return e?.message ?? 'Unknown error.';
  }
}
