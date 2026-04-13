import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatPaginatorModule, PageEvent } from '@angular/material/paginator';
import { AuditEvent, AuditFilter, AuditService } from '../../core/services/audit.service';

@Component({
  selector: 'app-audit',
  standalone: true,
  imports: [
    CommonModule, FormsModule,
    MatCardModule, MatFormFieldModule, MatInputModule, MatSelectModule,
    MatButtonModule, MatIconModule, MatPaginatorModule,
  ],
  template: `
    <div class="wf-page">
      <header class="wf-page-header">
        <div>
          <div class="eyebrow mono">// audit trail</div>
          <h1>Audit log</h1>
          <p class="sub">Every security-relevant event in your tenant. Use it for investigations, compliance reports, and SIEM feeds.</p>
        </div>
        <a mat-stroked-button color="primary" [href]="exportUrl()" download>
          <mat-icon>download</mat-icon> Export CSV
        </a>
      </header>

      <mat-card class="wf-card filters">
        <mat-form-field appearance="outline">
          <mat-label>Event type</mat-label>
          <mat-select [(ngModel)]="filter.eventType" (selectionChange)="refresh()">
            <mat-option [value]="">All</mat-option>
            <mat-option *ngFor="let t of eventTypeOptions" [value]="t">{{ t }}</mat-option>
          </mat-select>
        </mat-form-field>

        <mat-form-field appearance="outline">
          <mat-label>Actor email</mat-label>
          <input matInput [(ngModel)]="filter.actorEmail" (keyup.enter)="refresh()">
        </mat-form-field>

        <button mat-raised-button color="primary" (click)="refresh()">
          <mat-icon>search</mat-icon> Search
        </button>
      </mat-card>

      <mat-card class="wf-card">
        <table class="wf-table" *ngIf="events().length > 0">
          <thead>
            <tr>
              <th>When</th>
              <th>Event</th>
              <th>Outcome</th>
              <th>Actor</th>
              <th>Target</th>
              <th>IP</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let e of events()">
              <td class="mono nowrap">{{ e.createdAt | date:'yyyy-MM-dd HH:mm:ss' }}</td>
              <td class="mono">{{ e.eventType }}</td>
              <td>
                <span class="outcome" [class.ok]="e.outcome === 'SUCCESS'"
                                      [class.bad]="e.outcome !== 'SUCCESS'">{{ e.outcome }}</span>
              </td>
              <td>{{ e.actorEmail || '—' }}</td>
              <td class="mono">{{ e.targetType }}{{ e.targetId ? ' · ' + e.targetId : '' }}</td>
              <td class="mono">{{ e.ipAddress || '—' }}</td>
            </tr>
          </tbody>
        </table>
        <div class="empty mono" *ngIf="events().length === 0">// no events match the filter</div>

        <mat-paginator
          *ngIf="totalElements() > 0"
          [length]="totalElements()"
          [pageSize]="filter.size || 50"
          [pageSizeOptions]="[25, 50, 100, 200]"
          [pageIndex]="filter.page || 0"
          (page)="pageChange($event)">
        </mat-paginator>
      </mat-card>
    </div>
  `,
  styles: [`
    :host { display: block; }
    .wf-page { padding: 8px 0 48px; }
    .wf-page-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      gap: 24px;
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
    .wf-card { padding: 20px; margin-bottom: 16px; }
    .filters {
      display: flex;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
    }
    .filters mat-form-field { flex: 1 1 220px; min-width: 200px; }

    .wf-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    .wf-table th, .wf-table td {
      text-align: left;
      padding: 8px 10px;
      border-bottom: 1px solid var(--wf-border);
      vertical-align: top;
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
    .nowrap { white-space: nowrap; }

    .outcome {
      font-family: 'Space Mono', monospace;
      font-size: 10px;
      letter-spacing: 0.1em;
      padding: 2px 8px;
      border-radius: 2px;
    }
    .outcome.ok {
      background: rgba(74, 143, 245, 0.15);
      color: var(--wf-blue);
    }
    .outcome.bad {
      background: rgba(255, 80, 80, 0.15);
      color: #FF6B6B;
    }
    .empty {
      color: var(--wf-text-3);
      padding: 32px;
      text-align: center;
      border: 1px dashed var(--wf-border);
    }
  `]
})
export class AuditComponent implements OnInit {
  events = signal<AuditEvent[]>([]);
  totalElements = signal<number>(0);
  filter: AuditFilter = { page: 0, size: 50 };

  eventTypeOptions = [
    'auth.login.success', 'auth.login.failed', 'auth.login.mfa_required', 'auth.register',
    'mfa.factor.enroll', 'mfa.factor.activate', 'mfa.factor.remove',
    'mfa.challenge.success', 'mfa.challenge.failed',
    'mfa.self_reset', 'mfa.admin_reset', 'mfa.backup_codes.regenerated',
    'tenant.create', 'tenant.update', 'tenant.delete',
    'social_provider.upsert', 'social_provider.delete',
    'saml_provider.upsert', 'saml_provider.delete',
    'saml_idp.assertion.issued', 'saml_idp.sp.create', 'saml_idp.sp.update', 'saml_idp.sp.delete',
    'group_role.mapping.create', 'group_role.mapping.delete', 'group_role.apply',
    'scim.group.create', 'scim.group.replace', 'scim.group.patch', 'scim.group.delete',
    'scim.group.member.add', 'scim.group.member.remove',
    'scim.user.create', 'scim.user.replace', 'scim.user.patch', 'scim.user.delete',
    'scim.user.deactivate', 'scim.user.reactivate',
    'user.delete',
  ];

  constructor(private api: AuditService) {}

  ngOnInit() { this.refresh(); }

  refresh() {
    this.api.search(this.filter).subscribe({
      next: res => {
        this.events.set(res.content);
        this.totalElements.set(res.totalElements);
      },
      error: err => console.error('Audit search failed', err),
    });
  }

  pageChange(e: PageEvent) {
    this.filter.page = e.pageIndex;
    this.filter.size = e.pageSize;
    this.refresh();
  }

  exportUrl(): string {
    return this.api.exportCsvUrl({ ...this.filter, page: undefined, size: undefined });
  }
}
