import { Component, Input, OnInit, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute } from '@angular/router';
import { TenantBrandingService } from '../../core/services/tenant-branding.service';

/**
 * Branding-aware visual shell shared by every public auth screen
 * (login, register, forgot/reset password, verify email). Reads
 * `?tenant=` from the URL on init and applies the tenant's CSS-var
 * palette. Slot content into the default ng-content; pass `headline`
 * and optionally `subline` via inputs.
 */
@Component({
  selector: 'app-auth-shell',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="wf-login-shell">
      <div class="wf-login-card">
        <div class="wf-login-header">
          <img [src]="logoUrl()" [alt]="displayName()" height="44">
          <div class="wf-eyebrow" *ngIf="eyebrow()">{{ eyebrow() }}</div>
          <h1>{{ headline }}</h1>
          <p class="wf-sub" *ngIf="subline">{{ subline }}</p>
        </div>
        <ng-content></ng-content>
        <div class="wf-footer mono" *ngIf="!hideFooter()">
          <span>OAUTH2 · OIDC · SAML · X.509 · SCIM · TOTP · FIDO2</span>
        </div>
      </div>
    </div>
  `,
  styles: [`
    :host { display: block; }
    .wf-login-shell {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: calc(100vh - 64px);
      padding: 48px 24px;
      position: relative;
    }
    .wf-login-shell::after {
      content: '';
      position: absolute;
      inset: 0;
      background: radial-gradient(ellipse at 50% 40%, var(--wf-amber-glow, rgba(232, 146, 31, 0.08)) 0%, transparent 55%);
      pointer-events: none;
    }
    .wf-login-card {
      position: relative;
      width: 100%;
      max-width: 440px;
      background: var(--wf-bg-2);
      border: 1px solid var(--wf-border);
      padding: 40px 36px;
      border-radius: 4px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(74, 143, 245, 0.05) inset;
    }
    .wf-login-header { text-align: center; margin-bottom: 28px; }
    .wf-login-header img { margin-bottom: 18px; max-width: 240px; }
    .wf-eyebrow {
      font-family: var(--wf-mono, 'Space Mono', monospace);
      font-size: 11px;
      letter-spacing: 0.2em;
      text-transform: uppercase;
      color: var(--wf-amber);
      margin-bottom: 10px;
    }
    .wf-login-header h1 {
      font-family: var(--wf-display, 'Syne', sans-serif);
      font-weight: 700;
      font-size: 24px;
      margin: 0 0 8px;
      color: var(--wf-text);
    }
    .wf-sub { font-size: 13px; color: var(--wf-text-2); margin: 0; }
    .wf-footer {
      margin-top: 28px;
      padding-top: 20px;
      border-top: 1px solid var(--wf-border);
      text-align: center;
      font-size: 10px;
      letter-spacing: 0.18em;
      color: var(--wf-text-3);
    }
  `]
})
export class AuthShellComponent implements OnInit {
  @Input({ required: true }) headline!: string;
  @Input() subline?: string | null;

  readonly displayName = computed(() => this.branding.current()?.displayName ?? 'WeldForge');
  readonly logoUrl = computed(() => {
    const v = this.brandingValue<string>('logoUrl');
    return v || 'weldforge-logo.svg';
  });
  readonly eyebrow = computed(() => {
    const v = this.brandingValue<string>('eyebrow');
    return v ?? (this.branding.current() ? null : '// secure access');
  });
  readonly hideFooter = computed(() => !!this.brandingValue<boolean>('hideFooter') || !!this.branding.current());

  constructor(public branding: TenantBrandingService, private route: ActivatedRoute) {}

  ngOnInit(): void {
    const slug = this.route.snapshot.queryParamMap.get('tenant') || this.branding.slugFromUrl();
    if (slug && (!this.branding.current() || this.branding.current()?.slug !== slug)) {
      this.branding.load(slug).subscribe();
    }
  }

  private brandingValue<T>(key: string): T | null {
    const payload = this.branding.current()?.branding as Record<string, unknown> | undefined | null;
    if (!payload) return null;
    return (payload[key] ?? null) as T | null;
  }
}
