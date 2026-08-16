import { Component, OnInit, computed, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { AuthService, MfaFactorType } from '../../core/services/auth.service';
import { TenantBrandingService } from '../../core/services/tenant-branding.service';
import { catchError, tap } from 'rxjs/operators';
import { of } from 'rxjs';
import { forwardOidcParams, resolvePostAuthTarget } from '../../core/oidc-continuation';

type Step = 'credentials' | 'mfa';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [
    CommonModule, FormsModule, RouterLink,
    MatCardModule, MatFormFieldModule, MatInputModule,
    MatButtonModule, MatProgressSpinnerModule
  ],
  template: `
    <div class="wf-login-shell">
      <div class="wf-login-card">
        <div class="wf-login-header">
          <img *ngIf="logoUrl() as logo" [src]="logo" [alt]="displayName()" height="44">
          <div class="wf-wordmark" *ngIf="!logoUrl()">{{ wordmark() }}</div>
          <div class="wf-eyebrow" *ngIf="eyebrow()">{{ eyebrow() }}</div>
          <h1>{{ headline() }}</h1>
          <p class="wf-sub" *ngIf="step() === 'credentials'">{{ tagline() }}</p>
          <p class="wf-sub" *ngIf="step() === 'mfa'">Enter the 6-digit code from your authenticator app, or a backup code.</p>
        </div>

        <!-- Step 1: credentials -->
        <form *ngIf="step() === 'credentials'" (ngSubmit)="submitCredentials()" class="wf-form">
          <mat-form-field appearance="outline" class="wf-field">
            <mat-label>Email</mat-label>
            <input matInput [(ngModel)]="identifier" name="identifier" required type="email" autocomplete="username">
          </mat-form-field>

          <mat-form-field appearance="outline" class="wf-field">
            <mat-label>Password</mat-label>
            <input matInput [(ngModel)]="password" name="password" required type="password" autocomplete="current-password">
          </mat-form-field>

          <p class="wf-error" *ngIf="error()">{{ error() }}</p>

          <button mat-raised-button color="primary" type="submit" [disabled]="loading()" class="wf-submit">
            {{ loading() ? 'Authenticating…' : ctaLabel() }}
          </button>

          <div class="wf-links" *ngIf="passwordRecoveryEnabled() || registrationEnabled()">
            <a *ngIf="passwordRecoveryEnabled()"
               [routerLink]="['/forgot-password']" [queryParams]="forwardQueryParams()">
              Forgot your password?
            </a>
            <a *ngIf="registrationEnabled()"
               [routerLink]="['/register']" [queryParams]="forwardQueryParams()">
              Create an account
            </a>
          </div>
        </form>

        <!-- Step 2: MFA -->
        <form *ngIf="step() === 'mfa'" (ngSubmit)="submitMfa()" class="wf-form">
          <mat-form-field appearance="outline" class="wf-field" *ngIf="!useBackup()">
            <mat-label>Authenticator code</mat-label>
            <input matInput [(ngModel)]="otp" name="otp" maxlength="6" inputmode="numeric"
                   autocomplete="one-time-code" required autofocus>
          </mat-form-field>

          <mat-form-field appearance="outline" class="wf-field" *ngIf="useBackup()">
            <mat-label>Backup code</mat-label>
            <input matInput [(ngModel)]="backupCode" name="backupCode" required autofocus>
          </mat-form-field>

          <p class="wf-error" *ngIf="error()">{{ error() }}</p>

          <button mat-raised-button color="primary" type="submit" [disabled]="loading()" class="wf-submit">
            {{ loading() ? 'Verifying…' : 'Verify' }}
          </button>

          <div class="wf-alt">
            <button mat-button type="button" (click)="toggleBackup()">
              {{ useBackup() ? 'Use authenticator code' : 'Use a backup code instead' }}
            </button>
            <button mat-button type="button" (click)="reset()">Cancel</button>
          </div>
        </form>

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
    .wf-wordmark {
      margin-bottom: 18px;
      font-family: var(--wf-display, 'Syne', sans-serif);
      font-weight: 700;
      font-size: 26px;
      letter-spacing: 0.01em;
      color: var(--wf-text);
    }
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
    .wf-form { display: flex; flex-direction: column; gap: 4px; }
    .wf-field { width: 100%; }
    .wf-error {
      color: #FF6B6B;
      font-size: 12px;
      margin: 4px 0 8px;
      font-family: var(--wf-mono, 'Space Mono', monospace);
    }
    .wf-submit {
      height: 46px;
      margin-top: 12px;
      font-family: var(--wf-display, 'Syne', sans-serif) !important;
      font-weight: 700 !important;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      font-size: 13px !important;
    }
    .wf-links {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      margin-top: 14px;
      font-size: 12px;
    }
    .wf-links a {
      color: var(--wf-blue);
      text-decoration: none;
    }
    .wf-links a:hover { text-decoration: underline; }
    .wf-alt {
      display: flex;
      justify-content: space-between;
      margin-top: 8px;
    }
    .wf-footer {
      margin-top: 28px;
      padding-top: 20px;
      border-top: 1px solid var(--wf-border);
      text-align: center;
      font-size: 10px;
      letter-spacing: 0.18em;
      color: var(--wf-text-3);
    }
    /* Light tenant theme — drop the dark-tuned amber glow and heavy shadow. */
    :host-context(body.wf-light) .wf-login-shell::after { display: none; }
    :host-context(body.wf-light) .wf-login-card {
      box-shadow: 0 8px 30px rgba(17, 24, 39, 0.10);
    }
  `]
})
export class LoginComponent implements OnInit {
  identifier = '';
  password = '';
  otp = '';
  backupCode = '';

  step = signal<Step>('credentials');
  loading = signal(false);
  error = signal<string | null>(null);
  useBackup = signal(false);

  private challengeToken: string | null = null;
  private factors: MfaFactorType[] = [];

  // Branding-derived UI
  readonly displayName = computed(() => this.branding.current()?.displayName ?? 'WeldForge');
  readonly logoUrl = computed(() => {
    const url = this.brandingValue<string>('logoUrl');
    if (url) return url;
    // A branded tenant with no logo image gets a text wordmark, not the
    // WeldForge shield; only the unbranded default falls back to the shield.
    return this.branding.current() ? null : 'weldforge-logo.svg';
  });
  readonly wordmark = computed(() =>
    this.brandingValue<string>('wordmark') ?? this.displayName());
  readonly eyebrow = computed(() => {
    const v = this.brandingValue<string>('eyebrow');
    return v ?? (this.branding.current() ? null : '// secure access');
  });
  readonly tagline = computed(() => {
    const v = this.brandingValue<string>('tagline');
    return v ?? 'Federated identity, forged into one trusted layer.';
  });
  readonly ctaLabel = computed(() => {
    const v = this.brandingValue<string>('ctaLabel');
    return v ?? 'Enter the Forge';
  });
  readonly headline = computed(() => {
    if (this.step() === 'mfa') return 'Verify it\'s you';
    const v = this.brandingValue<string>('headline');
    return v ?? `Sign in to ${this.displayName()}`;
  });
  readonly hideFooter = computed(() => !!this.brandingValue<boolean>('hideFooter') || !!this.branding.current());
  readonly registrationEnabled = computed(() => {
    const b = this.branding.current();
    return b ? !!b.registrationEnabled : true;
  });
  readonly passwordRecoveryEnabled = computed(() => {
    const b = this.branding.current();
    return b ? !!b.passwordRecoveryEnabled : true;
  });

  constructor(private authService: AuthService,
              public branding: TenantBrandingService,
              private router: Router,
              private route: ActivatedRoute) {}

  ngOnInit(): void {
    const slug = this.branding.slugFromHost();
    if (slug) {
      this.branding.load(slug).subscribe();
    }
  }

  forwardQueryParams(): Record<string, string> {
    // Tenant identified by the page host — no tenant query param to forward.
    // Carry only the OIDC continuation through to forgot/reset-password and register, so a
    // password reset or a sign-up can return the user to the calling app.
    return forwardOidcParams(this.route.snapshot.queryParams);
  }

  private brandingValue<T>(key: string): T | null {
    const payload = this.branding.current()?.branding as Record<string, unknown> | undefined | null;
    if (!payload) return null;
    const v = payload[key];
    return (v ?? null) as T | null;
  }

  submitCredentials() {
    this.error.set(null);
    this.loading.set(true);
    this.authService.login({ identifier: this.identifier, password: this.password }).pipe(
      tap(res => {
        if (res.mfaRequired) {
          this.challengeToken = res.mfaChallengeToken ?? null;
          this.factors = res.availableFactors ?? [];
          this.step.set('mfa');
          this.loading.set(false);
        } else if (res.token) {
          this.goToApp();
        }
      }),
      catchError(err => {
        console.error(err);
        this.error.set(err?.error?.message || 'Invalid credentials');
        this.loading.set(false);
        return of(null);
      })
    ).subscribe();
  }

  submitMfa() {
    if (!this.challengeToken) { this.reset(); return; }
    this.error.set(null);
    this.loading.set(true);
    const body: any = {
      challengeToken: this.challengeToken,
      type: 'TOTP' as MfaFactorType,
    };
    if (this.useBackup()) body.backupCode = this.backupCode;
    else body.code = this.otp;

    this.authService.verifyMfa(body).pipe(
      tap(res => {
        if (res.token) { this.goToApp(); }
      }),
      catchError(err => {
        console.error(err);
        this.error.set('Incorrect code, try again');
        this.loading.set(false);
        return of(null);
      })
    ).subscribe();
  }

  toggleBackup() {
    this.useBackup.update(v => !v);
    this.otp = '';
    this.backupCode = '';
    this.error.set(null);
  }

  reset() {
    this.step.set('credentials');
    this.challengeToken = null;
    this.factors = [];
    this.otp = '';
    this.backupCode = '';
    this.useBackup.set(false);
    this.password = '';
    this.loading.set(false);
    this.error.set(null);
  }

  /**
   * Hand the freshly-authenticated browser back to the calling application, or to the portal.
   *
   * <p>This previously did `window.location.href = atob(oidcReturnTo)` with no validation.
   * `oidcReturnTo` is a query parameter, so it is attacker-supplied: sending a victim to
   * `https://{slug}.sso.weldforge.org/login/?oidcReturnTo=<base64 of https://evil.example>`
   * redirected them there the instant they signed in. An open redirect on an identity
   * provider is worth more than on an ordinary site, because the victim has just been taught
   * to trust the page that bounced them.
   *
   * <p>The decision now lives in {@link resolvePostAuthTarget}, which validates both the
   * off-origin continuation and the in-app `returnUrl`, and is unit-tested.
   */
  private goToApp() {
    const target = resolvePostAuthTarget(this.route.snapshot.queryParams);
    if (target.kind === 'external') {
      window.location.href = target.url;
      return;
    }
    this.router.navigate([target.route]);
  }
}
