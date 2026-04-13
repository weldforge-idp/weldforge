import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService, MfaFactorType } from '../../core/services/auth.service';
import { catchError, tap } from 'rxjs/operators';
import { of } from 'rxjs';

type Step = 'credentials' | 'mfa';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [
    CommonModule, FormsModule,
    MatCardModule, MatFormFieldModule, MatInputModule,
    MatButtonModule, MatProgressSpinnerModule
  ],
  template: `
    <div class="wf-login-shell">
      <div class="wf-login-card">
        <div class="wf-login-header">
          <img src="weldforge-logo.svg" alt="WeldForge" height="44">
          <div class="wf-eyebrow">// secure access</div>
          <h1>{{ step() === 'credentials' ? 'Sign in to WeldForge' : 'Verify it\\'s you' }}</h1>
          <p class="wf-sub" *ngIf="step() === 'credentials'">Federated identity, forged into one trusted layer.</p>
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
            {{ loading() ? 'Authenticating…' : 'Enter the Forge' }}
          </button>
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

        <div class="wf-footer mono">
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
      background: radial-gradient(ellipse at 50% 40%, rgba(232, 146, 31, 0.08) 0%, transparent 55%);
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
    .wf-login-header img { margin-bottom: 18px; }
    .wf-eyebrow {
      font-family: 'Space Mono', monospace;
      font-size: 11px;
      letter-spacing: 0.2em;
      text-transform: uppercase;
      color: var(--wf-amber);
      margin-bottom: 10px;
    }
    .wf-login-header h1 {
      font-family: 'Syne', sans-serif;
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
      font-family: 'Space Mono', monospace;
    }
    .wf-submit {
      height: 46px;
      margin-top: 12px;
      font-family: 'Syne', sans-serif !important;
      font-weight: 700 !important;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      font-size: 13px !important;
    }
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
  `]
})
export class LoginComponent {
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

  constructor(private authService: AuthService,
              private router: Router,
              private route: ActivatedRoute) {}

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

  private goToApp() {
    // OIDC redirect flow: when /authorize bounces an unauthenticated
    // caller to /login, it passes the original /authorize URL as
    // base64url-encoded "oidcReturnTo". After a successful login we
    // navigate the browser back to that absolute URL so the consent
    // screen can render against the now-authenticated session (the
    // wf_session cookie set by the backend on login carries it).
    const oidcReturnTo = this.route.snapshot.queryParams['oidcReturnTo'];
    if (oidcReturnTo) {
      try {
        const decoded = atob(oidcReturnTo.replace(/-/g, '+').replace(/_/g, '/'));
        // Hard navigation, not router.navigate — the target URL is
        // outside the Angular app's route tree.
        window.location.href = decoded;
        return;
      } catch (e) {
        console.error('Invalid oidcReturnTo, falling back to /tenants', e);
      }
    }
    const returnUrl = this.route.snapshot.queryParams['returnUrl'] || '/tenants';
    this.router.navigate([returnUrl]);
  }
}
