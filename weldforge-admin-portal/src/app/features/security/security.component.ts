import { Component, OnInit, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatDividerModule } from '@angular/material/divider';
import { MatChipsModule } from '@angular/material/chips';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { create as webauthnCreate, supported as webauthnSupported } from '@github/webauthn-json';
import { MfaFactor, MfaService, TotpEnrollResponse } from '../../core/services/mfa.service';

type TotpStep = 'idle' | 'scan' | 'verify';

@Component({
  selector: 'app-security',
  standalone: true,
  imports: [
    CommonModule, FormsModule,
    MatCardModule, MatButtonModule, MatIconModule,
    MatFormFieldModule, MatInputModule, MatDividerModule,
    MatChipsModule, MatSnackBarModule,
  ],
  template: `
    <div class="wf-page">
      <header class="wf-page-header">
        <div>
          <div class="eyebrow mono">// account security</div>
          <h1>Two-factor authentication</h1>
          <p class="sub">Strong factors protect your account even if your password is compromised. Enroll an authenticator app or security key, and keep backup codes somewhere safe.</p>
        </div>
      </header>

      <!-- Empty state -->
      <mat-card class="wf-card empty" *ngIf="factors().length === 0 && totpStep() === 'idle'">
        <mat-icon class="empty-icon">shield</mat-icon>
        <h3>No second factor yet</h3>
        <p>Your account is protected by password only. Add a factor below to harden it.</p>
      </mat-card>

      <!-- Factor list -->
      <mat-card class="wf-card" *ngIf="factors().length > 0">
        <h3 class="section-title">Enrolled factors</h3>
        <ul class="factor-list">
          <li *ngFor="let f of factors()" class="factor-row">
            <mat-icon class="factor-icon">{{ f.type === 'TOTP' ? 'qr_code_2' : 'key' }}</mat-icon>
            <div class="factor-body">
              <div class="factor-name">{{ f.label || (f.type === 'TOTP' ? 'Authenticator app' : 'Security key') }}</div>
              <div class="factor-meta mono">
                {{ f.type }} ·
                <span [class.active]="f.verified" [class.pending]="!f.verified">
                  {{ f.verified ? 'active' : 'pending activation' }}
                </span>
                <ng-container *ngIf="f.lastUsedAt"> · last used {{ f.lastUsedAt | date:'short' }}</ng-container>
              </div>
            </div>
            <button mat-icon-button color="warn" (click)="removeFactor(f)" aria-label="Remove factor">
              <mat-icon>delete</mat-icon>
            </button>
          </li>
        </ul>
      </mat-card>

      <!-- TOTP enrollment wizard -->
      <mat-card class="wf-card" *ngIf="totpStep() !== 'idle'">
        <h3 class="section-title">Add authenticator app</h3>

        <ng-container *ngIf="totpStep() === 'scan' && totpEnroll()">
          <ol class="steps">
            <li>Open your authenticator app (Google Authenticator, 1Password, Authy, …)</li>
            <li>Scan the QR code below — or enter the secret manually.</li>
            <li>Type the first 6-digit code it generates.</li>
          </ol>
          <div class="qr-row">
            <img [src]="totpEnroll()!.qrDataUri" alt="TOTP QR code" class="qr-img">
            <div class="secret">
              <div class="label mono">manual setup key</div>
              <code class="secret-code">{{ totpEnroll()!.secret }}</code>
              <button mat-button (click)="copy(totpEnroll()!.secret)">Copy</button>
            </div>
          </div>
          <div class="wf-actions">
            <button mat-button (click)="cancelTotp()">Cancel</button>
            <button mat-raised-button color="primary" (click)="advanceToVerify()">Next</button>
          </div>
        </ng-container>

        <ng-container *ngIf="totpStep() === 'verify'">
          <p class="sub">Enter the 6-digit code from your authenticator app to activate this factor.</p>
          <mat-form-field appearance="outline" class="otp-field">
            <mat-label>Code</mat-label>
            <input matInput [(ngModel)]="otp" name="otp" maxlength="6" inputmode="numeric"
                   autocomplete="one-time-code" autofocus>
          </mat-form-field>
          <p class="wf-error" *ngIf="activateError()">{{ activateError() }}</p>
          <div class="wf-actions">
            <button mat-button (click)="cancelTotp()">Cancel</button>
            <button mat-raised-button color="primary" [disabled]="otp.length < 6" (click)="activateTotp()">Activate</button>
          </div>
        </ng-container>
      </mat-card>

      <!-- Add factor buttons -->
      <div class="add-factors" *ngIf="totpStep() === 'idle'">
        <button mat-raised-button color="accent" (click)="startTotp()">
          <mat-icon>qr_code_2</mat-icon> Add authenticator app
        </button>
        <button mat-stroked-button color="primary"
                [disabled]="webauthnBusy() || !webauthnAvailable()"
                (click)="addSecurityKey()"
                [title]="webauthnAvailable() ? 'Add a passkey or hardware security key' : 'WebAuthn is not supported by this browser'">
          <mat-icon>key</mat-icon>
          {{ webauthnBusy() ? 'Waiting for authenticator…' : 'Add security key / passkey' }}
        </button>
      </div>

      <!-- Backup codes -->
      <mat-card class="wf-card">
        <h3 class="section-title">Backup codes</h3>
        <p class="sub">
          One-time codes you can use if you lose access to your other factor.
          <strong>{{ backupRemaining() }}</strong> unused.
        </p>

        <div class="backup-grid mono" *ngIf="freshBackupCodes().length > 0">
          <div *ngFor="let c of freshBackupCodes()" class="backup-code">{{ c }}</div>
        </div>
        <p class="wf-warning" *ngIf="freshBackupCodes().length > 0">
          <mat-icon>warning</mat-icon>
          Save these somewhere safe — they <strong>will not be shown again</strong>.
        </p>

        <div class="wf-actions">
          <button mat-stroked-button color="primary" (click)="regenerateBackupCodes()">
            <mat-icon>refresh</mat-icon> Regenerate backup codes
          </button>
          <button mat-button *ngIf="freshBackupCodes().length > 0" (click)="copy(freshBackupCodes().join('\\n'))">
            <mat-icon>content_copy</mat-icon> Copy all
          </button>
        </div>
      </mat-card>

      <!-- Reset all MFA -->
      <mat-card class="wf-card wf-danger" *ngIf="factors().length > 0">
        <h3 class="section-title">Reset all two-factor authentication</h3>
        <p class="sub">
          Removes every enrolled factor and backup code from this account. You'll need to re-enroll on your next login.
          For your protection, you must re-enter your password to confirm.
        </p>
        <div class="reset-row">
          <mat-form-field appearance="outline" class="pwd-field">
            <mat-label>Current password</mat-label>
            <input matInput type="password" [(ngModel)]="resetPassword" name="resetPassword"
                   autocomplete="current-password">
          </mat-form-field>
          <button mat-raised-button color="warn" [disabled]="!resetPassword" (click)="confirmSelfReset()">
            Reset MFA
          </button>
        </div>
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
    .sub { color: var(--wf-text-2); font-size: 13px; margin: 0; max-width: 640px; }

    .wf-card { padding: 24px; margin-bottom: 16px; }
    .section-title { font-family: 'Syne', sans-serif; margin: 0 0 12px; font-size: 16px; }

    .wf-card.empty { text-align: center; padding: 48px 24px; }
    .empty-icon {
      font-size: 48px;
      width: 48px;
      height: 48px;
      color: var(--wf-text-3);
      margin-bottom: 12px;
    }
    .empty h3 { font-family: 'Syne', sans-serif; margin: 0 0 6px; }

    .factor-list { list-style: none; padding: 0; margin: 0; }
    .factor-row {
      display: flex;
      align-items: center;
      gap: 14px;
      padding: 14px 0;
      border-bottom: 1px solid var(--wf-border);
    }
    .factor-row:last-child { border-bottom: none; }
    .factor-icon { color: var(--wf-blue); }
    .factor-body { flex: 1 1 auto; }
    .factor-name { font-family: 'Syne', sans-serif; font-size: 14px; }
    .factor-meta {
      font-size: 11px;
      color: var(--wf-text-3);
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }
    .factor-meta .active { color: var(--wf-blue); }
    .factor-meta .pending { color: var(--wf-amber); }

    .steps {
      font-size: 13px;
      color: var(--wf-text-2);
      padding-left: 20px;
      margin: 0 0 16px;
    }
    .qr-row {
      display: flex;
      gap: 20px;
      align-items: flex-start;
      padding: 16px;
      background: var(--wf-bg);
      border: 1px solid var(--wf-border);
      border-radius: 3px;
      margin-bottom: 16px;
    }
    .qr-img {
      width: 180px;
      height: 180px;
      background: #fff;
      padding: 8px;
      border-radius: 2px;
    }
    .secret { flex: 1 1 auto; min-width: 0; }
    .secret .label {
      font-size: 10px;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: var(--wf-text-3);
      margin-bottom: 6px;
    }
    .secret-code {
      display: block;
      font-family: 'Space Mono', monospace;
      font-size: 13px;
      word-break: break-all;
      background: var(--wf-bg-3);
      padding: 10px 12px;
      border-radius: 3px;
      border: 1px solid var(--wf-border);
      margin-bottom: 8px;
      color: var(--wf-text);
    }

    .otp-field { width: 160px; }
    .wf-actions {
      display: flex;
      gap: 8px;
      margin-top: 8px;
      justify-content: flex-end;
    }
    .wf-error { color: #FF6B6B; font-size: 12px; font-family: 'Space Mono', monospace; }

    .add-factors {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 24px;
    }

    .backup-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
      gap: 8px;
      margin: 16px 0;
    }
    .backup-code {
      background: var(--wf-bg-3);
      padding: 10px 14px;
      border: 1px solid var(--wf-border);
      border-radius: 3px;
      text-align: center;
      font-size: 13px;
      letter-spacing: 0.05em;
    }
    .wf-warning {
      display: flex;
      align-items: center;
      gap: 8px;
      background: rgba(232, 146, 31, 0.08);
      border: 1px solid var(--wf-amber-dim);
      border-radius: 3px;
      padding: 10px 14px;
      font-size: 13px;
      color: var(--wf-text);
      margin: 0 0 12px;
    }
    .wf-warning mat-icon { color: var(--wf-amber); }

    .wf-danger {
      border: 1px solid rgba(255, 107, 107, 0.3);
    }
    .wf-danger .section-title { color: #FF8A8A; }
    .reset-row { display: flex; gap: 12px; align-items: flex-start; }
    .pwd-field { flex: 1 1 auto; }

    .mono { font-family: 'Space Mono', monospace; }
  `]
})
export class SecurityComponent implements OnInit {
  factors = signal<MfaFactor[]>([]);
  backupRemaining = signal<number>(0);
  freshBackupCodes = signal<string[]>([]);
  totpStep = signal<TotpStep>('idle');
  totpEnroll = signal<TotpEnrollResponse | null>(null);
  activateError = signal<string | null>(null);

  webauthnBusy = signal(false);
  webauthnAvailable = signal<boolean>(typeof window !== 'undefined' && webauthnSupported());

  otp = '';
  resetPassword = '';

  constructor(private mfa: MfaService, private snack: MatSnackBar) {}

  ngOnInit() { this.refresh(); }

  refresh() {
    this.mfa.listFactors().subscribe({
      next: fs => this.factors.set(fs),
      error: e => this.err('Failed to load factors', e),
    });
    this.mfa.backupCodeStatus().subscribe({
      next: s => this.backupRemaining.set(s.remaining),
      error: () => {},
    });
  }

  // TOTP wizard ----------------------------------------------------

  startTotp() {
    this.activateError.set(null);
    this.mfa.enrollTotp('Authenticator app').subscribe({
      next: res => {
        this.totpEnroll.set(res);
        this.totpStep.set('scan');
      },
      error: e => this.err('Failed to start TOTP enrollment', e),
    });
  }

  advanceToVerify() {
    this.otp = '';
    this.activateError.set(null);
    this.totpStep.set('verify');
  }

  activateTotp() {
    const enroll = this.totpEnroll();
    if (!enroll) return;
    this.mfa.activateTotp(enroll.factorId, this.otp).subscribe({
      next: () => {
        this.ok('Authenticator activated');
        this.cancelTotp();
        this.refresh();
        // Offer to generate backup codes right after activation if none exist.
        if (this.backupRemaining() === 0) {
          this.snack.open('Tip: generate backup codes in case you lose your device.', 'OK', { duration: 6000 });
        }
      },
      error: () => {
        this.activateError.set('Incorrect code — try again');
      },
    });
  }

  cancelTotp() {
    // If the user cancels an unverified TOTP enrollment, remove the pending row.
    const enroll = this.totpEnroll();
    if (enroll && this.totpStep() !== 'idle') {
      const pending = this.factors().find(f => f.id === enroll.factorId && !f.verified);
      if (pending) {
        this.mfa.deleteFactor(enroll.factorId).subscribe({ next: () => this.refresh() });
      }
    }
    this.totpStep.set('idle');
    this.totpEnroll.set(null);
    this.otp = '';
    this.activateError.set(null);
  }

  // WebAuthn -------------------------------------------------------

  /**
   * Drives the full WebAuthn registration ceremony:
   *  1. Ask the backend to mint a fresh challenge + creation options
   *  2. Hand them to the browser via navigator.credentials.create()
   *  3. POST the resulting credential back so the server can persist it
   *
   * The @github/webauthn-json helpers handle the base64url <-> ArrayBuffer
   * dance on both sides — the server already speaks the same wire format
   * via the Yubico library, so the strings line up.
   */
  addSecurityKey() {
    if (!this.webauthnAvailable()) {
      this.err('Your browser does not support WebAuthn', null);
      return;
    }
    const label = window.prompt('Name this security key (e.g. "YubiKey 5C", "iPhone passkey")', 'Security key');
    if (label === null) return; // user cancelled the prompt
    this.webauthnBusy.set(true);

    this.mfa.startWebauthnRegistration(label).subscribe({
      next: async ({ ceremonyKey, publicKey }) => {
        try {
          const options = JSON.parse(publicKey);
          // The Yubico library serialises options under { publicKey: {...} }
          // when calling toCredentialsCreateJson(); the helper expects that
          // shape, but tolerates a flat options object too.
          const wrapped = options.publicKey ? options : { publicKey: options };
          const credential = await webauthnCreate(wrapped);
          this.mfa.finishWebauthnRegistration(ceremonyKey, JSON.stringify(credential), label).subscribe({
            next: () => {
              this.ok('Security key added');
              this.webauthnBusy.set(false);
              this.refresh();
            },
            error: e => {
              this.webauthnBusy.set(false);
              this.err('Server rejected the credential', e);
            },
          });
        } catch (e: any) {
          this.webauthnBusy.set(false);
          // The browser raises NotAllowedError when the user cancels —
          // treat it as a quiet exit, not a failure.
          if (e?.name === 'NotAllowedError') {
            this.snack.open('Cancelled', 'OK', { duration: 2000 });
          } else {
            this.err('WebAuthn ceremony failed', e);
          }
        }
      },
      error: e => {
        this.webauthnBusy.set(false);
        this.err('Failed to start WebAuthn registration', e);
      },
    });
  }

  // Factor list ----------------------------------------------------

  removeFactor(f: MfaFactor) {
    if (!confirm(`Remove "${f.label}"? You'll need to re-enroll if you want this factor back.`)) return;
    this.mfa.deleteFactor(f.id).subscribe({
      next: () => {
        this.ok('Factor removed');
        this.refresh();
      },
      error: e => this.err('Failed to remove factor', e),
    });
  }

  // Backup codes ---------------------------------------------------

  regenerateBackupCodes() {
    if (this.backupRemaining() > 0 &&
        !confirm('Regenerating will invalidate any unused backup codes. Continue?')) return;
    this.mfa.regenerateBackupCodes().subscribe({
      next: res => {
        this.freshBackupCodes.set(res.codes);
        this.backupRemaining.set(res.remaining);
        this.ok('New backup codes generated');
      },
      error: e => this.err('Failed to regenerate codes', e),
    });
  }

  // Self-reset -----------------------------------------------------

  confirmSelfReset() {
    if (!confirm('Remove every MFA factor and backup code from your account? You will need to re-enroll on next login.')) return;
    this.mfa.selfReset(this.resetPassword).subscribe({
      next: res => {
        this.ok(`Removed ${res.removed} factor${res.removed === 1 ? '' : 's'}`);
        this.resetPassword = '';
        this.freshBackupCodes.set([]);
        this.refresh();
      },
      error: e => {
        if (e?.status === 401) this.err('Password re-verification failed', e);
        else this.err('Reset failed', e);
      },
    });
  }

  // Utilities ------------------------------------------------------

  copy(text: string) {
    navigator.clipboard.writeText(text).then(
      () => this.ok('Copied'),
      () => this.err('Copy failed', null),
    );
  }

  private ok(msg: string) { this.snack.open(msg, 'OK', { duration: 3000 }); }
  private err(msg: string, e: any) {
    console.error(msg, e);
    this.snack.open(`${msg}${e?.error?.message ? ': ' + e.error.message : ''}`, 'Dismiss', { duration: 5000 });
  }
}
