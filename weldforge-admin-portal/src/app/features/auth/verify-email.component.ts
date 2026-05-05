import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { catchError, of, tap } from 'rxjs';
import { AuthService } from '../../core/services/auth.service';
import { AuthShellComponent } from './auth-shell.component';

@Component({
  selector: 'app-verify-email',
  standalone: true,
  imports: [
    CommonModule, FormsModule, RouterLink,
    MatFormFieldModule, MatInputModule, MatButtonModule,
    AuthShellComponent,
  ],
  template: `
    <app-auth-shell headline="Verify your email"
                    [subline]="status() === 'auto' ? 'Confirming your email…' : null">
      <div *ngIf="status() === 'auto'" class="wf-form">
        <p class="wf-info">Hold on while we activate your account.</p>
      </div>

      <div *ngIf="status() === 'success'" class="wf-form">
        <p class="wf-info">Your email is verified. You can now sign in.</p>
        <a mat-raised-button color="primary" [routerLink]="['/login']" [queryParams]="forwardQueryParams" class="wf-submit">
          Continue to sign in
        </a>
      </div>

      <div *ngIf="status() === 'failed'" class="wf-form">
        <p class="wf-error">{{ error() || 'This verification link is invalid or has expired.' }}</p>
        <p class="wf-info">Enter your email below to receive a fresh verification link.</p>
        <form (ngSubmit)="resend()" class="wf-form">
          <mat-form-field appearance="outline" class="wf-field">
            <mat-label>Email</mat-label>
            <input matInput [(ngModel)]="resendEmail" name="resendEmail" required type="email" autocomplete="email">
          </mat-form-field>
          <button mat-raised-button color="primary" type="submit" [disabled]="loading()" class="wf-submit">
            {{ loading() ? 'Sending…' : 'Resend verification' }}
          </button>
        </form>
        <div class="wf-links">
          <a [routerLink]="['/login']" [queryParams]="forwardQueryParams">Back to sign in</a>
        </div>
      </div>

      <div *ngIf="status() === 'resent'" class="wf-form">
        <p class="wf-info">If that email is registered and unverified, a new verification link has been sent.</p>
        <a mat-raised-button color="primary" [routerLink]="['/login']" [queryParams]="forwardQueryParams" class="wf-submit">
          Back to sign in
        </a>
      </div>
    </app-auth-shell>
  `,
  styles: [`
    .wf-form { display: flex; flex-direction: column; gap: 4px; }
    .wf-field { width: 100%; }
    .wf-submit {
      height: 46px;
      margin-top: 12px;
      font-family: var(--wf-display, 'Syne', sans-serif) !important;
      font-weight: 700 !important;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      font-size: 13px !important;
    }
    .wf-error {
      color: #FF6B6B;
      font-size: 13px;
      margin: 4px 0 12px;
      font-family: var(--wf-mono, 'Space Mono', monospace);
    }
    .wf-info { color: var(--wf-text-2); font-size: 13px; margin-bottom: 12px; }
    .wf-links { display: flex; justify-content: center; margin-top: 14px; font-size: 12px; }
    .wf-links a { color: var(--wf-blue); text-decoration: none; }
    .wf-links a:hover { text-decoration: underline; }
  `]
})
export class VerifyEmailComponent implements OnInit {
  status = signal<'auto' | 'success' | 'failed' | 'resent'>('auto');
  loading = signal(false);
  error = signal<string | null>(null);
  resendEmail = '';

  forwardQueryParams: Record<string, string> = {};

  constructor(private auth: AuthService, private route: ActivatedRoute) {
    const slug = route.snapshot.queryParamMap.get('tenant');
    if (slug) this.forwardQueryParams = { tenant: slug };
  }

  ngOnInit(): void {
    const token = this.route.snapshot.queryParamMap.get('token');
    if (!token) {
      this.status.set('failed');
      this.error.set('This verification link is missing the token. Request a fresh one below.');
      return;
    }
    this.auth.verifyEmail(token).pipe(
      tap(() => this.status.set('success')),
      catchError(err => {
        this.status.set('failed');
        this.error.set(err?.error?.message || 'This verification link is invalid or has expired.');
        return of(null);
      })
    ).subscribe();
  }

  resend(): void {
    this.error.set(null);
    this.loading.set(true);
    this.auth.resendVerification(this.resendEmail).pipe(
      tap(() => { this.status.set('resent'); this.loading.set(false); }),
      catchError(() => {
        this.loading.set(false);
        this.status.set('resent'); // Still show generic message to avoid enumeration.
        return of(null);
      })
    ).subscribe();
  }
}
