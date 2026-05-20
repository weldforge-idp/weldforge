import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { catchError, of, tap } from 'rxjs';
import { AuthService } from '../../core/services/auth.service';
import { AuthShellComponent } from './auth-shell.component';

@Component({
  selector: 'app-reset-password',
  standalone: true,
  imports: [
    CommonModule, FormsModule, RouterLink,
    MatFormFieldModule, MatInputModule, MatButtonModule,
    AuthShellComponent,
  ],
  template: `
    <app-auth-shell headline="Set a new password"
                    subline="Enter and confirm your new password.">
      <form *ngIf="!done()" (ngSubmit)="submit()" class="wf-form">
        <mat-form-field appearance="outline" class="wf-field">
          <mat-label>New password</mat-label>
          <input matInput [(ngModel)]="newPassword" name="newPassword" required type="password" autocomplete="new-password">
        </mat-form-field>

        <mat-form-field appearance="outline" class="wf-field">
          <mat-label>Confirm new password</mat-label>
          <input matInput [(ngModel)]="confirm" name="confirm" required type="password" autocomplete="new-password">
        </mat-form-field>

        <p class="wf-error" *ngIf="error()">{{ error() }}</p>

        <button mat-raised-button color="primary" type="submit"
                [disabled]="loading() || !token" class="wf-submit">
          {{ loading() ? 'Saving…' : 'Save password' }}
        </button>
        <div class="wf-links">
          <a [routerLink]="['/login']" [queryParams]="forwardQueryParams">Back to sign in</a>
        </div>
      </form>

      <div *ngIf="done()" class="wf-form">
        <p class="wf-info">
          {{ redirecting()
              ? 'Your password has been reset. Returning you to sign in…'
              : 'Your password has been reset. You can now sign in with the new password.' }}
        </p>
        <a mat-raised-button color="primary" [routerLink]="['/login']" [queryParams]="forwardQueryParams" class="wf-submit">
          Continue to sign in
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
      font-size: 12px;
      margin: 4px 0 8px;
      font-family: var(--wf-mono, 'Space Mono', monospace);
    }
    .wf-info { color: var(--wf-text-2); font-size: 13px; margin-bottom: 16px; }
    .wf-links { display: flex; justify-content: center; margin-top: 14px; font-size: 12px; }
    .wf-links a { color: var(--wf-blue); text-decoration: none; }
    .wf-links a:hover { text-decoration: underline; }
  `]
})
export class ResetPasswordComponent {
  newPassword = '';
  confirm = '';
  loading = signal(false);
  error = signal<string | null>(null);
  done = signal(false);
  redirecting = signal(false);
  token: string | null = null;

  forwardQueryParams: Record<string, string> = {};

  constructor(private auth: AuthService, private router: Router, route: ActivatedRoute) {
    this.token = route.snapshot.queryParamMap.get('token');
    if (!this.token) {
      this.error.set('This reset link is missing or invalid. Request a new one from the sign-in page.');
    }
    // Tenant is identified by the page host ({slug}.sso.weldforge.org).
    // No tenant query param to forward.
  }

  submit(): void {
    if (!this.token) return;
    if (this.newPassword !== this.confirm) {
      this.error.set('Passwords do not match.');
      return;
    }
    this.error.set(null);
    this.loading.set(true);
    this.auth.resetPassword(this.token, this.newPassword).pipe(
      tap(res => {
        this.loading.set(false);
        this.done.set(true);
        // Reset began inside an app flow — return the user to the sign-in
        // screen carrying the original OIDC continuation, so they sign in
        // with the new password and land back in the calling app.
        if (res.returnTo) {
          this.forwardQueryParams = { ...this.forwardQueryParams, oidcReturnTo: res.returnTo };
          this.redirecting.set(true);
          setTimeout(() => this.router.navigate(['/login'], { queryParams: this.forwardQueryParams }), 1800);
        }
      }),
      catchError(err => {
        this.error.set(err?.error?.message || 'Could not reset your password. The link may be expired.');
        this.loading.set(false);
        return of(null);
      })
    ).subscribe();
  }
}
