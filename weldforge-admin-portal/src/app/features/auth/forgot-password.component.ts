import { Component, signal } from '@angular/core';
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
  selector: 'app-forgot-password',
  standalone: true,
  imports: [
    CommonModule, FormsModule, RouterLink,
    MatFormFieldModule, MatInputModule, MatButtonModule,
    AuthShellComponent,
  ],
  template: `
    <app-auth-shell headline="Reset your password"
                    subline="Enter your account email — if it's registered, we'll send a link.">
      <form *ngIf="!sent()" (ngSubmit)="submit()" class="wf-form">
        <mat-form-field appearance="outline" class="wf-field">
          <mat-label>Email</mat-label>
          <input matInput [(ngModel)]="email" name="email" required type="email" autocomplete="email">
        </mat-form-field>

        <p class="wf-error" *ngIf="error()">{{ error() }}</p>

        <button mat-raised-button color="primary" type="submit" [disabled]="loading()" class="wf-submit">
          {{ loading() ? 'Sending…' : 'Send reset link' }}
        </button>
        <div class="wf-links">
          <a [routerLink]="['/login']" [queryParams]="forwardQueryParams">Back to sign in</a>
        </div>
      </form>

      <div *ngIf="sent()" class="wf-form">
        <p class="wf-info">If that email is registered, a reset link has been sent. Check your inbox.</p>
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
export class ForgotPasswordComponent {
  email = '';
  loading = signal(false);
  error = signal<string | null>(null);
  sent = signal(false);

  forwardQueryParams: Record<string, string> = {};
  private oidcReturnTo: string | null = null;

  constructor(private auth: AuthService, route: ActivatedRoute) {
    // The tenant is identified by the page host ({slug}.sso.weldforge.org) —
    // not by a query parameter. Don't forward a tenant= param to the next
    // page; the next page reads its own host. See docs/auth-url-spec.md.
    //
    // OIDC continuation forwarded from the login page — passed to the backend
    // so the completed reset can return the user to the calling app.
    this.oidcReturnTo = route.snapshot.queryParamMap.get('oidcReturnTo');
    if (this.oidcReturnTo) this.forwardQueryParams['oidcReturnTo'] = this.oidcReturnTo;
  }

  submit(): void {
    this.error.set(null);
    this.loading.set(true);
    this.auth.forgotPassword(this.email, this.oidcReturnTo ?? undefined).pipe(
      tap(() => { this.sent.set(true); this.loading.set(false); }),
      catchError(err => {
        if (err?.status === 404) {
          this.error.set('Password recovery is not available for this organization. Please contact your administrator.');
        } else {
          this.error.set(err?.error?.message || 'Something went wrong. Please try again.');
        }
        this.loading.set(false);
        return of(null);
      })
    ).subscribe();
  }
}
