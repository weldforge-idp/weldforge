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
import { forwardOidcParams, readOidcReturnTo, safeOidcReturnUrl } from '../../core/oidc-continuation';
import { ExternalNavigator } from '../../core/external-navigator';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [
    CommonModule, FormsModule, RouterLink,
    MatFormFieldModule, MatInputModule, MatButtonModule,
    AuthShellComponent,
  ],
  template: `
    <app-auth-shell headline="Create your account"
                    subline="Sign up to get started.">
      <form *ngIf="!disabled()" (ngSubmit)="submit()" class="wf-form">
        <mat-form-field appearance="outline" class="wf-field">
          <mat-label>Name</mat-label>
          <input matInput [(ngModel)]="name" name="name" required autocomplete="name">
        </mat-form-field>

        <mat-form-field appearance="outline" class="wf-field">
          <mat-label>Email</mat-label>
          <input matInput [(ngModel)]="email" name="email" required type="email" autocomplete="email">
        </mat-form-field>

        <mat-form-field appearance="outline" class="wf-field">
          <mat-label>Password</mat-label>
          <input matInput [(ngModel)]="password" name="password" required type="password" autocomplete="new-password">
        </mat-form-field>

        <p class="wf-error" *ngIf="error()">{{ error() }}</p>

        <button mat-raised-button color="primary" type="submit" [disabled]="loading()" class="wf-submit">
          {{ loading() ? 'Creating account…' : 'Create account' }}
        </button>
        <div class="wf-links">
          <a [routerLink]="['/login']" [queryParams]="forwardQueryParams">Back to sign in</a>
        </div>
      </form>

      <div *ngIf="disabled()" class="wf-form">
        <p class="wf-info">Self-registration is not available for this organization. Please contact your administrator to request an account.</p>
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
export class RegisterComponent {
  name = '';
  email = '';
  password = '';
  loading = signal(false);
  error = signal<string | null>(null);
  disabled = signal(false);

  forwardQueryParams: Record<string, string> = {};

  constructor(private auth: AuthService, private router: Router, private route: ActivatedRoute,
              private externalNav: ExternalNavigator) {
    // Tenant is identified by the page host ({slug}.sso.weldforge.org).
    // No tenant query param to forward to /login. See docs/auth-url-spec.md.
    //
    // The OIDC continuation, however, MUST be forwarded. A user who lands here from a calling
    // application's sign-in (Intelli-Accounting, say) arrives with ?oidcReturnTo=<authorize URL>.
    // This was previously left as {} and never populated, so both "Back to sign in" and the
    // post-registration redirect dropped it — the user was registered successfully and then
    // stranded in the portal's tenant list, and the calling app never saw them again.
    this.forwardQueryParams = forwardOidcParams(this.route.snapshot.queryParams);
  }

  submit(): void {
    this.error.set(null);
    this.loading.set(true);
    this.auth.register({ name: this.name, email: this.email, password: this.password }).pipe(
      tap(res => {
        this.loading.set(false);
        if (res?.token) {
          // Registered AND authenticated — resume the OIDC flow so the calling application
          // completes its own sign-up. For Intelli-Accounting that is spec §9: WeldForge owns
          // step 1 (login details), and steps 2-3 (company details, chart of accounts) happen
          // back in the app once the callback lands.
          this.goToApp();
        } else {
          // Successful response without token (eg. needs MFA enrollment / email verification).
          // Send them to sign-in still carrying the continuation, so the flow survives.
          this.router.navigate(['/login'], { queryParams: this.forwardQueryParams });
        }
      }),
      catchError(err => {
        this.loading.set(false);
        if (err?.status === 404) {
          this.disabled.set(true);
        } else {
          this.error.set(err?.error?.message || 'Could not create your account. Please try again.');
        }
        return of(null);
      })
    ).subscribe();
  }

  /**
   * Hand the freshly-authenticated browser back to the calling application, or fall back to
   * the portal when this was a standalone registration.
   *
   * <p>The continuation is attacker-supplied (it is a query parameter), so it is validated
   * against our own base domain before we redirect — see {@link safeOidcReturnUrl}. An
   * unvalidated redirect here would be an open redirect on an identity provider, which is
   * exactly the page a victim has just been taught to trust.
   */
  private goToApp(): void {
    const target = safeOidcReturnUrl(readOidcReturnTo(this.route.snapshot.queryParams));
    if (target) {
      this.externalNav.go(target);
      return;
    }
    this.router.navigate(['/tenants']);
  }
}
