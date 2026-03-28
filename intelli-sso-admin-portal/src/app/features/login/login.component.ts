import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';
import { catchError, tap } from 'rxjs/operators';
import { of } from 'rxjs';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [
    CommonModule, FormsModule,
    MatCardModule, MatFormFieldModule, MatInputModule,
    MatButtonModule, MatProgressSpinnerModule
  ],
  template: `
    <mat-card class="login-card">
      <mat-card-title>ForgeID Login</mat-card-title>

      <mat-card-content>
        <form (ngSubmit)="login()">
          <mat-form-field appearance="outline">
            <mat-label>Email</mat-label>
            <input matInput [(ngModel)]="credentials().email" required type="email">
          </mat-form-field>

          <mat-form-field appearance="outline">
            <mat-label>Password</mat-label>
            <input matInput [(ngModel)]="credentials().password" required type="password">
          </mat-form-field>

          <button mat-raised-button color="primary" type="submit" [disabled]="loading">
            {{ loading ? 'Logging in...' : 'Login' }}
          </button>
        </form>
      </mat-card-content>
    </mat-card>
  `,
  styles: [`
    .login-card { max-width: 400px; margin: 40px auto; padding: 20px; }
  `]
})
export class LoginComponent {
  credentials = signal({ email: '', password: '' });
  loading = false;

  constructor(private authService: AuthService, private router: Router, private route: ActivatedRoute) {}

  login() {
    this.loading = true;
    this.authService.login(this.credentials()).pipe(
      tap(() => {
        const returnUrl = this.route.snapshot.queryParams['returnUrl'] || '/users';
        this.router.navigate([returnUrl]);
      }),
      catchError(err => {
        console.error(err);
        this.loading = false;
        return of(null);
      })
    ).subscribe();
  }
}
