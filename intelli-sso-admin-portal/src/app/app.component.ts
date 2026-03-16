import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet, Router, RouterModule } from '@angular/router';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatButtonModule } from '@angular/material/button';
import { AuthService } from './core/services/auth.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, RouterModule, MatToolbarModule, MatButtonModule],
  template: `
    <mat-toolbar color="primary">
      <span>Intelli SSO Admin</span>
      <span class="spacer"></span>
      <button mat-button routerLink="/users">Users</button>
      <button mat-button routerLink="/roles">Roles</button>
      <button mat-button routerLink="/environments">Environments</button>
      <button mat-button routerLink="/app-clients">App Clients</button>
      <button mat-raised-button color="warn" (click)="logout()" *ngIf="authService.isLoggedIn()">Logout</button>
    </mat-toolbar>

    <main class="container">
      <router-outlet></router-outlet>
    </main>
  `,
  styles: [`
    .spacer { flex: 1 1 auto; }
    .container { padding: 16px; max-width: 1200px; margin: 0 auto; }
  `]
})
export class AppComponent {
  constructor(public authService: AuthService, private router: Router) {}

  logout() {
    this.authService.logout();
    this.router.navigate(['/login']);
  }
}
