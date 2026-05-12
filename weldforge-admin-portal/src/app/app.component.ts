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
    <mat-toolbar color="primary" class="wf-toolbar">
      <a routerLink="/" class="wf-brand">
        <img src="weldforge-logo.svg" alt="WeldForge" height="34">
      </a>
      <span class="wf-tagline mono">federated identity platform</span>
      <span class="spacer"></span>
      <nav class="wf-nav" *ngIf="authService.isLoggedIn()">
        <a mat-button routerLink="/tenants" routerLinkActive="active">Tenants</a>
        <a mat-button routerLink="/users" routerLinkActive="active">Users</a>
        <a mat-button routerLink="/roles" routerLinkActive="active">Roles</a>
        <a mat-button routerLink="/group-role-mappings" routerLinkActive="active">Group Roles</a>
        <a mat-button routerLink="/service-accounts" routerLinkActive="active">Service Accounts</a>
        <a mat-button routerLink="/audit" routerLinkActive="active">Audit</a>
        <a mat-button routerLink="/security" routerLinkActive="active">Security</a>
        <button mat-stroked-button class="wf-logout" (click)="logout()">Logout</button>
      </nav>
    </mat-toolbar>

    <main class="wf-container">
      <router-outlet></router-outlet>
    </main>
  `,
  styles: [`
    :host { display: block; }
    .spacer { flex: 1 1 auto; }

    .wf-toolbar {
      height: 64px;
      padding: 0 24px;
      gap: 16px;
    }

    .wf-brand {
      display: inline-flex;
      align-items: center;
      text-decoration: none;
      padding: 6px 4px;
      border-radius: 3px;
    }

    .wf-tagline {
      font-family: 'Space Mono', monospace;
      font-size: 11px;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--wf-text-3);
      padding-left: 14px;
      border-left: 1px solid var(--wf-border-2);
      margin-left: 4px;
    }

    .wf-nav {
      display: flex;
      align-items: center;
      gap: 4px;
    }

    .wf-nav a.active {
      color: var(--wf-amber) !important;
      background: rgba(232, 146, 31, 0.08);
    }

    .wf-logout {
      margin-left: 12px !important;
      color: var(--wf-text-2) !important;
      border-color: var(--wf-border-2) !important;
    }

    .wf-container {
      padding: 32px 24px;
      max-width: 1280px;
      margin: 0 auto;
    }

    @media (max-width: 760px) {
      .wf-tagline { display: none; }
      .wf-nav a { padding: 0 8px !important; min-width: 0 !important; }
    }
  `]
})
export class AppComponent {
  constructor(public authService: AuthService, private router: Router) {}

  logout() {
    // logout() now returns an Observable — it has already cleared
    // local state synchronously and the subscription drives the
    // network revocation of the refresh-token family. We don't gate
    // the redirect on the server response: the user should leave the
    // page immediately, and the catchError inside AuthService.logout
    // means a failed revocation won't surface here.
    this.authService.logout().subscribe();
    this.router.navigate(['/login']);
  }
}
