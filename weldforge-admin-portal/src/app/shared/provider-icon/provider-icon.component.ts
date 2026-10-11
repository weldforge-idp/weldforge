import { Component, Input, computed, signal } from '@angular/core';
import { CommonModule } from '@angular/common';

/**
 * The identity provider's own mark, for a social sign-in button:
 *
 *   <wf-provider-icon provider="GOOGLE" />
 *
 * Inline SVG, deliberately. A login page must not fetch a logo from a third
 * party: it would be a request to an outside host made before anyone has
 * signed in (so, a tracking vector on the one page where that matters most),
 * one more thing the CSP has to allow, and one more thing that can fail and
 * leave a button with a hole in it.
 *
 * Marks that are defined by their colour -- Google's four-colour G, Microsoft's
 * four squares -- carry their own; the rest use `currentColor` so they take the
 * button's text colour and stay legible on a tenant's dark or light branding.
 * Google's guidelines require their G rendered in its own colours, which is
 * also why it is not simply tinted with the others.
 *
 * Unknown or absent provider renders nothing rather than a placeholder, so a
 * provider added to the backend enum before a mark exists here degrades to the
 * plain text button it is today.
 */
@Component({
  selector: 'wf-provider-icon',
  standalone: true,
  imports: [CommonModule],
  template: `
    <span class="wf-provider-icon" [class.wf-provider-icon--empty]="!known()" aria-hidden="true">
      <ng-container [ngSwitch]="key()">

        <svg *ngSwitchCase="'google'" viewBox="0 0 48 48" width="18" height="18" focusable="false">
          <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
          <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
          <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
          <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
        </svg>

        <svg *ngSwitchCase="'microsoft'" viewBox="0 0 23 23" width="17" height="17" focusable="false">
          <path fill="#F25022" d="M1 1h10v10H1z"/>
          <path fill="#7FBA00" d="M12 1h10v10H12z"/>
          <path fill="#00A4EF" d="M1 12h10v10H1z"/>
          <path fill="#FFB900" d="M12 12h10v10H12z"/>
        </svg>

        <svg *ngSwitchCase="'github'" viewBox="0 0 16 16" width="18" height="18" fill="currentColor" focusable="false">
          <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/>
        </svg>

        <svg *ngSwitchCase="'apple'" viewBox="0 0 24 24" width="18" height="18" fill="currentColor" focusable="false">
          <path d="M17.05 12.54c-.03-2.6 2.12-3.85 2.22-3.91-1.21-1.77-3.09-2.01-3.76-2.04-1.6-.16-3.12.94-3.93.94-.81 0-2.06-.92-3.39-.9-1.74.03-3.35 1.01-4.25 2.57-1.81 3.14-.46 7.79 1.3 10.34.86 1.25 1.89 2.65 3.24 2.6 1.3-.05 1.79-.84 3.36-.84 1.57 0 2.01.84 3.38.81 1.4-.02 2.28-1.27 3.13-2.53.99-1.45 1.4-2.86 1.42-2.93-.03-.01-2.72-1.04-2.75-4.13zM14.5 4.7c.71-.87 1.19-2.07 1.06-3.27-1.02.04-2.26.68-3 1.54-.66.76-1.24 1.98-1.09 3.15 1.14.09 2.31-.58 3.03-1.42z"/>
        </svg>

        <svg *ngSwitchCase="'facebook'" viewBox="0 0 24 24" width="18" height="18" focusable="false">
          <path fill="#1877F2" d="M24 12.07C24 5.4 18.63 0 12 0S0 5.4 0 12.07C0 18.1 4.39 23.1 10.13 24v-8.44H7.08v-3.49h3.05V9.41c0-3.02 1.79-4.69 4.53-4.69 1.31 0 2.69.24 2.69.24v2.96h-1.52c-1.49 0-1.96.93-1.96 1.89v2.26h3.33l-.53 3.49h-2.8V24C19.61 23.1 24 18.1 24 12.07z"/>
        </svg>

        <svg *ngSwitchCase="'linkedin'" viewBox="0 0 24 24" width="18" height="18" focusable="false">
          <path fill="#0A66C2" d="M20.45 20.45h-3.56v-5.57c0-1.33-.02-3.04-1.85-3.04-1.85 0-2.14 1.45-2.14 2.94v5.67H9.35V9h3.41v1.56h.05c.47-.9 1.63-1.85 3.37-1.85 3.6 0 4.27 2.37 4.27 5.46v6.28zM5.34 7.43a2.06 2.06 0 1 1 0-4.13 2.06 2.06 0 0 1 0 4.13zM7.12 20.45H3.55V9h3.57v11.45zM22.22 0H1.77C.79 0 0 .77 0 1.72v20.56C0 23.23.79 24 1.77 24h20.45c.98 0 1.78-.77 1.78-1.72V1.72C24 .77 23.2 0 22.22 0z"/>
        </svg>

        <svg *ngSwitchCase="'twitter'" viewBox="0 0 24 24" width="16" height="16" fill="currentColor" focusable="false">
          <path d="M18.9 1.15h3.68l-8.04 9.19L24 22.85h-7.41l-5.8-7.58-6.64 7.58H.46l8.6-9.83L0 1.15h7.59l5.24 6.93 6.07-6.93zm-1.29 19.5h2.04L6.48 3.24H4.29l13.32 17.41z"/>
        </svg>

      </ng-container>
    </span>
  `,
  styles: [`
    .wf-provider-icon {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 18px;
      height: 18px;
      flex: 0 0 18px;
      line-height: 0;
    }
    /* No mark for this provider: take up no room rather than leaving a gap
       the button's text has to sit beside. */
    .wf-provider-icon--empty { display: none; }
  `],
})
export class ProviderIconComponent {
  /** Backend SocialProviderType, e.g. "GOOGLE". Case-insensitive. */
  @Input({ required: true })
  set provider(value: string | null | undefined) {
    this.raw.set(value ?? '');
  }

  /** A signal, not a plain field: this app is zoneless (see CLAUDE.md). */
  private readonly raw = signal('');

  readonly key = computed(() => this.raw().trim().toLowerCase());

  private static readonly KNOWN = new Set([
    'google', 'microsoft', 'github', 'apple', 'facebook', 'linkedin', 'twitter',
  ]);

  readonly known = computed(() => ProviderIconComponent.KNOWN.has(this.key()));
}
