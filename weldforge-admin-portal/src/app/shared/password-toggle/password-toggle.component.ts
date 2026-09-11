import { Component, Input, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';

/**
 * Show / hide button for a password field. Put it in the field's suffix and
 * point it at the input:
 *
 *   <input matInput #pw type="password" ...>
 *   <wf-password-toggle matIconSuffix [for]="pw" />
 *
 * It flips the input's `type` between `password` and `text`. A real
 * `<button type="button">` so it never submits the form, stays in the tab
 * order, and announces its state (aria-pressed) to screen readers.
 */
@Component({
  selector: 'wf-password-toggle',
  standalone: true,
  imports: [MatButtonModule, MatIconModule],
  template: `
    <button mat-icon-button type="button" class="wf-password-toggle"
            (click)="toggle()"
            [attr.aria-label]="visible() ? 'Hide password' : 'Show password'"
            [attr.aria-pressed]="visible()"
            [title]="visible() ? 'Hide password' : 'Show password'">
      <mat-icon>{{ visible() ? 'visibility_off' : 'visibility' }}</mat-icon>
    </button>
  `,
})
export class PasswordToggleComponent {
  @Input({ required: true }) for!: HTMLInputElement;

  /** A signal, not a field: this app is zoneless (see CLAUDE.md). */
  readonly visible = signal(false);

  toggle(): void {
    const next = !this.visible();
    this.visible.set(next);
    this.for.type = next ? 'text' : 'password';
  }
}
