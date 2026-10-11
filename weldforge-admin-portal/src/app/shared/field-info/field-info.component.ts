import { ChangeDetectionStrategy, Component, Input } from '@angular/core';
import { MatTooltipModule } from '@angular/material/tooltip';

/**
 * The small "i" on a form field's top-right corner that explains the field
 * when you hover it:
 *
 *   <div class="wf-field">
 *     <mat-form-field appearance="outline"> ... </mat-form-field>
 *     <wf-field-info label="Web origins" [text]="webOriginInfo()" />
 *   </div>
 *
 * The parent supplies the positioning context (`.wf-field` above is just
 * `position: relative`); everything else is here.
 *
 * It exists because the OIDC client form explained itself in `mat-hint`, and
 * those explanations ran to two and three lines. With
 * `subscriptSizing="dynamic"` they overflowed into the grid row beneath;
 * without it every field in the row reserved the tallest hint's height. Either
 * way a form that is read once and then used reads as a wall of small print,
 * and the lines that matter while you type -- "= 14 days", "must be positive"
 * -- were lost among the ones that do not change. Those stay inline. The
 * standing explanation moved in here.
 *
 * Bind `text` from a method rather than a field when it depends on the form.
 * Methods re-evaluate on every change-detection pass; a `computed()` over a
 * plain `[(ngModel)]` field would memoise its first value forever, which is
 * the zoneless trap that killed the Service Accounts Create button in PR #24.
 * OnPush is still correct here: the parent re-evaluates the binding each pass
 * and a changed input marks this component dirty.
 *
 * It is a <button>, not a <span>, so the explanation is reachable without a
 * mouse -- matTooltip opens on focus as well as hover.
 */
@Component({
  selector: 'wf-field-info',
  standalone: true,
  imports: [MatTooltipModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <button type="button"
            class="dot"
            [matTooltip]="text"
            matTooltipClass="wf-field-info-tip"
            matTooltipPosition="above"
            [matTooltipShowDelay]="100"
            [attr.aria-label]="label ? label + ' — what this field is for' : 'What this field is for'"
            (click)="$event.preventDefault()">i</button>
  `,
  styles: [`
    :host {
      position: absolute;
      top: -9px;
      right: 12px;
      z-index: 2;
      line-height: 0;
    }

    .dot {
      // It sits ON the field's outline, the way the floating label does, so
      // it needs the surrounding panel's own colour behind it to break the
      // border line cleanly. --wf-panel-bg is declared by whichever container
      // paints that panel; the card surface is the fallback.
      background: var(--wf-panel-bg, var(--wf-bg-2));
      color: var(--wf-text-3);
      border: 1px solid var(--wf-border-2);
      border-radius: 50%;
      width: 16px;
      height: 16px;
      padding: 0;
      font-family: var(--wf-sans);
      font-size: 11px;
      font-weight: 700;
      font-style: italic;
      line-height: 14px;
      text-align: center;
      cursor: help;
      transition: color 120ms ease, border-color 120ms ease;
    }

    .dot:hover,
    .dot:focus-visible {
      color: var(--wf-blue);
      border-color: var(--wf-blue);
    }

    .dot:focus-visible {
      outline: 2px solid var(--wf-blue);
      outline-offset: 2px;
    }
  `]
})
export class FieldInfoComponent {
  /** The explanation. Bind a method when it depends on the form's state. */
  @Input({ required: true }) text = '';

  /** The field's name, for the screen-reader label. */
  @Input() label = '';
}
