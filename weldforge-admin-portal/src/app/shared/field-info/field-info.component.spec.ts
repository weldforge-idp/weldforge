import { TestBed } from '@angular/core/testing';
import { MatTooltip } from '@angular/material/tooltip';
import { By } from '@angular/platform-browser';
import { describe, it, expect, beforeEach } from 'vitest';
import { FieldInfoComponent } from './field-info.component';

describe('FieldInfoComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [FieldInfoComponent] }).compileComponents();
  });

  function render(text: string, label?: string) {
    const fixture = TestBed.createComponent(FieldInfoComponent);
    fixture.componentRef.setInput('text', text);
    if (label !== undefined) fixture.componentRef.setInput('label', label);
    fixture.detectChanges();
    return fixture;
  }

  it('puts the explanation in the tooltip, not on the page', () => {
    const fixture = render('Not needed: a confidential client calls the token endpoint server-side.');
    const tooltip = fixture.debugElement.query(By.directive(MatTooltip)).injector.get(MatTooltip);

    expect(tooltip.message).toBe(
        'Not needed: a confidential client calls the token endpoint server-side.');
    // The point of the change: the sentence is not occupying the form.
    expect((fixture.nativeElement as HTMLElement).textContent?.trim()).toBe('i');
  });

  it('follows the field as the form changes', () => {
    const fixture = render('Required for a browser client, or every call is blocked by CORS.');
    const tooltip = fixture.debugElement.query(By.directive(MatTooltip)).injector.get(MatTooltip);

    fixture.componentRef.setInput('text', 'Not needed: a confidential client calls the token endpoint server-side.');
    fixture.detectChanges();

    expect(tooltip.message).toContain('Not needed');
  });

  it('is a button, so the explanation is reachable without a mouse', () => {
    // matTooltip opens on focus as well as hover; a <span> would put this
    // text out of reach of anyone not using a pointer.
    const el = render('anything').nativeElement as HTMLElement;
    const button = el.querySelector('button');

    expect(button).toBeTruthy();
    // Inside a form, and not a submit button.
    expect(button!.getAttribute('type')).toBe('button');
  });

  it('names the field it belongs to for a screen reader', () => {
    const el = render('anything', 'Web origins').nativeElement as HTMLElement;
    expect(el.querySelector('button')!.getAttribute('aria-label')).toContain('Web origins');
  });

  it('still has a usable label when no field name is given', () => {
    const el = render('anything').nativeElement as HTMLElement;
    const aria = el.querySelector('button')!.getAttribute('aria-label');
    expect(aria).toBeTruthy();
    expect(aria).not.toContain('undefined');
  });
});
