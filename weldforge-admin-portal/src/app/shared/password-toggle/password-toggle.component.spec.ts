import { describe, it, expect, beforeEach } from 'vitest';
import { Component } from '@angular/core';
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { PasswordToggleComponent } from './password-toggle.component';

@Component({
  standalone: true,
  imports: [PasswordToggleComponent],
  template: `
    <form>
      <input #pw type="password" name="password" value="hunter2-but-longer">
      <wf-password-toggle [for]="pw" />
    </form>
  `,
})
class HostComponent {}

describe('PasswordToggleComponent', () => {
  let fixture: ComponentFixture<HostComponent>;
  let input: HTMLInputElement;
  let button: HTMLButtonElement;

  beforeEach(async () => {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({ imports: [HostComponent] });
    fixture = TestBed.createComponent(HostComponent);
    await fixture.whenStable();
    input = fixture.nativeElement.querySelector('input');
    button = fixture.nativeElement.querySelector('button');
  });

  it('starts masked, labelled "Show password"', () => {
    expect(input.type).toBe('password');
    expect(button.getAttribute('aria-label')).toBe('Show password');
    expect(button.getAttribute('aria-pressed')).toBe('false');
    expect(button.textContent).toContain('visibility');
  });

  it('reveals and hides the password', async () => {
    button.click();
    await fixture.whenStable();
    expect(input.type).toBe('text');
    expect(button.getAttribute('aria-label')).toBe('Hide password');
    expect(button.getAttribute('aria-pressed')).toBe('true');
    expect(button.textContent).toContain('visibility_off');

    button.click();
    await fixture.whenStable();
    expect(input.type).toBe('password');
    expect(button.getAttribute('aria-pressed')).toBe('false');
  });

  it('never submits the form it sits in', () => {
    expect(button.type).toBe('button');
  });
});
