import { TestBed } from '@angular/core/testing';
import { describe, it, expect, beforeEach } from 'vitest';
import { ProviderIconComponent } from './provider-icon.component';

describe('ProviderIconComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [ProviderIconComponent] }).compileComponents();
  });

  function render(provider: string | null | undefined) {
    const fixture = TestBed.createComponent(ProviderIconComponent);
    fixture.componentRef.setInput('provider', provider);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('renders a mark for every provider the backend enum defines', () => {
    // Kept in step with SocialProviderType deliberately. A provider added
    // there without a mark here falls back to a text-only button, which is
    // what this list is here to make someone notice.
    for (const p of ['GOOGLE', 'MICROSOFT', 'GITHUB', 'FACEBOOK', 'APPLE', 'LINKEDIN', 'TWITTER']) {
      const el = render(p);
      expect(el.querySelector('svg'), `no mark for ${p}`).toBeTruthy();
    }
  });

  it('accepts the provider in any case', () => {
    expect(render('google').querySelector('svg')).toBeTruthy();
    expect(render('Google').querySelector('svg')).toBeTruthy();
    expect(render(' GOOGLE ').querySelector('svg')).toBeTruthy();
  });

  it('renders nothing, and takes no space, for an unknown or absent provider', () => {
    for (const p of ['OKTA', '', null, undefined]) {
      const el = render(p);
      expect(el.querySelector('svg')).toBeNull();
      expect(el.querySelector('.wf-provider-icon--empty')).toBeTruthy();
    }
  });

  it("keeps Google's mark in its own colours rather than the button's", () => {
    // Google's guidelines require the four-colour G. If someone later
    // "tidies" these to currentColor, that is a brand violation, not a
    // styling preference.
    const svg = render('GOOGLE').querySelector('svg')!;
    const fills = [...svg.querySelectorAll('path')].map(p => p.getAttribute('fill'));
    expect(fills).toContain('#EA4335');
    expect(fills).toContain('#4285F4');
    expect(fills).toContain('#FBBC05');
    expect(fills).toContain('#34A853');
  });

  it('lets monochrome marks take the button text colour, so they work on a dark tenant', () => {
    for (const p of ['GITHUB', 'APPLE', 'TWITTER']) {
      const svg = render(p).querySelector('svg')!;
      expect(svg.getAttribute('fill'), `${p} should follow currentColor`).toBe('currentColor');
    }
  });

  it('hides the mark from assistive tech, because the button already says the provider', () => {
    const el = render('GOOGLE');
    expect(el.querySelector('.wf-provider-icon')!.getAttribute('aria-hidden')).toBe('true');
  });
});
