---
name: Angular zoneless pitfalls in this codebase
description: two patterns that have silently broken pages here — computed() over a non-signal field, and template `!` non-null assertions on lazily-initialised drafts
type: feedback
originSessionId: 2c8ec944-2f7f-4c86-a922-6989bb89938b
---
The admin portal runs with `provideZonelessChangeDetection()` (see `app.config.ts`) and signals throughout. Two patterns have silently broken pages and cost multiple PRs each to track down. Watch for both when reviewing or writing component code.

**1. `computed()` over a plain (non-signal) field memoises to its first value forever.**

```ts
protected draft = { name: '', adminRole: 'TENANT_ADMIN' };  // plain object
protected canCreate = computed(() => !!this.draft.name?.trim());
//                    ^^^ ran once at construction with name='', cached false, NEVER re-runs
```

`computed()` only re-evaluates when one of its tracked **signals** changes. A plain object field is not tracked — even though `[(ngModel)]="draft.name"` mutates it on every keystroke, the computed sits frozen. Symptoms: a button stays disabled forever, or a guard returns the wrong value. Fix: either make `draft` a signal (`signal({...})` + `.update()`) or make the derived value a plain method (`canCreate(): boolean { ... }`). Methods re-evaluate on every CD pass, which is what you want here.

Why this bit us: PR #24 — Service Accounts Create button silently dead.

**2. Template `t.x!.y` is compile-only and throws at runtime if `x` is undefined, silently truncating the CD pass.**

```html
@for (t of tenants(); track t.id) {
  <input [(ngModel)]="t.twilioDraft!.accountSid">
  <!-- t.twilioDraft is undefined for any tenant not yet "opened" → throws on render -->
}
```

The TS `!` non-null assertion is a compile-time hint only. At runtime, `undefined.accountSid` throws `TypeError: Cannot read properties of undefined (reading 'accountSid')`. In zoneless mode the throw aborts CD partway through the iteration, so panels rendered before the throw populate and panels rendered after are silently empty (header bindings included). The pattern of "first row works, rest are blank" is the tell.

Fix: initialise the optional draft eagerly in the data-loading callback (alongside `draft`, `samlDraft`, `brandingDraft`), or guard the binding with `@if (t.twilioDraft) { ... }`.

Why this bit us: PR #23 — Tenants page showed only the first row. Spent two PRs chasing red herrings (`*ngFor` → `@for` migration in PR #22) before finding the actual throw via DevTools console.

**How to apply:**
- When you see "only the first iteration works", check DevTools console for a runtime throw before assuming it's a CD/iteration bug.
- Code review: any `computed()` body that reaches into a plain class field is suspect. Any template `!` on a property that's lazy-loaded is suspect.
- Test pattern: hover the first ngFor row vs the second — if the second's header bindings are empty strings but the DOM element exists, it's the second case.
