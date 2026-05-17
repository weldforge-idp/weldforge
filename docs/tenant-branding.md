# Tenant branding contract

Per-tenant branding for the WeldForge **Angular admin-portal auth screens** —
the login, register, forgot-password, reset-password and verify-email pages.
This is the **canonical reference**; update it whenever a branding key changes.

## Where it lives and how it flows

- Stored on `tenants.branding` (JSONB) — `Tenant.branding` (`Map<String,Object>`).
- Served to the browser by `GET /api/auth/tenants/{slug}/branding`.
- Applied by `weldforge-admin-portal`'s `TenantBrandingService`:
  - CSS-variable keys → `--wf-*` custom properties on `:root`.
  - `theme` → toggles the `.wf-light` class on `<body>`.
- Content keys are read directly by `login.component.ts` and
  `auth-shell.component.ts`.

> The backend `LoginController` also reads branding, but nginx serves the
> Angular portal at `/login` — `LoginController` is **shadowed** and is *not*
> the page users see. Brand the Angular surface. (PR #30 themed that
> shadowed controller; harmless but inert.)

## Keys

### CSS-variable keys (→ `--wf-*` on `:root`)

| Key | CSS variable | Purpose |
|---|---|---|
| `primaryColor` | `--wf-blue` | primary colour — buttons, links |
| `primaryDarkColor` | `--wf-blue-dim` | primary, darker / hover |
| `accentColor` | `--wf-amber` | accent colour |
| `accentDarkColor` | `--wf-amber-dim` | accent, darker |
| `bgColor` | `--wf-bg` | page background |
| `bg2Color` | `--wf-bg-2` | card / surface background |
| `bg3Color` | `--wf-bg-3` | raised surface |
| `borderColor` | `--wf-border` | borders / dividers |
| `textColor` | `--wf-text` | primary text |
| `text2Color` | `--wf-text-2` | secondary text |
| `text3Color` | `--wf-text-3` | tertiary / muted text |
| `displayFont` | `--wf-display` | headings font stack |
| `sansFont` | `--wf-sans` | body font stack |
| `monoFont` | `--wf-mono` | monospace font stack |

### Theme switch

| Key | Values | Effect |
|---|---|---|
| `theme` | `"light"` \| anything else = dark | `"light"` adds `.wf-light` to `<body>`, which scopes a **light Angular Material colour theme**. This is required: Material is built as a dark theme, so CSS-variable overrides alone leave `mat-form-field` internals (outlines, labels, ripples) dark and unreadable on a light surface. |

### Content keys (read directly by the components)

| Key | Type | Effect |
|---|---|---|
| `logoUrl` | string | Logo image URL. If absent on a branded tenant, a text **wordmark** is shown — never the WeldForge shield. |
| `wordmark` | string | Text shown in place of a logo when `logoUrl` is absent. Falls back to the tenant display name. |
| `headline` | string | Login-card headline. Default: `Sign in to {displayName}`. |
| `eyebrow` | string | Small uppercase line above the headline. |
| `tagline` | string | Sub-line under the headline. |
| `ctaLabel` | string | Submit-button label. Default: `Enter the Forge`. |
| `hideFooter` | boolean | Hide the `OAUTH2 · OIDC · …` footer strip. |

Unknown keys are ignored — adding keys is backward-safe.

## Setting branding

`PUT /api/admin/tenants/{id}` with a `branding` object. Cross-tenant admins
add the `X-WF-Tenant: <slug>` header.

### Example — a light-themed tenant (oggendboodskap / "Devotional Bot")

```json
{
  "branding": {
    "theme": "light",
    "bgColor": "#F3F4F6",
    "bg2Color": "#FFFFFF",
    "bg3Color": "#F9FAFB",
    "borderColor": "#E5E7EB",
    "textColor": "#111827",
    "text2Color": "#6B7280",
    "text3Color": "#9CA3AF",
    "primaryColor": "#16A34A",
    "primaryDarkColor": "#15803D",
    "sansFont": "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif",
    "displayFont": "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif",
    "wordmark": "Devotional Bot",
    "headline": "Sign in to Devotional Bot",
    "tagline": "Sign in to manage your morning devotionals.",
    "ctaLabel": "Sign in"
  }
}
```
