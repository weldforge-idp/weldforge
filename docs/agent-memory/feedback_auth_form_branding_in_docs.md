---
name: Document auth-form branding customization in docs/tutorials
description: When writing or updating product docs/tutorials, always include guidance on customizing the login + password-reset (and other auth) forms so they match the embedding site's branding
type: feedback
originSessionId: fbd7467f-a028-47b3-a1d0-d02fc549f716
---
When producing user-facing documentation, integration guides, or tutorials for WeldForge, **include explicit instructions on how an operator customises the login form and password-reset form** (and by extension the other auth-shell screens — register, forgot-password, verify-email) so the visual styling matches the rest of the consuming site.

The mechanisms are already in the platform: the `tenants.branding` JSONB column drives CSS-var overrides for the SPA (V32 migration documents the keys: `logoUrl`, `primaryColor`, `primaryDarkColor`, `accentColor`, `bgColor`, `bg2Color`, `textColor`, `displayFont`, `sansFont`, `tagline`, `eyebrow`, `headline`, `ctaLabel`, `customCssUrl`, etc.), plus `displayName`, `registrationEnabled`, `passwordRecoveryEnabled`. The admin Tenants → Branding tab writes them. Tutorials should call this out, not leave readers to discover it.

**Why:** Adopters embedding WeldForge expect the auth forms to feel native to their site. Without explicit guidance the platform's defaults bleed through and look like a third-party logo paste-in.

**How to apply:** Whenever I write/edit any tutorial, README section, integration guide, or marketing copy that walks a reader through onboarding a tenant, add a "Customising the login and password-reset forms" section that lists: (1) where to set branding (admin portal Tenants tab → Branding subtab, or `POST/PUT /api/admin/tenants/{id}` with a `branding` JSON), (2) the supported keys and what each one does, (3) the per-tenant feature toggles (`registrationEnabled`, `passwordRecoveryEnabled`, `emailVerificationRequired`), (4) how the tenant slug enters the auth URLs (`?tenant=<slug>` query param or `/t/<slug>/...` path prefix). This applies across the OIDC tutorial, SAML tutorial, embedding guide, "first-tenant setup" runbook, and any future getting-started flows.
