// Development environment.
//
// The API key is intentionally blank. Never commit a working key here —
// see SECURITY_AUDIT_2026-04-15.md CRITICAL-1. For a local dev loop,
// create an `environment.local.ts` (gitignored) that overrides appApiKey
// with a freshly-issued wf_live_… key from your local backend.
export const environment = {
  production: false,
  apiBaseUrl: 'http://localhost:8076',
  appApiKey: '',
  // Public base domain for per-tenant auth subdomains. Local dev runs
  // single-host, so this is the literal "localhost" — slugFromHost()
  // returns null on a single-label host, falling back to the tenant
  // picker. See docs/auth-url-spec.md.
  publicBaseDomain: 'localhost'
};