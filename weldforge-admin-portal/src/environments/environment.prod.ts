// Production environment.
//
// The SPA uses relative URLs (apiBaseUrl: '') and the nginx vhost for
// admin.weldforge.org proxies /api/*, /scim/v2/*, /t/*/oauth2/*, etc.
// through to sso-api. The nginx layer is responsible for injecting the
// x-app-authorization header from a k8s Secret so the key never touches
// the browser — see SECURITY_AUDIT_2026-04-15.md CRITICAL-1.
//
// Do not re-introduce an appApiKey field in this file.
export const environment = {
  production: true,
  apiBaseUrl: '',
  appApiKey: ''
};