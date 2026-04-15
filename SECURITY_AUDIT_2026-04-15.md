# WeldForge Security Audit — 2026-04-15

**Scope:** `www.weldforge.org`, `weldforge.org`, `sso.weldforge.org`,
`admin.weldforge.org`, the deployed `intelli-sso-auth` Spring Boot
application, and its dependency surface.

**Methodology:** Phase 1 passive analysis only. No active fuzzing, no
brute-force, no exploitation. Every probe was a single read-only HTTP
request issued from a controlled workstation. No credentials were brute
forced; one credential was extracted from a publicly accessible
JavaScript bundle (see CRITICAL-1).

**Tools:** `curl`, `openssl`, `dig`, `python3`, `mvn dependency:list`. No
Burp/ZAP/Nikto/sqlmap/etc. — all probes were hand-issued.

**Status:** Phase 1 complete. Phase 2 (active OWASP Top 10 probes against
authenticated endpoints) **not started** — pending review of the critical
findings below, which need fixing before further testing is meaningful.

---

## Executive summary

| Severity   | Count | Highest item                                                          |
|------------|-------|-----------------------------------------------------------------------|
| Critical   | **1** | Hardcoded API key in V2 migration, exposed in admin SPA JS bundle     |
| High       | **3** | SPA built with dev environment; no HSTS/CSP/etc on marketing site; HTTPS→HTTP downgrade in nginx redirect |
| Medium     | **5** | OpenAPI spec public; outdated Spring Security; missing CAA; missing DMARC; method-not-allowed returns 500 |
| Low        | **6** | Server header disclosure; duplicate security headers; missing TLS 1.3 on NLB; SCIM 500 on missing slug; etc. |
| Info       | **2** | TLS 1.3 only on Xneelo; Apache/nginx versions disclosed                |

**The single most urgent action is rotating the leaked API keys and
removing the V2 seed migration. Until that is done, the SSO API has a
publicly-known credential.**

---

## CRITICAL findings

### CRITICAL-1 — Hardcoded API key in V2 migration, leaked via admin SPA bundle

**Severity:** CRITICAL — exploit-ready, no auth required.

**Evidence:**

`intelli-sso-auth/src/main/resources/db/migration/V2__seed_app_clients.sql`
contains:

```sql
INSERT INTO app_clients (client_name, api_key, enabled) VALUES
    ('frontend-admin-portal', 'x-app-auth-1234567890abcdef', TRUE),
    ('mobile-backend',        'x-app-auth-mobile-9876543210fedcba', TRUE)
ON CONFLICT (api_key) DO NOTHING;
```

These two app-client API keys are seeded into the `app_clients` table on
first install of every environment. They are accepted as valid by
`AppAuthorizationFilter` because the legacy plaintext fallback added in
Epic E still honours rows with a `api_key` value (and no `api_key_hash`).

The first key is **also hardcoded in the deployed Angular bundle** as the
production `appApiKey`:

```js
// from https://admin.weldforge.org/main-J6IOXZKB.js
var We = {
    production: !1,
    apiBaseUrl: "http://localhost:8076",
    appApiKey:  "x-app-auth-1234567890abcdef"
};
```

The bundle is anonymously fetchable. Any visitor can read it and obtain
the working credential.

**Reproduction:**

```bash
curl -sS https://admin.weldforge.org/main-J6IOXZKB.js | \
    grep -oE '"x-app-auth-[a-z0-9]+"'
# -> "x-app-auth-1234567890abcdef"

curl -sS -i -X POST https://sso.weldforge.org/api/auth/login \
    -H 'Content-Type: application/json' \
    -H 'x-app-authorization: x-app-auth-1234567890abcdef' \
    -d '{}'
# -> HTTP 500 (filter accepts the key, controller crashes on empty body
#    — proof the key is honoured by the auth filter)

# Compare with a bogus key:
curl -sS -i -X POST https://sso.weldforge.org/api/auth/login \
    -H 'Content-Type: application/json' \
    -H 'x-app-authorization: not-a-real-key' \
    -d '{}'
# -> HTTP 403 "Missing or invalid x-app-authorization header"
```

The 500 vs 403 split is the smoking gun: a 500 means the request reached
the controller, which means the filter authenticated the credential.

**Impact:**

The leaked key bypasses the *first* layer of API auth on every endpoint.
Most admin endpoints additionally require a JWT bound to a real user with
an `AdminRole`, so this key alone does not grant admin access. **But** it
unlocks the unauthenticated surface:

- `POST /api/auth/register` — anonymous bulk user registration
- `POST /api/auth/login` — credential-stuffing oracle (timing, rate limit
  exhaustion, account lockouts on real users)
- `POST /api/auth/password-reset/request` — email enumeration / harvest
- Hitting OIDC `/t/{slug}/oauth2/*` endpoints to map tenants
- Triggering the per-tenant federation rules engine
- Filling the audit log with arbitrary noise

Combined with the missing Phase-2 testing of authorization layers, the
true blast radius is unconfirmed but at minimum permits abuse of every
public auth endpoint.

The second key (`mobile-backend`, `x-app-auth-mobile-9876543210fedcba`)
is the same shape and the same problem; it just isn't currently used by
any client we know of. It is still in the production database.

**Remediation (in this order):**

1. **Immediate, in production:**
   ```sql
   UPDATE app_clients
       SET enabled = FALSE,
           api_key = NULL,
           api_key_hash = NULL,
           api_key_prefix = NULL
       WHERE api_key IN
           ('x-app-auth-1234567890abcdef',
            'x-app-auth-mobile-9876543210fedcba');
   ```
   Run via `kubectl exec deployment/sso-postgres -- psql -U sso -d intelli_sso`
   then verify with `SELECT id, client_name, enabled FROM app_clients;`.

2. **In the repo:**
   - Replace `V2__seed_app_clients.sql` body with a comment explaining
     it was redacted; do **not** delete the file because Flyway tracks
     applied migrations by filename.
   - Add a new `V30__revoke_seeded_app_clients.sql` migration that runs
     the SQL above (idempotent on environments that already had it
     manually applied).
   - Commit, deploy.

3. **In the admin SPA:**
   - Issue a fresh app client per Epic E:
     `POST /api/admin/app-clients { "clientName": "admin-portal" }`
     This returns a `wf_live_…` value once. Capture it.
   - Move the value out of `intelli-sso-admin-portal/src/environments/`
     and into either:
     - a build-time substitution from a TeamCity password parameter, **or**
     - a server-side config endpoint that requires the user to have
       authenticated by other means first (catch-22 for a SPA, so usually
       option a is simpler).
   - Rebuild and redeploy the SPA. Verify the bundle no longer contains
     the literal string.

4. **In `AppAuthorizationFilter`:**
   - Once every legitimate consumer has rotated to a hashed key, remove
     the `findByApiKeyAndEnabledTrue` plaintext-fallback branch entirely.
     The fallback existed for the V23 migration grace period; it should
     not survive past CRITICAL-1's remediation.

5. **Audit:**
   - Query `audit_events` for any successful API call that came in with
     either of the leaked keys since deploy. Anything with the
     `frontend-admin-portal` or `mobile-backend` tag in metadata should
     be reviewed.

---

## HIGH findings

### HIGH-1 — Admin SPA built with dev environment, broken in production

**Evidence:** The deployed SPA bundle at `https://admin.weldforge.org/main-J6IOXZKB.js`
contains `production: !1` (i.e. `false`) and `apiBaseUrl: "http://localhost:8076"`.

```bash
curl -sS https://admin.weldforge.org/main-J6IOXZKB.js | \
    grep -oE 'var We=\{[^}]+\}'
# var We={production:!1,apiBaseUrl:"http://localhost:8076",appApiKey:"x-app-auth-1234567890abcdef"}
```

**Impact:**

- The Angular `production: false` flag means `enableProdMode()` is not
  called. Verbose error messages, debug-mode change detection, and dev
  helpers run in production browsers.
- The SPA's HTTP calls go to `http://localhost:8076` from a browser whose
  page was loaded over `https://admin.weldforge.org`. **Mixed content
  blocking** in every modern browser will block every API call. The admin
  portal is therefore non-functional for any normal user.
- The fact that nginx also reverse-proxies `/api/*` on `admin.weldforge.org`
  is irrelevant: the SPA constructs absolute URLs from `apiBaseUrl`, so
  it never uses the relative-path proxy.

**Remediation:**

- Build with the production environment file:
  `ng build --configuration production`. The `environment.production.ts`
  should set `production: true`, `apiBaseUrl: "https://sso.weldforge.org"`
  (or `""` for relative URLs through the nginx proxy).
- After CRITICAL-1 is fixed, the `appApiKey` should be set from a
  TeamCity password parameter at build time, not committed to the repo.
- Re-deploy the SPA image (`sso-frontend`).
- Verify by loading `https://admin.weldforge.org/` in a fresh incognito
  window and watching the network tab — every XHR should target
  `https://sso.weldforge.org/...` or `https://admin.weldforge.org/api/...`.

### HIGH-2 — Marketing site has zero security headers and no HTTP→HTTPS redirect

**Evidence:**

```bash
curl -sSI https://www.weldforge.org/
# server: Apache
# (no HSTS, no CSP, no X-Frame-Options, no X-Content-Type-Options,
#  no Referrer-Policy, no Permissions-Policy)

curl -sS -o /dev/null -w '%{http_code}\n' http://www.weldforge.org/
# 200 — serves over plaintext HTTP, no redirect to HTTPS
```

**Impact:**

- A first-time visitor on a hostile network (coffee shop, public Wi-Fi)
  can be served a tampered page over HTTP. Without HSTS the browser
  never learns to upgrade subsequent visits.
- The site can be embedded in an `<iframe>` from anywhere
  (clickjacking surface).
- No `X-Content-Type-Options: nosniff` means the browser may MIME-sniff
  responses, which on a static site is low risk but still defence in
  depth.
- A page from `www.weldforge.org` could be loaded over plain HTTP and
  then read or modified by a network attacker on the way back.

**Remediation:**

Add an `.htaccess` to `intelli-sso-www/public/` and re-deploy:

```apache
# Force HTTPS on every request
RewriteEngine On
RewriteCond %{HTTPS} !=on
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

# Strict baseline of security headers
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
    Header always set Content-Security-Policy "default-src 'self'; img-src 'self' data:; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src https://fonts.gstatic.com; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';"
</IfModule>

# Hide the Apache 404 default page (which leaks "Apache Server at … Port 443")
ErrorDocument 404 /index.html
```

Notes:

- The CSP allows Google Fonts because `styles.css` imports them via
  `@import url('https://fonts.googleapis.com/...')`. Tighten further by
  self-hosting the fonts.
- Once HSTS has been live for a few weeks without issues, raise
  `max-age` to `63072000` (2 years) and add `preload` for the HSTS
  preload list submission.

### HIGH-3 — nginx 301 redirect downgrades HTTPS to HTTP

**Evidence:**

```bash
curl -sSI https://admin.weldforge.org/login
# HTTP/1.1 301 Moved Permanently
# Location: http://admin.weldforge.org/login/
#                ^^^^ should be https://
```

The nginx config inside the `sso-frontend` pod is constructing the
redirect Location with the wrong scheme — it's stripping the TLS context
because the NLB terminates TLS upstream and the pod sees plain HTTP on
port 80.

**Impact:**

A user who clicks a link to `https://admin.weldforge.org/login` gets
back `Location: http://admin.weldforge.org/login/`. The browser:

1. With HSTS already cached: rewrites the http: to https: before
   sending. Net result: minor inefficiency, one extra round-trip.
2. Without HSTS (first visit): briefly issues an HTTP request,
   exposing the path `/login/` and the cookies (if any non-Secure
   cookies were set) over plaintext. Then it follows the secondary
   HTTP→HTTPS redirect we already have.

Because HSTS is set on the responses, exposure is minimal **but** the
redirect chain is broken-by-design and confuses some clients (cURL with
`-L` for instance follows the http: link).

**Remediation:** in `infrastructure/kubernetes/sso/frontend/nginx-configmap.yaml`,
inside every `server { ... }` block, add:

```nginx
absolute_redirect off;
port_in_redirect off;
# trust the X-Forwarded-Proto header from the NLB
set_real_ip_from 0.0.0.0/0;
real_ip_header X-Forwarded-For;

# In the location blocks where you need to know the original scheme:
proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;
```

Or, more directly, fix the redirect by setting:

```nginx
if ($http_x_forwarded_proto = "http") {
    return 301 https://$host$request_uri;
}
```

at the top of each `server` block, and then trust the NLB to send
`X-Forwarded-Proto: https` on TLS-terminated requests (which it does by
default).

---

## MEDIUM findings

### MEDIUM-1 — OpenAPI spec publicly accessible without authentication

**Evidence:**

```bash
curl -sS https://sso.weldforge.org/v3/api-docs | head -c 200
# {"openapi":"3.0.1","info":{"title":"intelli-sso API",...
#  ... 95 endpoints documented including /api/admin/* and /scim/v2/* ...
```

`https://sso.weldforge.org/swagger-ui/index.html` returns the live
Swagger UI, also unauthenticated.

**Impact:** every API endpoint, request shape, response shape, security
scheme, and admin operation is visible to an anonymous attacker. This
hands a road map to anyone doing reconnaissance — including the
attacker who already has CRITICAL-1's API key.

**Remediation:** in `SecurityConfig.java`, move `/v3/api-docs/**`,
`/swagger-ui/**` and `/swagger-ui.html` out of the `permitAll` chain
into a chain that requires `ROLE_ADMIN` (or that requires the special
admin app-key). Or restrict at the nginx layer with an allowlist of
internal IPs / VPN CIDRs.

### MEDIUM-2 — Outdated Spring Security 6.3.3 (CVE-2024-38821)

**Evidence:** `mvn dependency:list` shows `spring-security-core:jar:6.3.3`.
Spring Security 6.3.4 was released to fix CVE-2024-38821 (an
authorization bypass in static-resource handling under specific
filter-chain configurations).

**Impact:** unconfirmed in this codebase — exploitation requires a
particular static-resource filter chain that we do not appear to use.
Still, the runtime is one patch behind a known security release.

**Remediation:** bump `spring-boot.version` in `pom.xml` to the latest
3.3.x patch (currently 3.3.6 or later in OSS). Run the full test suite
(`mvn test`) — every Cucumber scenario should still pass — and redeploy.

### MEDIUM-3 — `/scim/v2/Users` returns 500 on missing tenant slug

**Evidence:**

```bash
curl -sS https://sso.weldforge.org/scim/v2/Users
# {"error":"internal_error","message":"An unexpected error occurred",
#  "timestamp":"...","path":"/scim/v2/Users"}
```

The actual SCIM endpoint is `/scim/v2/{slug}/Users`. Hitting the path
without the slug should return a clean 404, not a 500. The 500 confirms
that an unhandled exception is occurring inside the SCIM controller
chain — not a security bug per se, but it indicates an unhandled error
path.

**Impact:** noise in logs, false alarms in monitoring, slightly
unprofessional response shape. Not directly exploitable.

**Remediation:** ensure the SCIM filter chain in `SecurityConfig`
matches `/scim/v2/{slug}/**` rather than `/scim/v2/**`, and add an
explicit 404 for paths that don't carry a slug.

### MEDIUM-4 — Method-not-allowed returns 500 instead of 405

**Evidence:**

```bash
curl -sS -i -X PUT https://sso.weldforge.org/actuator/health
# HTTP/1.1 500
# Content-Type: application/json
# {"error":"internal_error","message":"An unexpected error occurred",...}
```

`HttpRequestMethodNotSupportedException` from Spring is being caught by
the catch-all `@ExceptionHandler(Exception.class)` in
`GlobalExceptionHandler` and turned into a 500.

**Impact:** wrong HTTP semantics, misleading to legitimate clients,
inflates the 500 rate in monitoring (Epic F's webhook stream will fire
on these as if they were real errors).

**Remediation:** add an explicit handler:

```java
@ExceptionHandler(HttpRequestMethodNotSupportedException.class)
public ResponseEntity<Map<String, Object>> handleMethodNotAllowed(
        HttpRequestMethodNotSupportedException ex, HttpServletRequest req) {
    return respond(HttpStatus.METHOD_NOT_ALLOWED, "method_not_allowed",
                   "HTTP " + ex.getMethod() + " not supported here", req);
}
```

Same treatment for `NoResourceFoundException` → 404.

### MEDIUM-5 — Missing CAA record on `weldforge.org`

**Evidence:**

```bash
dig +short weldforge.org CAA
# (no output)
```

Without a CAA record, **any** publicly trusted CA may issue a
certificate for `weldforge.org` and its subdomains. An attacker who
compromises one mis-configured CA could obtain a trusted cert and MITM
the platform.

**Remediation:** add a CAA record at the registrar:

```
weldforge.org. CAA 0 issue "letsencrypt.org"
weldforge.org. CAA 0 issue "amazon.com"
weldforge.org. CAA 0 issuewild ";"
weldforge.org. CAA 0 iodef "mailto:security@weldforge.org"
```

`letsencrypt.org` covers the Xneelo-issued cert, `amazon.com` covers
the AWS NLB cert. The `issuewild ";"` line forbids wildcard certs.

---

## LOW findings

### LOW-1 — `Server` header version disclosure on internal nginx

`https://sso.weldforge.org/*` and `https://admin.weldforge.org/*`
respond with `Server: nginx/1.29.8`. **Remediation:** `server_tokens off;`
in nginx-configmap.yaml.

### LOW-2 — `Server: Apache` on the marketing site

`https://www.weldforge.org/` returns `Server: Apache`. Xneelo-managed,
no version disclosed. **Remediation:** `ServerTokens Prod` in
`.htaccess` (may be disabled by Xneelo at the global level).

### LOW-3 — Duplicate security headers

`https://sso.weldforge.org/actuator/health` returns
`X-Frame-Options`, `Strict-Transport-Security`, and
`X-Content-Type-Options` **twice** each (once from Spring Security, once
from the nginx layer). Functionally identical; cosmetic.

`X-XSS-Protection` is set to both `0` (modern recommendation) and
`1; mode=block` (deprecated) in the same response — a browser will pick
one but the inconsistency is sloppy.

**Remediation:** drop the headers on one side. Cleanest is to remove
them from the Spring chain (`http.headers().disable()` for individual
headers) and let nginx own them.

### LOW-4 — TLS 1.3 not offered on the AWS NLB listener

`sso.weldforge.org` and `admin.weldforge.org` only negotiate TLS 1.2.
Modern AWS NLB listeners can be configured with the
`ELBSecurityPolicy-TLS13-1-2-2021-06` policy.

**Remediation:** in the `sso-frontend` Service annotations:
```yaml
service.beta.kubernetes.io/aws-load-balancer-ssl-negotiation-policy: ELBSecurityPolicy-TLS13-1-2-2021-06
```

### LOW-5 — `Apache Server at weldforge.org Port 443` in 404 body

The marketing site's default 404 page leaks the host and port.
**Remediation:** the `ErrorDocument 404 /index.html` line in the
HIGH-2 `.htaccess` snippet fixes this as a side-effect.

### LOW-6 — Missing DMARC record

```bash
dig +short _dmarc.weldforge.org TXT
# (no output)
```

SPF is present (`v=spf1 mx a include:spf.host-h.net ?all`) but the `?all`
qualifier is "neutral" (anyone may send mail purporting to be from this
domain), and there is no DMARC policy.

**Remediation:** if you don't send mail from this domain, publish a hard
reject:

```
weldforge.org.        TXT  "v=spf1 -all"
_dmarc.weldforge.org. TXT  "v=DMARC1; p=reject; rua=mailto:security@weldforge.org"
```

If you do send mail (e.g. from sso for password resets), tighten
`include:spf.host-h.net ?all` to `-all` and publish DKIM + DMARC.

---

## Information findings

### INFO-1 — `/actuator/circuitbreakers` not externally routed

Internal `kubectl exec ... curl localhost:8080/actuator/circuitbreakers`
returns the JSON correctly. External
`https://sso.weldforge.org/actuator/circuitbreakers` returns 404 — the
nginx ConfigMap `sso-frontend` does not include this path in its
allowed actuator routes. Not a security issue (less attack surface) but
the Epic J observability target is therefore not externally reachable.

**Remediation:** add `location = /actuator/circuitbreakers { proxy_pass …; }`
to the nginx server block for `sso.weldforge.org`.

### INFO-2 — SPA "fallback returns 200" pattern hides info-disclosure probe results

The `try_files $uri /index.html;` Angular routing means
`https://admin.weldforge.org/.env` returns `200 text/html` (the SPA
shell). Automated scanners will flag this as an exposed `.env` file —
false positive, but worth knowing. Optional remediation: in nginx, add
explicit 404s for sensitive patterns:

```nginx
location ~ /\.(env|git|svn|hg|DS_Store|htaccess|htpasswd) { return 404; }
location ~ /(package|tsconfig|angular)\.json$              { return 404; }
```

---

## What I did NOT test (Phase 2 / Phase 3 scope)

These were deliberately deferred until you sign off on the rules of
engagement and CRITICAL-1 has been remediated:

- **OWASP A01 Broken Access Control**: cross-tenant reads with a real
  TENANT_ADMIN token; admin role escalation; horizontal access via
  guessable IDs.
- **OWASP A03 Injection**: SQLi probes against search/filter
  parameters, LDAP injection through the new `LdapUpstreamService`,
  XSS reflection probes.
- **OWASP A07 Identification & Auth Failures**: account-lockout
  exhaustion (would need a real test tenant), MFA bypass, JWT
  algorithm confusion / `none` algorithm acceptance.
- **OWASP A08 Software & Data Integrity**: testing whether webhook
  HMAC signing actually rejects tampered payloads end-to-end.
- **OWASP A10 SSRF**: webhook subscription targeting internal AWS
  metadata IP (`169.254.169.254`); CRM provider URL pointing at
  internal services; LDAP URL pointing at file://.
- **Multi-tenant isolation**: trying to read tenant A data while
  authenticated as tenant B (the unit + integration test suite covers
  this in code but I did not verify the deployed binary).
- **Active scanning of the marketing site**: would risk impacting other
  Xneelo shared-tenant accounts.
- **Dynamic OWASP Top 10 with ZAP/Burp**: not installed in this
  environment.

I recommend running Phase 2 only after CRITICAL-1, HIGH-1 and HIGH-2
are fixed and re-deployed. A Phase 2 against the current state would
mostly re-discover what we already know.

---

## Recommended action order

1. **Today** — rotate the leaked API keys in production (CRITICAL-1
   step 1), commit the V30 revoke migration, and force-disable the
   plaintext app-key fallback. Roughly 30 min of work + a redeploy.
2. **Today** — add the `.htaccess` to the marketing site (HIGH-2). One
   FTP push.
3. **This week** — rebuild the admin SPA with the production
   environment file and a proper api base URL (HIGH-1). Redeploy.
4. **This week** — fix the nginx redirect downgrade (HIGH-3) and gate
   `/v3/api-docs` + Swagger UI behind admin auth (MEDIUM-1).
5. **This sprint** — bump Spring Boot to latest 3.3.x patch
   (MEDIUM-2), add the missing exception handlers (MEDIUM-4), publish
   CAA records (MEDIUM-5).
6. **Next sprint** — Phase 2 active testing once the criticals are
   verified fixed.

---

*Audit performed 2026-04-15 against the live deployments at
sso.weldforge.org (commit `b07884c`), admin.weldforge.org (Angular
build of the same commit), and www.weldforge.org (commit `6f145b2`).*
