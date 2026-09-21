<#
.SYNOPSIS
    Black-box checks against a deployed WeldForge environment, to be run before
    promoting staging to production.

.DESCRIPTION
    This is a regression net, not a test suite. Every check here exists because
    the thing it checks was broken in production at some point -- mostly on
    2026-09-13, when a single session found ten live defects. The unit and
    integration suites cover the code; these cover the gap the code cannot see:
    routing, ingress, TLS, headers and configuration, which live in a different
    repository and deploy on a different trigger.

    The common thread in those ten defects is that almost all of them returned
    HTTP 200 while doing the wrong thing. So several checks here assert on
    Content-Type rather than status: an API path answering `text/html` means the
    request fell through to the SPA, and a 200 proves nothing.

    Read-only. It performs no writes and creates no accounts, so it is safe to
    point at production -- and you should, after promoting.

.PARAMETER BaseUrl
    Environment to test. Defaults to staging.

.PARAMETER Tenant
    Tenant slug used for the public protocol endpoints. Staging has no `leap`
    tenant, so it defaults per environment: `default` on staging, `leap` on
    production.

.PARAMETER SkipTls
    Skip certificate expiry checks (they need `openssl` on PATH).

.EXAMPLE
    ./scripts/Test-PrePromotion.ps1
    Check staging before promoting.

.EXAMPLE
    ./scripts/Test-PrePromotion.ps1 -BaseUrl https://sso.weldforge.org
    Check production after promoting.
#>
[CmdletBinding()]
param(
    [string] $BaseUrl = 'https://staging.weldforge.org',
    [string] $Tenant,
    [switch] $SkipTls
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$BaseUrl = $BaseUrl.TrimEnd('/')
if (-not $Tenant) {
    # Staging has never had the `leap` tenant -- it is seeded by V40 only in
    # production. Testing staging against `leap` produces four confusing 404s.
    $Tenant = if ($BaseUrl -match 'staging') { 'default' } else { 'leap' }
}

$script:Failures = @()
$script:Passed   = 0

function Invoke-Probe {
    <# A request that never throws: a transport failure is a result, not an error. #>
    param([string] $Url, [string] $Method = 'GET', [hashtable] $Headers, $Body, [string] $ContentType)

    $params = @{
        Uri                = $Url
        Method             = $Method
        MaximumRedirection = 0
        TimeoutSec         = 30
        SkipHttpErrorCheck = $true
        ErrorAction        = 'Stop'
    }
    if ($Headers)     { $params.Headers = $Headers }
    if ($null -ne $Body) { $params.Body = $Body }
    if ($ContentType) { $params.ContentType = $ContentType }

    try {
        $r = Invoke-WebRequest @params
        return [pscustomobject]@{
            Status  = [int] $r.StatusCode
            Type    = [string] $r.Headers['Content-Type']
            Headers = $r.Headers
            Content = $r.Content
            Error   = $null
        }
    } catch {
        return [pscustomobject]@{
            Status = 0; Type = ''; Headers = @{}; Content = ''
            Error  = $_.Exception.Message
        }
    }
}

function Assert-Check {
    param([string] $Name, [bool] $Ok, [string] $Detail, [string] $Why)

    if ($Ok) {
        $script:Passed++
        Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor Green
    } else {
        $script:Failures += [pscustomobject]@{ Name = $Name; Detail = $Detail; Why = $Why }
        Write-Host ("  FAIL  {0}" -f $Name) -ForegroundColor Red
        Write-Host ("        {0}" -f $Detail) -ForegroundColor DarkGray
        if ($Why) { Write-Host ("        why: {0}" -f $Why) -ForegroundColor DarkGray }
    }
}

Write-Host ""
Write-Host ("WeldForge pre-promotion check  --  {0}  (tenant: {1})" -f $BaseUrl, $Tenant) -ForegroundColor Cyan
Write-Host ("-" * 72)

# ---------------------------------------------------------------------------
Write-Host "`nLiveness and public protocol surface" -ForegroundColor Cyan

$r = Invoke-Probe "$BaseUrl/health"
Assert-Check "GET /health is 200 JSON" `
    ($r.Status -eq 200 -and $r.Type -match 'json') `
    "got $($r.Status) $($r.Type) $($r.Error)" `
    "/health is the public liveness endpoint; HTML here means the API is not routing at all."

foreach ($probe in @(
    @{ Path = "/t/$Tenant/.well-known/openid-configuration"; Type = 'json'; Name = 'OIDC discovery' },
    @{ Path = "/t/$Tenant/oauth2/jwks";                      Type = 'json'; Name = 'JWKS' },
    @{ Path = "/t/$Tenant/saml2/idp/metadata";               Type = 'xml';  Name = 'SAML IdP metadata' }
)) {
    $r = Invoke-Probe "$BaseUrl$($probe.Path)"
    Assert-Check "$($probe.Name) is 200 $($probe.Type)" `
        ($r.Status -eq 200 -and $r.Type -match $probe.Type) `
        "got $($r.Status) $($r.Type) $($r.Error)" `
        "These are what relying parties fetch. A 500 here took the default tenant offline once (PR #47)."
}

# The issuer must match the host it was served from, or every token this tenant
# mints is rejected by a correctly-behaving relying party.
$r = Invoke-Probe "$BaseUrl/t/$Tenant/.well-known/openid-configuration"
if ($r.Status -eq 200 -and $r.Type -match 'json') {
    $disco = $r.Content | ConvertFrom-Json
    Assert-Check "OIDC issuer matches the requested host" `
        ($disco.issuer -like "$BaseUrl*") `
        "issuer is '$($disco.issuer)', expected it to start with '$BaseUrl'" `
        "A mismatched iss fails validation at the relying party, not here."
}

# ---------------------------------------------------------------------------
Write-Host "`nRouting regressions" -ForegroundColor Cyan

# 2026-09-13: the ingress had `path: /t` and Traefik reads pathType: Prefix as a
# STRING prefix, so /tenants matched the OIDC deep-link rule and was answered by
# the API with 403 "Missing or invalid x-app-authorization header". The admin
# portal's own page was unreachable on a refresh or a direct link.
$r = Invoke-Probe "$BaseUrl/tenants"
Assert-Check "/tenants serves the portal, not the API" `
    ($r.Status -eq 200 -and $r.Type -match 'html') `
    "got $($r.Status) $($r.Type)" `
    "A 403 here means the ingress /t rule lost its trailing slash again."

# 2026-09-13: /actuator was routed publicly and SecurityConfig permits
# /actuator/prometheus and /actuator/health by name so in-cluster monitors can
# reach them -- so both answered 200 to the internet with every metric, tenant
# slug and request URI in them. Prometheus scrapes the ClusterIP Service, so
# nothing needs this route.
foreach ($path in '/actuator/prometheus', '/actuator/health', '/actuator/env') {
    $r = Invoke-Probe "$BaseUrl$path"
    $exposed = ($r.Status -eq 200 -and $r.Type -notmatch 'html')
    Assert-Check "$path is not publicly readable" (-not $exposed) `
        "got $($r.Status) $($r.Type)" `
        "200 with a non-HTML body means actuator is exposed to the internet again."
}

# ---------------------------------------------------------------------------
Write-Host "`nRequest handling" -ForegroundColor Cyan

# A form-encoded POST to a JSON endpoint must be refused at the door.
$r = Invoke-Probe "$BaseUrl/api/auth/login" -Method POST -Body 'a=b' -ContentType 'application/x-www-form-urlencoded'
Assert-Check "login rejects the wrong Content-Type with 415" `
    ($r.Status -eq 415) `
    "got $($r.Status)" `
    "The 415 guard is what keeps form-encoded credential stuffing off the JSON endpoints."

# B-API-2: there was no Bean Validation provider, so @Valid was enforced
# nowhere and malformed input produced 500s -- which leak stack detail and read
# as outages.
foreach ($case in @(
    @{ Name = 'malformed JSON';   Body = '{"identifier":' },
    @{ Name = 'empty body';       Body = '' },
    @{ Name = 'missing fields';   Body = '{}' },
    @{ Name = 'wrong value type'; Body = '{"identifier":[],"password":123}' }
)) {
    $r = Invoke-Probe "$BaseUrl/api/auth/login" -Method POST -Body $case.Body -ContentType 'application/json'
    Assert-Check "$($case.Name) does not 500" `
        ($r.Status -ge 400 -and $r.Status -lt 500) `
        "got $($r.Status)" `
        "Any 5xx here is B-API-2 regressing: a client mistake must not be a server error."
}

# Bad credentials must be a clean 401, and must not distinguish 'no such user'
# from 'wrong password' by status.
#
# 429 counts as a pass. Login is rate limited to 10 per 15 minutes, so running
# this script a few times in a row legitimately trips it -- and a 429 still
# proves the point being tested, which is that the endpoint handles an unknown
# account without a 5xx. Treating it as a failure would train the operator to
# ignore a red line on an otherwise healthy environment.
$r = Invoke-Probe "$BaseUrl/api/auth/login" -Method POST -ContentType 'application/json' `
     -Body ('{{"identifier":"no-such-user-{0}@example.invalid","password":"wrong-password"}}' -f (Get-Random))
Assert-Check "unknown account gets 401 (or 429), not 5xx" `
    ($r.Status -in 400, 401, 429) `
    "got $($r.Status)" `
    "A 500 on a bad login is both an information leak and a monitoring false positive."
if ($r.Status -eq 429) {
    Write-Host "        (429 = the login rate limiter is live; re-run in 15 minutes for the 401 path)" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
Write-Host "`nSecurity headers at the edge" -ForegroundColor Cyan

$r = Invoke-Probe "$BaseUrl/health"
if ($r.Status -eq 200) {
    foreach ($h in @(
        @{ Name = 'X-Content-Type-Options'; Expect = 'nosniff' },
        @{ Name = 'X-Frame-Options';        Expect = 'DENY' },
        @{ Name = 'Strict-Transport-Security'; Expect = 'max-age' }
    )) {
        $value = if ($r.Headers.ContainsKey($h.Name)) { ($r.Headers[$h.Name] -join ' ') } else { '' }
        Assert-Check "$($h.Name) is set" `
            ($value -match [regex]::Escape($h.Expect)) `
            "got '$value'" `
            "These are applied once at the edge; API responses bypass nginx entirely and would lose them."
    }

    # CONF-7.2: weldforge-auth sends `same-origin` itself -- NOT no-referrer.
    # Both keep protocol URLs (codes, state, SAML payloads) out of Referer to
    # third parties. But under no-referrer a browser posts "Origin: null" even
    # on a same-origin form submit, CORS refuses it, and the OIDC consent form
    # answered 403 in production from 2026-09-10 to 2026-09-21.
    # Traefik OVERWRITES this header, so a referrerPolicy in the edge middleware
    # would silently replace it with something else.
    $ref = if ($r.Headers.ContainsKey('Referrer-Policy')) { ($r.Headers['Referrer-Policy'] -join ' ') } else { '' }
    Assert-Check "Referrer-Policy is same-origin (not no-referrer)" `
        ($ref -eq 'same-origin') `
        "got '$ref'" `
        "no-referrer makes browsers send Origin: null on same-origin POSTs and breaks the consent form. Anything else here means the edge middleware is overwriting the app's header."
}

# ---------------------------------------------------------------------------
Write-Host "`nBrowser form submission" -ForegroundColor Cyan

# The consent form POSTs to /authorize/decide from a page this service renders.
# A browser sends that page's own origin -- or "null", under no-referrer. curl
# sends no Origin at all, which is exactly why every earlier check passed while
# real users got 403. So test the two Origins a browser can actually send.
# An empty body is enough: past CORS it fails on a missing parameter, which is
# the point -- it reached the controller.
$decide = "$BaseUrl/t/$Tenant/oauth2/authorize/decide"
$selfOrigin = ([Uri]$BaseUrl).GetLeftPart([UriPartial]::Authority)

$r = Invoke-Probe -Method Post -Url $decide -Headers @{ Origin = $selfOrigin } -ContentType 'application/x-www-form-urlencoded' -Body ''
$body = if ($r.Content) { [string]$r.Content } else { '' }
Assert-Check "consent POST with the site's own Origin passes CORS" `
    ($r.Status -ne 403 -or $body -notmatch 'Invalid CORS request') `
    "HTTP $($r.Status): $($body.Substring(0, [Math]::Min(80, $body.Length)))" `
    "A browser submitting the consent form sends this Origin. A CORS 403 here means no first-time sign-in can complete."

$r = Invoke-Probe -Method Post -Url $decide -Headers @{ Origin = 'null' } -ContentType 'application/x-www-form-urlencoded' -Body ''
$body = if ($r.Content) { [string]$r.Content } else { '' }
Assert-Check "Origin: null is still refused (it must not be trusted)" `
    ($r.Status -eq 403) `
    "HTTP $($r.Status)" `
    "Sandboxed iframes and data:/file: documents send 'null'. Trusting it with credentials would be a hole. The fix is the Referrer-Policy above, not this."

# ---------------------------------------------------------------------------
Write-Host "`nPer-tenant subdomain" -ForegroundColor Cyan

# Wildcard DNS + TLS went live with the k3s move. Emailed links (password
# resets, invites) are built on these hosts, so if they stop resolving or the
# wildcard SAN is dropped, every emailed link lands on a handshake failure --
# and the apex keeps working, so nothing else notices.
$apexHost   = ([uri]$BaseUrl).Host
$tenantHost = "$Tenant.$apexHost"
$r = Invoke-Probe "https://$tenantHost/login"
Assert-Check "https://$tenantHost/login resolves and serves" `
    ($r.Status -eq 200 -and $r.Type -match 'html') `
    "got $($r.Status) $($r.Type) $($r.Error)" `
    "DNS wildcard resolves before TLS completes, so a missing SAN fails at handshake, not with a 404."

if (-not $SkipTls) {
    if (Get-Command openssl -ErrorAction SilentlyContinue) {
        foreach ($h in $apexHost, $tenantHost) {
            # Wrapped: a certificate this script cannot parse must not abort the
            # run and leave the earlier results looking like a pass.
            try {
                $out = (& cmd /c "echo. | openssl s_client -servername $h -connect ${h}:443 2>nul | openssl x509 -noout -enddate 2>nul")
                if ($out -match 'notAfter=(.+)') {
                    # openssl prints "Nov 28 13:11:25 2026 GMT", which the current
                    # culture will not parse -- and the day is space-padded, so both
                    # the single- and double-space forms have to be accepted. The
                    # format list must be cast to [string[]] or PowerShell picks the
                    # single-format overload and passes the array as one string.
                    $raw = ($Matches[1].Trim() -replace '\s*GMT\s*$', '')
                    $formats = [string[]]@('MMM d HH:mm:ss yyyy', 'MMM  d HH:mm:ss yyyy', 'MMM dd HH:mm:ss yyyy')
                    $expiry = [datetime]::ParseExact(
                        $raw, $formats,
                        [System.Globalization.CultureInfo]::InvariantCulture,
                        [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
                        [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                    $days = [int]($expiry - [datetime]::UtcNow).TotalDays
                    Assert-Check "TLS for $h has more than 10 days left" ($days -gt 10) `
                        "expires in $days days ($raw UTC)" `
                        "cert-manager renews at 30 days; under 10 means renewal has been failing for weeks."
                } else {
                    Assert-Check "TLS for $h is readable" $false "openssl returned no notAfter" ''
                }
            } catch {
                Assert-Check "TLS for $h is readable" $false "could not read or parse the certificate: $($_.Exception.Message)" ''
            }
        }
    } else {
        Write-Host "  SKIP  TLS expiry (openssl not on PATH)" -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------
Write-Host "`nDeployed version" -ForegroundColor Cyan

# The single most common deploy mistake here is believing a change is live when
# it is not: images publish on merge, but nothing reaches the cluster until
# someone bumps newTag in the infrastructure repo. This reads the tag actually
# running so the operator can compare it against the commit they meant to ship.
$infraOverlay = Join-Path (Split-Path $PSScriptRoot -Parent) '..' |
                Join-Path -ChildPath 'infrastructure/apps/weldforge/overlays'
$envName = if ($BaseUrl -match 'staging') { 'staging' } else { 'production' }
$overlayFile = Join-Path $infraOverlay "$envName/kustomization.yaml"

if (Test-Path $overlayFile) {
    $tag = (Select-String -Path $overlayFile -Pattern 'newTag:\s*(\S+)' |
            Select-Object -First 1).Matches.Groups[1].Value
    Write-Host ("  INFO  infrastructure overlay pins {0} to {1}" -f $envName, $tag) -ForegroundColor DarkGray
    Write-Host  "        Confirm that is the commit you intend to promote." -ForegroundColor DarkGray
} else {
    Write-Host ("  INFO  infrastructure repo not found next to this one; skipping the version read.") -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
Write-Host ""
Write-Host ("-" * 72)
if ($script:Failures.Count -eq 0) {
    Write-Host ("ALL CLEAR  --  {0} checks passed against {1}" -f $script:Passed, $BaseUrl) -ForegroundColor Green
    Write-Host ""
    exit 0
}

Write-Host ("{0} passed, {1} FAILED against {2}" -f $script:Passed, $script:Failures.Count, $BaseUrl) -ForegroundColor Red
Write-Host ""
foreach ($f in $script:Failures) {
    Write-Host ("  * {0}" -f $f.Name) -ForegroundColor Red
    Write-Host ("      {0}" -f $f.Detail) -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "Do not promote until these are understood." -ForegroundColor Yellow
Write-Host ""
exit 1
