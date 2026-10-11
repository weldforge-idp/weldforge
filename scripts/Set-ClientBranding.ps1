<#
.SYNOPSIS
  Apply per-client login branding to a tenant's OIDC clients from a JSON file.

.DESCRIPTION
  Each tenant's clients can override the tenant's login branding key by key
  (V64, oidc_clients.branding). Setting six of them by hand through the portal
  is six chances to paste the wrong palette into the wrong row, so this does it
  from a file that can be reviewed in a diff.

  Dry run by default. It prints what it WOULD change and exits; nothing is sent
  without -Apply.

  The token never appears on the command line -- it is read from the WF_TOKEN
  environment variable, so it does not land in your shell history.

.PARAMETER Tenant
  Tenant slug, e.g. cwvermaak-tech. Sent as X-WF-Tenant, so the call is
  membership-checked and audited server-side like any cross-tenant admin call.

.PARAMETER File
  JSON object mapping clientId -> branding object. Keys beginning with an
  underscore are treated as notes and skipped.

.PARAMETER BaseUrl
  Defaults to production. Point at https://staging.weldforge.org to rehearse.

.EXAMPLE
  $env:WF_TOKEN = '<paste admin access token>'
  ./scripts/Set-ClientBranding.ps1 -Tenant cwvermaak-tech -File scripts/branding/cwvermaak-tech.json
  # review the plan, then:
  ./scripts/Set-ClientBranding.ps1 -Tenant cwvermaak-tech -File scripts/branding/cwvermaak-tech.json -Apply
  Remove-Item Env:WF_TOKEN
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Tenant,
    [Parameter(Mandatory = $true)][string] $File,
    [string] $BaseUrl = 'https://sso.weldforge.org',
    [switch] $Apply
)

$ErrorActionPreference = 'Stop'

if (-not $env:WF_TOKEN) {
    Write-Error "WF_TOKEN is not set. Run:  `$env:WF_TOKEN = '<admin access token>'"
    exit 1
}
if (-not (Test-Path $File)) { Write-Error "No such file: $File"; exit 1 }

$headers = @{
    'Authorization' = "Bearer $($env:WF_TOKEN)"
    'X-WF-Tenant'   = $Tenant
    'Content-Type'  = 'application/json'
}

$payloads = Get-Content $File -Raw | ConvertFrom-Json

Write-Host ""
Write-Host "Tenant   : $Tenant"
Write-Host "Target   : $BaseUrl"
Write-Host "Mode     : $(if ($Apply) { 'APPLY' } else { 'dry run (use -Apply to write)' })"
Write-Host ""

# Which clients actually exist, and their numeric ids. Done once: the update
# endpoint is keyed by id, while the file is keyed by clientId, which is the
# name a person recognises.
try {
    $clients = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/admin/oidc/clients" -Headers $headers
} catch {
    Write-Error "Could not list clients for '$Tenant'. $($_.Exception.Message)"
    Write-Host  "A 401 means the token has expired; a 403/404 means it has no admin membership in that tenant."
    exit 1
}

$byClientId = @{}
foreach ($c in $clients) { $byClientId[$c.clientId] = $c }

Write-Host "$($clients.Count) client(s) in $Tenant : $(($clients.clientId) -join ', ')"
Write-Host ""

$planned = 0; $missing = @(); $applied = 0; $failed = 0

foreach ($prop in $payloads.PSObject.Properties) {
    if ($prop.Name.StartsWith('_')) { continue }   # notes
    $clientId = $prop.Name
    $branding = $prop.Value

    $target = $byClientId[$clientId]
    if (-not $target) {
        $missing += $clientId
        Write-Host ("  SKIP   {0,-20} no such client in this tenant" -f $clientId) -ForegroundColor DarkYellow
        continue
    }

    $keys = ($branding.PSObject.Properties.Name | Sort-Object) -join ', '
    $had  = if ($target.branding) { 'replacing existing' } else { 'currently inherits tenant' }
    Write-Host ("  SET    {0,-20} id={1,-4} {2}" -f $clientId, $target.id, $had)
    Write-Host ("         keys: {0}" -f $keys) -ForegroundColor DarkGray
    $planned++

    if (-not $Apply) { continue }

    # Only `branding` is sent. The server leaves unmentioned fields alone, so
    # this cannot disturb redirect URIs, scopes or TTLs by omission.
    $body = @{ branding = $branding } | ConvertTo-Json -Depth 10 -Compress
    try {
        $null = Invoke-RestMethod -Method Put -Uri "$BaseUrl/api/admin/oidc/clients/$($target.id)" `
                                  -Headers $headers -Body $body
        Write-Host ("         applied") -ForegroundColor Green
        $applied++
    } catch {
        Write-Host ("         FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red
        $failed++
    }
}

Write-Host ""
if (-not $Apply) {
    Write-Host "$planned client(s) would be updated. Nothing was sent." -ForegroundColor Cyan
    if ($missing.Count) { Write-Host "Not found in this tenant: $($missing -join ', ')" -ForegroundColor DarkYellow }
    Write-Host "Re-run with -Apply to write."
    exit 0
}

Write-Host "$applied applied, $failed failed." -ForegroundColor $(if ($failed) { 'Red' } else { 'Green' })

# Read back rather than trusting the write. A 200 on the PUT says the request
# was accepted; this says the value is actually on the row.
Write-Host ""
Write-Host "Verifying..."
$after = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/admin/oidc/clients" -Headers $headers
foreach ($c in $after) {
    if (-not $payloads.PSObject.Properties.Name.Contains($c.clientId)) { continue }
    $state = if ($c.branding) { "branding set ($(($c.branding.PSObject.Properties.Name).Count) keys)" }
             else { "STILL EMPTY" }
    $colour = if ($c.branding) { 'Green' } else { 'Red' }
    Write-Host ("  {0,-20} {1}" -f $c.clientId, $state) -ForegroundColor $colour
}

if ($failed) { exit 1 }
