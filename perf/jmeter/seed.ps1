<#
.SYNOPSIS
  Seed test users into the LOCAL WeldForge instance so the auth-based load and
  security probes (login throughput, account-lockout, rate-limit) have real
  accounts to hit.

.DESCRIPTION
  Registers a small pool of users under a tenant via POST /api/auth/register
  (X-Tenant-Slug header). Registration is rate-limited (5 / 60 min by default),
  so this seeds a handful and pauses; bump APP_RATE_LIMIT_ENABLED=false on the
  app if you need a larger pool quickly.

.EXAMPLE
  ./seed.ps1 -Tenant leap -Count 3
#>
param(
  [string]$BaseUrl = 'http://localhost:8076',
  [string]$Tenant  = 'leap',
  [int]$Count      = 3,
  [string]$Password = 'LoadTest1!pass'   # satisfies min-10 + upper/lower/digit/symbol
)

$ErrorActionPreference = 'Continue'
$headers = @{ 'Content-Type' = 'application/json'; 'X-Tenant-Slug' = $Tenant }

function Register($name, $email) {
  $body = @{ name = $name; email = $email; password = $Password } | ConvertTo-Json -Compress
  try {
    $r = Invoke-WebRequest -Uri "$BaseUrl/api/auth/register" -Method Post -Headers $headers -Body $body -SkipHttpErrorCheck
    "{0,-40} -> HTTP {1}" -f $email, $r.StatusCode
  } catch { "{0,-40} -> ERROR {1}" -f $email, $_.Exception.Message }
}

Write-Host "Seeding $Count users into tenant '$Tenant' at $BaseUrl`n" -ForegroundColor Cyan
# Fixed accounts the plans reference by name:
Register 'Load Test'  'loadtest@example.test'
Register 'Rate Limit' 'ratelimit@example.test'
for ($i = 1; $i -le $Count; $i++) { Register "User $i" "user$i@example.test" }

Write-Host "`nNote: if a tenant has emailVerificationRequired=true, login will be" -ForegroundColor Yellow
Write-Host "blocked until verified. The 'leap'/'default' tenants ship with it off." -ForegroundColor Yellow
