<#
.SYNOPSIS
  Run a WeldForge JMeter plan headless and generate an HTML dashboard report.

.EXAMPLE
  ./run.ps1 -Plan 02-performance-baseline
  ./run.ps1 -Plan 01-load -P @{ threads = 100; duration = 300 }
  ./run.ps1 -Plan 04-security -Tenant leap

.NOTES
  Targets the LOCAL docker-compose app on http://localhost:8076 by default.
  NEVER point -Host at sso.weldforge.org — load/spike/security traffic against
  production is an attack.
#>
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('01-load','02-performance-baseline','03-spike','04-security')]
  [string]$Plan,
  [string]$JMeterHost = 'localhost',
  [int]$Port = 8076,
  [string]$Scheme = 'http',
  [string]$Tenant = 'leap',
  [hashtable]$P = @{}   # extra -J properties, e.g. @{ threads = 100; duration = 300 }
)

$ErrorActionPreference = 'Stop'
$jmeter = 'C:\dev\tools\jmeter\bin\jmeter.bat'
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $here "results\$Plan-$stamp"
New-Item -ItemType Directory -Force $outDir | Out-Null
$jtl    = Join-Path $outDir 'results.jtl'
$log    = Join-Path $outDir 'jmeter.log'
$report = Join-Path $outDir 'report'

if ($JMeterHost -match 'weldforge\.org') {
  throw "Refusing to run against '$JMeterHost'. These plans are for the LOCAL instance only."
}

$jargs = @(
  '-n','-t', (Join-Path $here "$Plan.jmx"),
  '-l', $jtl, '-j', $log,
  '-e','-o', $report,
  "-Jhost=$JMeterHost", "-Jport=$Port", "-Jscheme=$Scheme", "-Jtenant=$Tenant"
)
foreach ($k in $P.Keys) { $jargs += "-J$k=$($P[$k])" }

Write-Host "Running $Plan against ${Scheme}://${JMeterHost}:$Port (tenant=$Tenant)" -ForegroundColor Cyan
Write-Host "Output: $outDir`n"

& $jmeter @jargs

Write-Host "`nDone. HTML dashboard: $report\index.html" -ForegroundColor Green
Write-Host "Raw JTL: $jtl"
