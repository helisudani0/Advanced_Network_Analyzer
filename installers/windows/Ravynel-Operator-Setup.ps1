param(
  [string]$InstallPath = ""
)

$ErrorActionPreference = "Stop"

function Pause-And-Exit {
  param([int]$Code = 1)
  Write-Host ""
  Read-Host "Press Enter to close"
  exit $Code
}

function Find-RavynelRoot {
  param([string]$RequestedPath)

  $candidates = @()
  if ($RequestedPath) { $candidates += $RequestedPath }
  $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
  $candidates += $scriptDir
  $candidates += (Split-Path -Parent $scriptDir)
  $candidates += (Get-Location).Path
  $candidates += (Join-Path $HOME "Desktop\Projects\Ravynel-Security")
  $candidates += (Join-Path $HOME "Desktop\Ravynel-Security")
  $candidates += (Join-Path $HOME "Downloads\Ravynel-Security")

  foreach ($candidate in $candidates | Select-Object -Unique) {
    if (-not $candidate) { continue }
    $appPath = Join-Path $candidate "app.py"
    if (Test-Path $appPath) { return (Resolve-Path $candidate).Path }
  }
  return ""
}

$root = Find-RavynelRoot -RequestedPath $InstallPath
if (-not $root) {
  Write-Host "Ravynel installation folder was not found automatically." -ForegroundColor Yellow
  $manual = Read-Host "Paste the full Ravynel-Security folder path"
  $root = Find-RavynelRoot -RequestedPath $manual
}

if (-not $root) {
  Write-Host "Could not find app.py. This bootstrap must be pointed at an installed Ravynel folder." -ForegroundColor Red
  Pause-And-Exit 1
}

$launcher = Join-Path $root "scripts\start-ravynel.ps1"
if (Test-Path $launcher) {
  Write-Host "Launching Ravynel from $root" -ForegroundColor Green
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $launcher
  Pause-And-Exit $LASTEXITCODE
}

Write-Host "Launching Ravynel live analyzer from $root" -ForegroundColor Green
Set-Location $root
& python app.py dashboard
Pause-And-Exit $LASTEXITCODE
