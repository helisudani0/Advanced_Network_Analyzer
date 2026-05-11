param(
  [string]$ApiHost = "0.0.0.0",
  [int]$ApiPort = 8080,
  [switch]$ShowLogs
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$app = Join-Path $root "app.py"
$logDir = Join-Path $root "logs"

function Get-LanIp {
  try {
    $socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
    $socket.Connect("8.8.8.8", 80)
    $ip = $socket.LocalEndPoint.Address.ToString()
    $socket.Close()
    if ($ip -and -not $ip.StartsWith("127.")) { return $ip }
  } catch {}
  try {
    $candidate = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.PrefixOrigin -ne 'WellKnown' } |
      Select-Object -First 1 -ExpandProperty IPAddress
    if ($candidate) { return $candidate }
  } catch {}
  return "127.0.0.1"
}
function Test-PortOpen {
  param([string]$HostName, [int]$Port)
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $async = $client.BeginConnect($HostName, $Port, $null, $null)
    $connected = $async.AsyncWaitHandle.WaitOne(250, $false)
    if ($connected) { $client.EndConnect($async) }
    $client.Close()
    return $connected
  } catch {
    return $false
  }
}

function Find-FreePort {
  param([string]$HostName, [int]$StartPort)
  for ($port = $StartPort; $port -lt ($StartPort + 80); $port++) {
    if (-not (Test-PortOpen $HostName $port)) { return $port }
  }
  throw "No free local API port found starting at $StartPort."
}

function Require-Command {
  param([string]$Name, [string]$InstallHint)
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show("Missing dependency: $Name`n`n$InstallHint", "Ravynel Security", "OK", "Error") | Out-Null
    exit 1
  }
}

function Show-ErrorDialog {
  param([string]$Message)
  try {
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show($Message, "Ravynel Security", "OK", "Error") | Out-Null
  } catch {
    Write-Host $Message -ForegroundColor Red
  }
}

if (-not (Test-Path $app)) {
  Show-ErrorDialog "Ravynel could not find app.py at $app.`nRun this launcher from the Ravynel installation directory."
  exit 1
}

Require-Command "python" "Install Python 3.12+ and ensure it is available as 'python'."
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$runStamp = Get-Date -Format "yyyyMMdd-HHmmss-fff"
$appOutLog = Join-Path $logDir "app-$runStamp.out.log"
$appErrLog = Join-Path $logDir "app-$runStamp.err.log"
$latestLog = Join-Path $logDir "latest-launch.txt"

$lanIp = Get-LanIp
$selectedPort = Find-FreePort "127.0.0.1" $ApiPort
$appUrl = "http://$lanIp`:$selectedPort/app"
$healthUrl = "http://127.0.0.1`:$selectedPort/health"

try {
  "[$(Get-Date -Format o)] Starting Ravynel on $appUrl`nstdout=$appOutLog`nstderr=$appErrLog" | Set-Content -Path $latestLog -Encoding utf8
} catch {
  # Do not block launch if a text editor or previous process has a log metadata file open.
}

$arguments = @("app.py", "dashboard", "--api-host", $ApiHost, "--api-port", [string]$selectedPort, "--no-browser")
$process = Start-Process -FilePath "python" -ArgumentList $arguments -WorkingDirectory $root -WindowStyle Hidden -PassThru -RedirectStandardOutput $appOutLog -RedirectStandardError $appErrLog

$ready = $false
for ($i = 0; $i -lt 80; $i++) {
  Start-Sleep -Milliseconds 250
  if ($process.HasExited) { break }
  try {
    $response = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 1
    if ($response.StatusCode -eq 200) { $ready = $true; break }
  } catch {
  }
}

if ($ready) {
  Start-Process $appUrl
  if ($ShowLogs) { Start-Process notepad.exe $appOutLog }
  exit 0
}

$err = "Ravynel did not become ready."
if ($process.HasExited) { $err += " The app process exited with code $($process.ExitCode)." }
$err += "`n`nLogs:`n$appOutLog`n$appErrLog"
Show-ErrorDialog $err
if ($ShowLogs) {
  if (Test-Path $appErrLog) { Start-Process notepad.exe $appErrLog }
  if (Test-Path $appOutLog) { Start-Process notepad.exe $appOutLog }
}
exit 1
