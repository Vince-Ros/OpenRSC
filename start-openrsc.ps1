[CmdletBinding()]
param(
    [switch]$Tunnel,
    [string]$TunnelTokenFile,
    [switch]$NoElevate,
    [int]$Port = 8787
)

$ErrorActionPreference = 'Stop'
$Project = Split-Path -Parent $MyInvocation.MyCommand.Path
$Config = Join-Path $Project 'config\openrsc.json'
$Data = Join-Path $Project 'data'

if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
    throw "Configuration missing. Run: python scripts\configure_password.py"
}

$account = if ($env:USERDOMAIN) { "$env:USERDOMAIN\$env:USERNAME" } else { $env:USERNAME }
& icacls.exe $Config /inheritance:r /grant:r "${account}:(F)" '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the private configuration ACL.' }
if (-not (Test-Path -LiteralPath $Data -PathType Container)) {
    New-Item -ItemType Directory -Path $Data | Out-Null
}
& icacls.exe $Data /inheritance:r /grant:r "${account}:(OI)(CI)(F)" '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' /T | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the runtime-data ACL.' }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and -not $NoElevate) {
    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"' + $MyInvocation.MyCommand.Path + '"'),
        '-Port', $Port
    )
    if ($Tunnel) { $arguments += '-Tunnel' }
    if ($TunnelTokenFile) { $arguments += @('-TunnelTokenFile', ('"' + $TunnelTokenFile + '"')) }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arguments -WorkingDirectory $Project -WindowStyle Hidden
    Write-Output 'OpenRSC elevation requested; logs will be written under data\logs.'
    exit 0
}

Set-Location -LiteralPath $Project
$python = (Get-Command python -ErrorAction Stop).Source
$arguments = @('-m', 'openrsc', '--config', $Config, '--data', $Data, '--port', $Port)
if ($Tunnel) { $arguments += '--tunnel' }
if ($TunnelTokenFile) { $arguments += @('--tunnel-token-file', $TunnelTokenFile) }
& $python @arguments
exit $LASTEXITCODE
