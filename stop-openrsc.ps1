[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Project = Split-Path -Parent $MyInvocation.MyCommand.Path
$SupervisorPidFile = Join-Path $Project 'data\openrsc-supervisor.pid'
$ServerPidFile = Join-Path $Project 'data\openrsc.pid'

function Resolve-OpenRSCProcess {
    param(
        [Parameter(Mandatory)] [string] $PidFile,
        [Parameter(Mandatory)] [string] $CommandPattern
    )
    if (-not (Test-Path -LiteralPath $PidFile -PathType Leaf)) { return $null }
    try {
        $RecordedPid = [int](Get-Content -LiteralPath $PidFile -Raw).Trim()
    } catch {
        Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
        return $null
    }
    $Process = Get-CimInstance Win32_Process -Filter "ProcessId=$RecordedPid" -ErrorAction SilentlyContinue
    if ($null -eq $Process) {
        Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
        return $null
    }
    if ($Process.CommandLine -and $Process.CommandLine -notmatch $CommandPattern) {
        throw "PID file $PidFile does not identify the expected OpenRSC process."
    }
    return $Process
}

$Target = Resolve-OpenRSCProcess -PidFile $SupervisorPidFile -CommandPattern '(?i)launcher\.py.*--supervise'
if ($null -eq $Target) {
    $Target = Resolve-OpenRSCProcess -PidFile $ServerPidFile -CommandPattern '(?i)(launcher\.py|openrsc)'
}
if ($null -eq $Target) {
    Write-Output 'OpenRSC is not recording a running process.'
    exit 0
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $MyInvocation.MyCommand.Path + '"')
    ) -WorkingDirectory $Project -WindowStyle Hidden
    Write-Output 'OpenRSC stop elevation requested.'
    exit 0
}

& taskkill.exe /PID $Target.ProcessId /T /F | Out-Null
Remove-Item -LiteralPath $SupervisorPidFile -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $ServerPidFile -Force -ErrorAction SilentlyContinue
Write-Output "Stopped OpenRSC process tree $($Target.ProcessId)."
