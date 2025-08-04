<#
.PARAMETER ComputerName
    Target computer name. Defaults to localhost if not specified.
.SYNOPSIS
    Investigates suspicious PowerShell DLL loading by unexpected processes.

.DESCRIPTION
    This script investigates when processes like conhost.exe load PowerShell automation DLLs,
    which may indicate malicious "PowerShell without PowerShell" techniques or legitimate
    but unusual system activity.

.PARAMETER ProcessId
    The Process ID (PID) of the suspicious process that loaded PowerShell DLLs.
    If not provided, defaults to 23864 from the original alert.

.PARAMETER EventTime
    The timestamp when the DLL load event occurred. If not provided, defaults to 
    30 days ago to capture recent activity.

.PARAMETER ProcessName
    The name of the suspicious process that loaded PowerShell DLLs (e.g., "conhost.exe", "notepad.exe").
    If not provided, the script will attempt to determine it from the ProcessId or use generic searches.

.EXAMPLE
    .\Investigate-PowerShellDLLLoad.ps1 -ProcessId 23864 -ProcessName "conhost.exe" -EventTime "2025-08-01 16:02:01"
    
    Investigates PID 23864 (conhost.exe) for PowerShell DLL loading activity around the specified time.

.EXAMPLE
    .\Investigate-PowerShellDLLLoad.ps1 -ProcessId 12345 -ProcessName "notepad.exe"
    
    Investigates PID 12345 (notepad.exe) using default event time (30 days ago) for broader context.

.NOTES
    Designed for SOC analysts investigating Elastic Security alerts for:
    - Rule: "Suspicious PowerShell Engine ImageLoad"
    - Processes like conhost.exe, unusual services, or unknown executables
    - MITRE ATT&CK T1059.001 (PowerShell execution)
#>

param(
    [Parameter(Mandatory=$false)]
    [int]$ProcessId = 23864,
    
    [Parameter(Mandatory=$false)]
    [string]$ProcessName = "",
    
    [Parameter(Mandatory=$false)]
    [datetime]$EventTime = (Get-Date).AddDays(-30),
    
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = $env:COMPUTERNAME
)

Write-Host "=== PowerShell DLL Load Investigation ===" -ForegroundColor Cyan
Write-Host "Target PID: $ProcessId" -ForegroundColor Yellow
Write-Host "Target Process: $(if($ProcessName) {$ProcessName} else {'Unknown'})" -ForegroundColor Yellow
Write-Host "Event Time: $EventTime" -ForegroundColor Yellow
Write-Host "Computer: $ComputerName" -ForegroundColor Yellow
Write-Host ""

# Find process name as needed
if (-not $ProcessName) {
    $RunningProcess = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($RunningProcess) {
        $ProcessName = $RunningProcess.ProcessName + ".exe"
        Write-Host "Auto-detected process name: $ProcessName" -ForegroundColor Cyan
    } else {
        Write-Host "Process not running and name not provided - using generic searches" -ForegroundColor Yellow
    }
}

# 1. Check if the process is still running
Write-Host "[1] Checking if process $ProcessId is still running..." -ForegroundColor Green
Get-Process -Id $ProcessId -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, StartTime, Path, CommandLine

# 2. Look for parent process information around the event time
Write-Host "[2] Searching for process creation events around $EventTime..." -ForegroundColor Green
if ($ProcessName) {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$EventTime.AddMinutes(-5); EndTime=$EventTime.AddMinutes(5)} -ErrorAction SilentlyContinue | 
        Where-Object {$_.Message -like "*$ProcessName*"} | 
        Select-Object TimeCreated, Id, Message | 
        Format-List
} else {
    Write-Host "No process name available - searching for all process creation events in timeframe..." -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$EventTime.AddMinutes(-5); EndTime=$EventTime.AddMinutes(5)} -ErrorAction SilentlyContinue | 
        Select-Object TimeCreated, Id, @{Name='ProcessInfo';Expression={($_.Message -split "`n" | Where-Object {$_ -like "*Process Name:*"}) -join " | "}} | 
        Format-Table -Wrap
}

# 3. Check related Powershell activity
Write-Host "[3] Checking PowerShell operational logs around event time..." -ForegroundColor Green
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; StartTime=$EventTime.AddMinutes(-10); EndTime=$EventTime.AddMinutes(10)} -ErrorAction SilentlyContinue | 
    Select-Object TimeCreated, Id, LevelDisplayName, Message | 
    Format-Table -Wrap

# 4. Look for suspicious process creation
Write-Host "[4] Analyzing process creation patterns..." -ForegroundColor Green
$ProcessFilter = if ($ProcessName) { 
    "*cmd.exe*", "*powershell*", "*$ProcessName*" 
} else { 
    "*cmd.exe*", "*powershell*" 
}

Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$EventTime.AddHours(-1); EndTime=$EventTime.AddHours(1)} -ErrorAction SilentlyContinue | 
    Where-Object {
        $message = $_.Message
        $ProcessFilter | ForEach-Object { if ($message -like $_) { return $true } }
    } |
    Select-Object TimeCreated, @{Name='ProcessInfo';Expression={($_.Message -split "`n" | Where-Object {$_ -like "*Process Name:*" -or $_ -like "*Process Command Line:*"}) -join " | "}} |
    Format-Table -Wrap

# 5. Check for encoded/obfuscated PowerShell
Write-Host "[5] Searching for encoded/obfuscated PowerShell commands..." -ForegroundColor Green
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$EventTime.AddHours(-2); EndTime=$EventTime.AddHours(2)} -ErrorAction SilentlyContinue |
    Where-Object {$_.Message -like "*encoded*" -or $_.Message -like "*-enc*" -or $_.Message -like "*FromBase64*"} |
    Select-Object TimeCreated, Message |
    Format-List

# 6. Look for related scheduled tasks or services 
Write-Host "[6] Checking scheduled tasks with PowerShell/CMD execution..." -ForegroundColor Green
Get-ScheduledTask | Where-Object {$_.Actions.Execute -like "*powershell*" -or $_.Actions.Execute -like "*cmd*"} |
    Select-Object TaskName, State, @{Name='NextRun';Expression={$_.NextRunTime}}, @{Name='Command';Expression={$_.Actions.Execute + " " + $_.Actions.Arguments}} |
    Format-Table -AutoSize

# 7. Check for any WMI/CIM activity 
Write-Host "[7] Checking WMI activity around event time..." -ForegroundColor Green
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; StartTime=$EventTime.AddMinutes(-15); EndTime=$EventTime.AddMinutes(15)} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Format-Table -Wrap

# 8. Verify PowerShell DLL hash/location
Write-Host "[8] Verifying PowerShell DLL integrity..." -ForegroundColor Green
$DLLPath = "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll"
if (Test-Path $DLLPath) {
    $FileHash = Get-FileHash -Path $DLLPath -Algorithm SHA256
    Write-Host "DLL Hash: $($FileHash.Hash)" -ForegroundColor White
    Write-Host "Expected: 0ee8d47fe66360a46dfaa0159309e61d2caa7e75683c8d90c2e628e1a40d3078" -ForegroundColor White
    
    if ($FileHash.Hash -eq "0ee8d47fe66360a46dfaa0159309e61d2caa7e75683c8d90c2e628e1a40d3078") {
        Write-Host "✓ DLL hash matches expected Microsoft signature" -ForegroundColor Green
    } else {
        Write-Host "⚠ WARNING: DLL hash does not match expected value!" -ForegroundColor Red
    }
    
    Get-Item $DLLPath | Select-Object Name, Length, CreationTime, LastWriteTime, VersionInfo
} else {
    Write-Host "⚠ PowerShell DLL not found at expected location" -ForegroundColor Yellow
}
