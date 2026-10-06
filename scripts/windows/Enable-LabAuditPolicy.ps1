#Requires -Version 5.1
<#
.SYNOPSIS
    Turns on the Windows audit policy that Project 3's detections depend on.

.DESCRIPTION
    Run on win11-endpoint (elevated). Windows 11 audits most of these by default, but hardening
    baselines and Group Policy can switch them off; this makes every setting the lab relies on
    explicit:

      Subcategory                 Events used by the lab rules
      Logon                       4624 (logon, incl. RDP type 10), 4625 (failed logon)
      Account Lockout             4625 for logons refused because the account is locked
      User Account Management     4720 (user created), 4740 (account locked out)
      Security Group Management   4732 (member added to a local group)

    Event 1102 (audit log cleared) is always logged. The Security log is also enlarged to
    256 MB so a busy test session cannot roll over evidence. Use -WhatIf for a dry run.

.EXAMPLE
    .\Enable-LabAuditPolicy.ps1 -WhatIf
    .\Enable-LabAuditPolicy.ps1 -Verbose
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(20, 4096)]
    [int] $SecurityLogSizeMB = 256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -and -not $WhatIfPreference) {
    throw 'Run this script from an elevated PowerShell (Run as administrator), or use -WhatIf.'
}

# GUIDs are locale-independent; subcategory names are translated on non-English Windows.
$subcategories = [ordered]@{
    'Logon'                     = @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true }
    'Account Lockout'           = @{ Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $true }
    'User Account Management'   = @{ Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true }
    'Security Group Management' = @{ Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $false }
}

foreach ($name in $subcategories.Keys) {
    $s = $subcategories[$name]
    $success = if ($s.Success) { 'enable' } else { 'disable' }
    $failure = if ($s.Failure) { 'enable' } else { 'disable' }
    if ($PSCmdlet.ShouldProcess($name, "auditpol success:$success failure:$failure")) {
        & auditpol.exe /set /subcategory:$($s.Guid) /success:$success /failure:$failure | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "auditpol failed for '$name' (exit $LASTEXITCODE)." }
        Write-Verbose "Audit '$name': success=$success failure=$failure"
    }
}

$bytes = [int64] $SecurityLogSizeMB * 1MB
if ($PSCmdlet.ShouldProcess('Security event log', "Set maximum size to $SecurityLogSizeMB MB")) {
    & wevtutil.exe set-log Security /maxsize:$bytes | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "wevtutil failed (exit $LASTEXITCODE)." }
}

if (-not $WhatIfPreference) {
    $guids = ($subcategories.Values | ForEach-Object { $_.Guid }) -join ','
    & auditpol.exe /get "/subcategory:$guids"
}
