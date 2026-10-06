#Requires -Version 5.1
<#
.SYNOPSIS
    Creates the isolated SIEM-Lab network on the Hyper-V host.

.DESCRIPTION
    Builds the network from docs/architecture/lab-architecture.md:
      * an Internal Hyper-V switch (not bridged to any physical adapter);
      * the host's gateway address on that switch (10.10.10.1/24 by default);
      * a NAT so VMs can download packages while nothing on the home LAN can reach them.

    Idempotent: anything that already exists is left alone, so the script is safe to re-run.
    Run with -WhatIf first to see exactly what would change.

.EXAMPLE
    .\New-LabNetwork.ps1 -WhatIf
    .\New-LabNetwork.ps1 -Verbose
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateNotNullOrEmpty()]
    [string] $SwitchName = 'SIEM-Lab',

    [ValidateScript({ [System.Net.IPAddress]::TryParse($_, [ref] $null) })]
    [string] $GatewayAddress = '10.10.10.1',

    [ValidateRange(16, 29)]
    [int] $PrefixLength = 24,

    [ValidateNotNullOrEmpty()]
    [string] $NatName = 'SIEM-Lab-NAT'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-NetworkPrefix {
    param([string] $Address, [int] $Length)
    $bytes = ([System.Net.IPAddress]::Parse($Address)).GetAddressBytes()
    [Array]::Reverse($bytes)
    $value = [BitConverter]::ToUInt32($bytes, 0)
    $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $Length))
    $network = [BitConverter]::GetBytes([uint32]($value -band $mask))
    [Array]::Reverse($network)
    return '{0}/{1}' -f ([System.Net.IPAddress]::new($network)).ToString(), $Length
}

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -and -not $WhatIfPreference) {
    throw 'Run this script from an elevated PowerShell (Run as administrator), or use -WhatIf.'
}
if (-not (Get-Command -Name New-VMSwitch -ErrorAction SilentlyContinue)) {
    throw 'Hyper-V PowerShell module not found. Enable Hyper-V first (docs/setup-guides/00-host-preparation.md).'
}

$prefix = Get-NetworkPrefix -Address $GatewayAddress -Length $PrefixLength
$alias = "vEthernet ($SwitchName)"

# 1. Internal switch
if (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue) {
    Write-Verbose "Switch '$SwitchName' already exists."
}
elseif ($PSCmdlet.ShouldProcess($SwitchName, 'Create internal Hyper-V switch')) {
    New-VMSwitch -Name $SwitchName -SwitchType Internal | Out-Null
    Write-Verbose "Created internal switch '$SwitchName'."
}

# 2. Host gateway address on the switch's virtual adapter
$existing = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -eq $GatewayAddress }
if ($existing) {
    Write-Verbose "$alias already has $GatewayAddress."
}
elseif ($PSCmdlet.ShouldProcess($alias, "Assign $GatewayAddress/$PrefixLength")) {
    New-NetIPAddress -InterfaceAlias $alias -IPAddress $GatewayAddress -PrefixLength $PrefixLength | Out-Null
    Write-Verbose "Assigned $GatewayAddress/$PrefixLength to $alias."
}

# 3. NAT (Windows supports a single NetNat; refuse to clobber someone else's)
$nat = Get-NetNat -Name $NatName -ErrorAction SilentlyContinue
if ($nat) {
    if ($nat.InternalIPInterfaceAddressPrefix -ne $prefix) {
        throw "NAT '$NatName' exists for $($nat.InternalIPInterfaceAddressPrefix), expected $prefix. Fix it manually."
    }
    Write-Verbose "NAT '$NatName' already covers $prefix."
}
else {
    $other = @(Get-NetNat -ErrorAction SilentlyContinue)
    if ($other.Count -gt 0) {
        Write-Warning ("Another NAT exists ({0}). Windows usually allows only one; New-NetNat may fail." -f ($other.Name -join ', '))
    }
    if ($PSCmdlet.ShouldProcess($prefix, "Create NAT '$NatName'")) {
        New-NetNat -Name $NatName -InternalIPInterfaceAddressPrefix $prefix | Out-Null
        Write-Verbose "Created NAT '$NatName' for $prefix."
    }
}

[pscustomobject]@{
    Switch  = $SwitchName
    Gateway = "$GatewayAddress/$PrefixLength"
    Nat     = "$NatName ($prefix)"
}
