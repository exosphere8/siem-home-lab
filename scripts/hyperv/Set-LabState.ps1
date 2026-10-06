#Requires -Version 5.1
<#
.SYNOPSIS
    Starts or stops the VMs a lab session needs (see "Resource Plan" in the architecture doc).

.DESCRIPTION
    Profiles:
      Linux    wazuh-server + ubuntu-endpoint                 (projects 2, 4, 5, 6, 7)
      Windows  wazuh-server + win11-endpoint                  (projects 1, 3)
      All      wazuh-server + ubuntu-endpoint + win11-endpoint

    Start brings the Wazuh server up first and waits for its integration services heartbeat,
    so agents can reconnect as soon as the endpoints boot. Stop shuts down guests gracefully
    (endpoints first, server last). Use -WhatIf for a dry run.

.EXAMPLE
    .\Set-LabState.ps1 -LabProfile Linux -State Running
    .\Set-LabState.ps1 -LabProfile All -State Off
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Linux', 'Windows', 'All')]
    [string] $LabProfile,

    [Parameter(Mandatory)]
    [ValidateSet('Running', 'Off')]
    [string] $State,

    [ValidateRange(30, 900)]
    [int] $TimeoutSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$endpoints = @{
    Linux   = @('ubuntu-endpoint')
    Windows = @('win11-endpoint')
    All     = @('ubuntu-endpoint', 'win11-endpoint')
}[$LabProfile]
$server = 'wazuh-server'

function Wait-Heartbeat {
    param([string] $Name, [int] $Timeout)
    $deadline = (Get-Date).AddSeconds($Timeout)
    while ((Get-Date) -lt $deadline) {
        $hb = Get-VMIntegrationService -VMName $Name -Name 'Heartbeat' -ErrorAction SilentlyContinue
        if ($hb -and $hb.PrimaryStatusDescription -eq 'OK') { return }
        Start-Sleep -Seconds 5
    }
    Write-Warning "$Name did not report a heartbeat within $Timeout s; continuing."
}

if ($State -eq 'Running') {
    foreach ($name in @($server) + $endpoints) {
        $vm = Get-VM -Name $name
        if ($vm.State -eq 'Running') { Write-Verbose "$name already running."; continue }
        if ($PSCmdlet.ShouldProcess($name, 'Start VM')) {
            Start-VM -VM $vm
            if ($name -eq $server) { Wait-Heartbeat -Name $name -Timeout $TimeoutSeconds }
        }
    }
}
else {
    foreach ($name in $endpoints + @($server)) {
        $vm = Get-VM -Name $name
        if ($vm.State -eq 'Off') { Write-Verbose "$name already off."; continue }
        if ($PSCmdlet.ShouldProcess($name, 'Shut down VM (graceful)')) {
            Stop-VM -VM $vm
        }
    }
}

Get-VM -Name (@($server) + $endpoints) | Select-Object Name, State, CPUUsage, MemoryAssigned, Uptime
