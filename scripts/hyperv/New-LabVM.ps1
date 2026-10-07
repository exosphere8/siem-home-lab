#Requires -Version 5.1
<#
.SYNOPSIS
    Creates one lab VM with the sizing from docs/architecture/lab-architecture.md.

.DESCRIPTION
    Roles and their presets:

      Role               Name              vCPU  Memory                 Disk   Secure Boot template
      WazuhServer        wazuh-server      4     4 GB fixed             60 GB  Microsoft UEFI CA (Linux)
      Wazuh5Server       wazuh5-server     4     4 GB fixed             60 GB  Microsoft UEFI CA (Linux)
      UbuntuEndpoint     ubuntu-endpoint   2     1-2 GB dynamic         25 GB  Microsoft UEFI CA (Linux)
      Windows11Endpoint  win11-endpoint    2     4 GB start, 2-4 GB     64 GB  Microsoft Windows + vTPM

    Wazuh5Server is the second server used only while migrating to Wazuh 5, which cannot be
    upgraded in place (docs/setup-guides/05-upgrading-wazuh.md).

    Every VM is Generation 2, attached to the SIEM-Lab switch (create it first with
    New-LabNetwork.ps1), boots from the installer ISO, and has automatic checkpoints off
    so disk space is not silently consumed. Static IPs are set inside the guest
    (see docs/setup-guides/01-hyperv-network-and-vms.md).

    Refuses to touch an existing VM of the same name. Use -WhatIf for a dry run.

.EXAMPLE
    .\New-LabVM.ps1 -Role WazuhServer -IsoPath D:\iso\ubuntu-24.04-live-server-amd64.iso -WhatIf
    .\New-LabVM.ps1 -Role Windows11Endpoint -IsoPath D:\iso\Win11_English_x64.iso -Verbose
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateSet('WazuhServer', 'Wazuh5Server', 'UbuntuEndpoint', 'Windows11Endpoint')]
    [string] $Role,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $IsoPath,

    [string] $SwitchName = 'SIEM-Lab',

    # Defaults to the Hyper-V host's configured virtual hard disk folder.
    [string] $VhdFolder
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$presets = @{
    WazuhServer       = @{ Name = 'wazuh-server'; Cpu = 4; Startup = 4GB; Min = 4GB; Max = 4GB; Dynamic = $false; Disk = 60GB; Template = 'MicrosoftUEFICertificateAuthority'; Tpm = $false }
    Wazuh5Server      = @{ Name = 'wazuh5-server'; Cpu = 4; Startup = 4GB; Min = 4GB; Max = 4GB; Dynamic = $false; Disk = 60GB; Template = 'MicrosoftUEFICertificateAuthority'; Tpm = $false }
    UbuntuEndpoint    = @{ Name = 'ubuntu-endpoint'; Cpu = 2; Startup = 1GB; Min = 1GB; Max = 2GB; Dynamic = $true; Disk = 25GB; Template = 'MicrosoftUEFICertificateAuthority'; Tpm = $false }
    Windows11Endpoint = @{ Name = 'win11-endpoint'; Cpu = 2; Startup = 4GB; Min = 2GB; Max = 4GB; Dynamic = $true; Disk = 64GB; Template = 'MicrosoftWindows'; Tpm = $true }
}
$p = $presets[$Role]

if (-not (Get-Command -Name New-VM -ErrorAction SilentlyContinue)) {
    throw 'Hyper-V PowerShell module not found. Enable Hyper-V first (docs/setup-guides/00-host-preparation.md).'
}
if (Get-VM -Name $p.Name -ErrorAction SilentlyContinue) {
    throw "A VM named '$($p.Name)' already exists. Remove or rename it first; this script never modifies existing VMs."
}
if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue) -and -not $WhatIfPreference) {
    throw "Switch '$SwitchName' not found. Run New-LabNetwork.ps1 first."
}
if (-not $VhdFolder) {
    $VhdFolder = (Get-VMHost).VirtualHardDiskPath
}
$vhdPath = Join-Path $VhdFolder "$($p.Name).vhdx"
if (Test-Path -LiteralPath $vhdPath) {
    throw "Disk '$vhdPath' already exists. Refusing to overwrite it."
}

if (-not $PSCmdlet.ShouldProcess($p.Name, "Create $Role VM ($($p.Cpu) vCPU, $($p.Startup / 1GB) GB, $($p.Disk / 1GB) GB disk)")) {
    return
}

$vm = New-VM -Name $p.Name -Generation 2 -MemoryStartupBytes $p.Startup `
    -NewVHDPath $vhdPath -NewVHDSizeBytes $p.Disk -SwitchName $SwitchName
Set-VMProcessor -VM $vm -Count $p.Cpu
if ($p.Dynamic) {
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $true -MinimumBytes $p.Min -StartupBytes $p.Startup -MaximumBytes $p.Max
}
else {
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $false
}
Set-VM -VM $vm -AutomaticCheckpointsEnabled $false -AutomaticStopAction ShutDown

$dvd = Add-VMDvdDrive -VM $vm -Path $IsoPath -Passthru
Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate $p.Template -FirstBootDevice $dvd

if ($p.Tpm) {
    # Windows 11 requires a TPM 2.0: a local key protector, then the virtual TPM.
    Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
    Enable-VMTPM -VM $vm
}

Write-Verbose "Created $($p.Name). Start it with: Start-VM -Name $($p.Name); vmconnect localhost $($p.Name)"
Get-VM -Name $p.Name | Select-Object Name, State, ProcessorCount, MemoryStartup, Generation
