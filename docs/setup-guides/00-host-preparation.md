# 00 - Host Preparation

Checks and changes made on the Windows host before building any VMs.

## 1. Check hardware and existing software

Run in a normal (non-admin) PowerShell window. All commands are read-only.

```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture | Format-List
Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors | Format-List
"RAM (GB): {0:N1}   Hypervisor running: {1}" -f ((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB), (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
Get-PhysicalDisk | Select-Object FriendlyName, MediaType, @{n='SizeGB';e={[math]::Round($_.Size/1GB)}} | Format-Table -AutoSize
git --version
```

What to look for:

- Windows edition must be Pro, Enterprise, or Education for Hyper-V.
- `Hypervisor running: True` with `VirtualizationFirmwareEnabled: False` means virtualization is on, but Windows' own hypervisor already owns it.
- VM disks should go on an SSD.

## 2. Enable Hyper-V

Requires administrator rights and a restart.

1. Start menu -> **Turn Windows features on or off**.
2. Tick **Hyper-V** and both sub-options.
3. Click **OK**, then **Restart now**.

## 3. Verify

```powershell
Get-Service vmms
```

Expected:

```text
Status   Name               DisplayName
------   ----               -----------
Running  vmms               Hyper-V Virtual Machine Management
```

`vmms` exists only when Hyper-V is enabled, which makes it a fast check.
