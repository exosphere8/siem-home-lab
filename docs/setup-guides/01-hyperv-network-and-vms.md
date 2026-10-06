# 01: Hyper-V network and VMs

Builds the isolated network and the three VMs from the
[architecture](../architecture/lab-architecture.md). Prerequisite: [00: Host preparation](00-host-preparation.md).

All scripts support `-WhatIf` (a dry run that changes nothing) and `-Verbose`. Run them from an
**elevated** PowerShell in the repository root. Windows blocks local scripts by default, so
allow them for the current window only (the setting ends when the window closes):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## 1. Network: internal switch, gateway, NAT

```powershell
.\scripts\hyperv\New-LabNetwork.ps1 -WhatIf     # review
.\scripts\hyperv\New-LabNetwork.ps1 -Verbose    # apply
```

The script is idempotent. Verify:

```powershell
Get-VMSwitch -Name SIEM-Lab
Get-NetIPAddress -InterfaceAlias 'vEthernet (SIEM-Lab)' -AddressFamily IPv4
Get-NetNat -Name SIEM-Lab-NAT
```

Expected: an `Internal` switch, `10.10.10.1/24` on its adapter, and a NAT for `10.10.10.0/24`.

## 2. VMs

Download the Ubuntu Server LTS and Windows 11 ISOs from their official sites, then:

```powershell
.\scripts\hyperv\New-LabVM.ps1 -Role WazuhServer       -IsoPath D:\iso\ubuntu-server.iso -WhatIf
.\scripts\hyperv\New-LabVM.ps1 -Role WazuhServer       -IsoPath D:\iso\ubuntu-server.iso
.\scripts\hyperv\New-LabVM.ps1 -Role UbuntuEndpoint    -IsoPath D:\iso\ubuntu-server.iso
.\scripts\hyperv\New-LabVM.ps1 -Role Windows11Endpoint -IsoPath D:\iso\windows11.iso
```

| Role | VM | vCPU | Memory | Disk | Notes |
|---|---|---|---|---|---|
| `WazuhServer` | wazuh-server | 4 | 4 GB fixed | 60 GB | Secure Boot with the Microsoft UEFI CA template (required for Linux) |
| `UbuntuEndpoint` | ubuntu-endpoint | 2 | 1-2 GB dynamic | 25 GB | Same template |
| `Windows11Endpoint` | win11-endpoint | 2 | 2-4 GB dynamic | 64 GB | Microsoft Windows template plus a virtual TPM (Windows 11 requires one) |

The script refuses to overwrite an existing VM or disk, and turns off automatic checkpoints so
disk space is not consumed silently.

## 3. Install the guests

Start a VM and open its console: `Start-VM wazuh-server; vmconnect localhost wazuh-server`.

**Ubuntu (both Linux VMs).** Choose a minimal install with OpenSSH server. The SIEM-Lab
switch has no DHCP server, so the VM has no network yet. Either enter the static address on
the installer's network screen, or after the first boot type the matching file from
[`configs/sanitized/netplan/`](../../configs/sanitized/netplan/) into the console (it is
eight lines):

```bash
sudo nano /etc/netplan/50-lab.yaml        # contents of wazuh-server.yaml / ubuntu-endpoint.yaml
sudo chmod 600 /etc/netplan/50-lab.yaml
sudo netplan try                                           # reverts automatically if you lose access
sudo apt update && sudo apt full-upgrade -y
sudo timedatectl set-timezone UTC                          # one time zone across the lab keeps timelines simple
```

**Windows 11.** Install normally with a local account. Then set the static address
(10.10.10.30/24, gateway 10.10.10.1, DNS 1.1.1.1):

```powershell
New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 10.10.10.30 -PrefixLength 24 -DefaultGateway 10.10.10.1
Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 1.1.1.1
```

## 4. Verify connectivity and isolation

From each VM, the host gateway and the internet must be reachable:

```bash
ping -c 2 10.10.10.1      # host gateway: replies
ping -c 2 1.1.1.1         # internet through NAT: replies
```

What NAT does and does not isolate:

- **Inbound is closed.** Nothing on the home LAN can open a connection to 10.10.10.0/24: the
  lab subnet is not routed on your LAN. Check it from another device on the LAN, such as a
  phone: `10.10.10.20` must not answer.
- **Outbound is open.** VMs reach the internet, and also the home LAN, through the host's NAT.
  That is why every validation step in this repository targets lab addresses (10.10.10.x)
  only. If you want the VMs fully cut off from the LAN, add a Windows Firewall rule on the host
  that blocks traffic from 10.10.10.0/24 to your LAN range.

## 5. Day-to-day

Start only what a session needs (see "Resource Plan" in the architecture doc):

```powershell
.\scripts\hyperv\Set-LabState.ps1 -LabProfile Linux -State Running
.\scripts\hyperv\Set-LabState.ps1 -LabProfile Linux -State Off
```

Next: [02: Wazuh server](02-wazuh-server.md).
