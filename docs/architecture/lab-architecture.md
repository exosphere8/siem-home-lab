# Lab Architecture

## Context and Goals

This lab simulates a small Security Operations Center on a single laptop. A central Wazuh server collects logs from a Linux and a Windows endpoint, applies detection rules, and presents alerts in a dashboard for investigation.

Design constraints:

- One host with 4 cores / 8 threads and about 12 GB of RAM.
- Everything must stay on an isolated network: lab traffic never reaches the home LAN or the internet as attack traffic.
- Free and open-source tools only.

## Text Diagram

```text
+---------------------------------------------------------------+
|  Windows 11 Pro host (Hyper-V)        10.10.10.1 (gateway/NAT)|
|  - Browser -> Wazuh dashboard                                 |
|  - Git, documentation, safe test-traffic source               |
+------------------------------+--------------------------------+
                               |
          SIEM-Lab internal switch, 10.10.10.0/24
                               |
     +-------------------------+--------------------------+
     |                         |                          |
+----+-------------+  +--------+----------+  +------------+-----+
| wazuh-server     |  | ubuntu-endpoint   |  | win11-endpoint   |
| 10.10.10.10      |  | 10.10.10.20       |  | 10.10.10.30      |
| manager          |  | Wazuh agent       |  | Wazuh agent      |
| indexer          |  | SSH, Nginx,       |  | Security Event   |
| dashboard        |  | (later Suricata)  |  | Logs             |
+------------------+  +-------------------+  +------------------+
```

## Component Roles

| Component | Role |
|---|---|
| Hyper-V | Type 1 hypervisor built into Windows 11 Pro. Runs all lab VMs. |
| SIEM-Lab internal switch | Virtual network connecting the host and the VMs. Not bridged to the physical adapter. |
| Host NAT | Lets VMs download packages through the host, while nothing on the home LAN can reach the VMs. |
| Wazuh manager | Receives agent events, decodes them, and evaluates detection rules. |
| Wazuh indexer | Stores and indexes alerts so they can be searched (OpenSearch-based). |
| Wazuh dashboard | Web interface for alerts, searches, and dashboards. |
| Wazuh agent | Runs on each endpoint, reads local logs, and forwards events to the manager. |

## Network Plan

| Host | IP | Notes |
|---|---|---|
| Host gateway | 10.10.10.1 | Hyper-V internal switch adapter, NAT gateway for the lab |
| wazuh-server | 10.10.10.10 | Static IP; agents are configured to report here |
| ubuntu-endpoint | 10.10.10.20 | Static IP |
| win11-endpoint | 10.10.10.30 | Static IP |
| Reserved | 10.10.10.50 | Optional lightweight test VM |

Key ports:

| Port | Direction | Purpose |
|---|---|---|
| 1514/tcp | Agents -> manager | Event forwarding |
| 1515/tcp | Agents -> manager | Agent enrollment |
| 443/tcp | Host -> server | Wazuh dashboard (HTTPS) |

## Key Decisions and Trade-offs

**Hyper-V instead of VirtualBox.** Windows 11 already runs its own hypervisor for virtualization-based security. VirtualBox and VMware would run in a slower compatibility mode on top of it, and avoiding that would mean turning off Windows security features on the host. Hyper-V is built into Windows 11 Pro, supports Dynamic Memory, and provides a virtual TPM and Secure Boot for the Windows 11 guest. Trade-off: most Wazuh lab tutorials use VirtualBox, so screens and network setup differ.

**Wazuh server at 4 GB instead of the recommended 8 GB.** With about 12 GB on the host, 8 GB for one VM leaves too little for the endpoints. Four GB is enough for two or three agents once the indexer's memory is reduced. Trade-off: slower searches and less headroom.

**Windows endpoint runs only when needed.** It is started for agent enrollment and the Windows-focused project, then shut down. Linux-focused projects run with only the server and the Ubuntu endpoint.

**No Kali VM.** Every planned simulation (failed logins, test file changes, scans of lab VMs) can be generated from the host or a small test VM, which saves 2+ GB of RAM.

**One pinned Wazuh version.** The server and agents run exactly the version in `configs/wazuh-version` (4.14.8), with the packages held. Agents must never be newer than the manager, and a minor release can still change how rules match, so every upgrade is a planned step with a checkpoint and a full re-run of the logtest checklists ([05: Upgrading Wazuh](../setup-guides/05-upgrading-wazuh.md)). Wazuh 5 replaces XML rules with Sigma-format rules evaluated in the indexer, so the lab stays on 4.x until 5.x is generally available. Trade-off: security fixes arrive only when the lab is deliberately upgraded.

**Fixed static IPs.** The Hyper-V "Default Switch" changes its address range after reboots, which would break agent configuration. A dedicated internal switch with NAT keeps addresses stable.

## Resource Plan

| Session type | Running VMs | Approx. RAM used by VMs |
|---|---|---|
| Linux projects (2, 4, 5, 6, 7) | wazuh-server, ubuntu-endpoint | 5-6 GB |
| Windows projects (1, 3) | wazuh-server, win11-endpoint (+ ubuntu if RAM allows) | 6-8 GB |

All VM disks live on the internal NVMe SSD. The Wazuh indexer performs poorly on spinning disks.
