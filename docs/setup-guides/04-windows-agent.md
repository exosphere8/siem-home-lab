# 04: Windows agent (win11-endpoint)

Run everything below in an **elevated** PowerShell on `win11-endpoint`.

## 1. Install the agent

Download the Windows agent MSI that matches the manager's version from the
[Wazuh packages list](https://documentation.wazuh.com/current/installation-guide/packages-list.html),
then:

```powershell
# -Wait matters: msiexec returns immediately otherwise, before the service exists.
Start-Process msiexec.exe -Wait -ArgumentList '/i .\wazuh-agent.msi /q WAZUH_MANAGER=10.10.10.10 WAZUH_AGENT_NAME=win11-endpoint'
Start-Service -Name WazuhSvc
Get-Service -Name WazuhSvc     # Running
```

## 2. Make the audit policy explicit

A fresh Windows 11 already audits logons, account management and group changes, but local
hardening baselines or Group Policy can switch them off, and then Project 3 goes silent.
The script sets every subcategory the rules depend on explicitly. Copy the repository's
`scripts\windows` folder to the VM and run (the first line allows local scripts for this
window only; Windows blocks them by default):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Enable-LabAuditPolicy.ps1 -WhatIf
.\Enable-LabAuditPolicy.ps1 -Verbose
```

This sets Logon, Account Lockout, User Account Management and Security Group Management
auditing, and enlarges the Security log to 256 MB. Subcategories are set by GUID, so it also
works on non-English Windows.

## 3. Configure FIM

Merge [`configs/sanitized/wazuh/agent-windows-ossec.conf`](../../configs/sanitized/wazuh/agent-windows-ossec.conf)
into `C:\Program Files (x86)\ossec-agent\ossec.conf`, then:

```powershell
Restart-Service -Name WazuhSvc
```

## 4. Verify

On the **server**, `sudo /var/ossec/bin/agent_control -l` lists `win11-endpoint` as Active.
In the dashboard (**Threat Hunting**, agent `win11-endpoint`), sign out and back in on the VM:
a `Windows logon success` event should appear within a minute.

Project 1 is complete when both agents are Active and sending events.
Next: [Project 2](../projects/02-ssh-bruteforce.md).
