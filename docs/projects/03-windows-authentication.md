# Project 3: Windows authentication monitoring

**Status:** rules written and statically validated in CI; lab validation pending.
**Rules:** [`detections/windows/100200-windows-authentication.xml`](../../detections/windows/100200-windows-authentication.xml),
Sigma rules in [`detections/sigma/windows/`](../../detections/sigma/windows/)

## Objective

Watch the Windows Security log for password guessing, account lockouts, remote desktop
logons, new local accounts, new local administrators and cleared audit logs.

| Event | Rule | Level | ATT&CK |
|---|---|---|---|
| 4625 failed logon | 100200 | 5 | T1110 |
| 8+ × 4625 from one address in 2 min | 100201 | 10 | T1110.001 |
| 4740 account locked out | 100202 | 8 | T1110 |
| 4624 logon type 10 (RDP) | 100203 | 6 | T1021.001 |
| 4720 user account created | 100204 | 8 | T1136.001 |
| 4732 member added to Administrators (S-1-5-32-544) | 100205 | 12 | T1098 |
| 1102 audit log cleared | 100206 | 12 | T1070.001 |

The Sigma versions add two **correlation rules** (Sigma v2): password guessing (event count)
and password spraying (distinct target accounts per source), for other SIEMs.

## Prerequisite

The audit policy from [04: Windows agent](../setup-guides/04-windows-agent.md)
(`Enable-LabAuditPolicy.ps1`). Windows 11 logs these events by default, but a hardening
baseline or Group Policy can turn them off; the script makes the required settings explicit.

## Validate with routine administration

Every event above comes from normal admin work on `win11-endpoint` (elevated PowerShell):

```powershell
# 4720 then 4732: create a temporary account and make it an administrator
$pw = Read-Host -AsSecureString 'Temporary password'
New-LocalUser -Name lab-temp -Password $pw -Description 'Project 3 validation'
Add-LocalGroupMember -Group Administrators -Member lab-temp

# clean up
Remove-LocalGroupMember -Group Administrators -Member lab-temp
Remove-LocalUser -Name lab-temp
```

For 4625, mistype your own password at the VM's sign-in screen. For 100201 the threshold is
eight failures from one address within two minutes. Leave 1102 for last: clearing the
Security log (`wevtutil cl Security`) removes your test evidence, which is exactly why
attackers do it.

| Action | Expected alert |
|---|---|
| `New-LocalUser` | 100204 |
| `Add-LocalGroupMember -Group Administrators` | 100205 |
| Wrong password at sign-in | 100200 |
| `wevtutil cl Security` | 100206 |

## Investigation playbook (100205 or 100206)

1. Who did it? For 4720 and 4732, `win.eventdata.subjectUserName` and its logon session.
   Event 1102 stores the subject under `UserData/LogFileCleared` instead, so open the full
   event in the alert.
2. Was it planned? Check with the owner or the change log. Unplanned means an incident.
3. What happened before? Look for 4625 bursts (100201) and RDP logons (100203) from the same
   address in the preceding hour.
4. Contain: disable the new account (`Disable-LocalUser`), remove it from Administrators, and
   reset the password of the account that made the change.

## Tuning

- 100200 is a building block (level 5). Alert on 100201 and the correlations, not on single typos.
- Exclude service accounts with known-bad stored credentials by `targetUserName` in a child rule
  at level 0, rather than raising thresholds for everyone.

## Wazuh 5

Integration [`lab-windows-auth`](../../detections/wazuh5/lab-windows-auth/). Rules match the event ID in
`event.code`. 100201 (password guessing) is now `siemlab correlate`'s `brute_force`, which
uses one threshold for SSH and Windows: 6 failures within 2 minutes, where 100201 needed 8.
*Windows logon from a network address* (informational) is new, so `siemlab` can see a guess
that worked. The RDP rule reads the logon type from the event text, and the Administrators
rule accepts the group SID either as `group.id` or in the text: confirm which one the
Windows decoder fills with a live event.

## Validation checklist

- [ ] Audit policy applied; `auditpol /get` shows Success/Failure as expected
- [ ] 100204, 100205, 100200 observed in the dashboard
- [ ] 100201 threshold confirmed: ____ failures
- [ ] 100206 observed (run last)
- [ ] Screenshots saved to `docs/screenshots/`
- [ ] Wazuh 5: a failed logon, an RDP logon, a new account, an Administrators change and a cleared log each produced their finding
- [ ] Wazuh 5: the RDP logon type and the group SID are read from: ____
