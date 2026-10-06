# Project 4: File-integrity monitoring

**Status:** rules written and statically validated in CI; lab validation pending.
**Rules:** [`detections/linux/100300-file-integrity.xml`](../../detections/linux/100300-file-integrity.xml),
[`detections/windows/100350-file-integrity.xml`](../../detections/windows/100350-file-integrity.xml)

## Objective

Alert in real time when files that grant access or run code change. Generic "a file changed"
alerts are ignored quickly; these rules say *which kind* of change it is and why it matters.

| Rule | Level | Path | ATT&CK |
|---|---|---|---|
| 100300 | 12 | `/etc/passwd`, `shadow`, `group`, `gshadow` | T1098 |
| 100301 | 12 | `/etc/sudoers`, `/etc/sudoers.d/*` | T1548.003 |
| 100302 | 10 | `~/.ssh/authorized_keys` (root and users) | T1098.004 |
| 100303 | 10 | `/etc/crontab`, `/etc/cron.*/`, `/var/spool/cron/` | T1053.003 |
| 100304 | 10 | systemd `.service` / `.timer` units | T1543.002 |
| 100305 | 10 | script files under `/var/www` | T1505.003 |
| 100350 | 10 | Windows Startup folders | T1547.001 |
| 100351 | 10 | script files under the IIS web root | T1505.003 |

## Configuration

The agent configs monitor these paths continuously
([Linux](../../configs/sanitized/wazuh/agent-linux-ossec.conf),
[Windows](../../configs/sanitized/wazuh/agent-windows-ossec.conf)): directories in real-time
(inotify) mode, and single files such as `/etc/passwd` in *whodata* mode (auditd), because
real-time mode only works on directories. Whodata also records **who** changed the file
(`syscheck.audit.login_user`, `process_name`), which answers the first investigation question.
`report_changes` (content diffs in the alert) is on for sudoers, cron, systemd and the web root,
and deliberately **off for `/etc/shadow`**, so password hashes never end up in alert data.

## Validate with harmless changes

On `ubuntu-endpoint`. Every change is a comment or an empty file, and every one is reverted:

```bash
# 100303: a cron file containing only a comment (runs nothing)
echo "# project 4 validation" | sudo tee /etc/cron.d/lab-fim-test >/dev/null
sudo rm /etc/cron.d/lab-fim-test

# 100302: a comment line in your own authorized_keys (sshd ignores comments)
echo "# project 4 validation" >> ~/.ssh/authorized_keys
sed -i '/# project 4 validation/d' ~/.ssh/authorized_keys

# 100305: an empty file with a script extension under the web root
sudo touch /var/www/html/lab-fim-test.php
sudo rm /var/www/html/lab-fim-test.php
```

On `win11-endpoint`, an empty text file in your Startup folder triggers 100350:

```powershell
$startup = [Environment]::GetFolderPath('Startup')
New-Item -Path (Join-Path $startup 'lab-fim-test.txt') -ItemType File | Out-Null
Remove-Item -Path (Join-Path $startup 'lab-fim-test.txt')
```

Expected alerts per step:

| Step | Alerts |
|---|---|
| cron file added, then deleted | 100303 twice (the rule also covers deletions) |
| authorized_keys line appended, then removed | 100302 twice (both are modifications) |
| web-root file added, then deleted | 100305, then built-in 553 (100305 ignores deletions) |
| Startup folder file added, then deleted | 100350, then built-in 553 |

## Investigation playbook

1. Read the diff (`syscheck.diff`) when `report_changes` is on: what was added?
2. Who changed it? Match the time against `auth.log` sessions and sudo commands (Project 5).
3. A new key in `authorized_keys`, or a cron job nobody planned: remove it, then investigate
   how the attacker got write access, because they still have it.

## Validation checklist

- [ ] 100303, 100302 and 100305 observed on Linux
- [ ] 100350 observed on Windows (Wazuh reports Windows paths in lower case)
- [ ] If `<field name="file">` does not match on this Wazuh version, note the field name
      shown in the alert JSON here: ____
