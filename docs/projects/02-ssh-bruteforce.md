# Project 2: Linux SSH brute-force detection

**Status:** rules written and statically validated in CI; lab validation pending.
**Rules:** [`detections/linux/100100-ssh-bruteforce.xml`](../../detections/linux/100100-ssh-bruteforce.xml),
Sigma [`lnx_sshd_failed_root_login.yml`](../../detections/sigma/linux/lnx_sshd_failed_root_login.yml)

## Objective

Detect password guessing against SSH on `ubuntu-endpoint`, and above all the moment it
**succeeds**: a successful login from a source that was just failing repeatedly.

| ATT&CK | Technique |
|---|---|
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts (the login that worked) |

## Data source

`/var/log/auth.log` on `ubuntu-endpoint`, collected by the agent
([config](../../configs/sanitized/wazuh/agent-linux-ossec.conf)).

## Detection logic

| Rule | Level | Fires when |
|---|---|---|
| 100100 | 5 | Any failed sshd login (re-labels the built-in failure rules with an ATT&CK mapping) |
| 100101 | 10 | 6+ failures from one source IP within 2 minutes (any account, root included) |
| 100102 | 13 | A successful login from that source within 10 minutes of 100101: likely compromise |
| 100103 | 8 | A failed login as `root` (root SSH login should be disabled) |

## Validate the rules with wazuh-logtest

`wazuh-logtest` runs log lines through the real decoders and rules without any traffic.
On `wazuh-server`, after deploying the rules:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste one line at a time:

```text
Oct  5 10:00:01 ubuntu-endpoint sshd[2301]: Failed password for labadmin from 10.10.10.50 port 40001 ssh2
Oct  5 10:00:03 ubuntu-endpoint sshd[2301]: Failed password for root from 10.10.10.50 port 40002 ssh2
```

| Line | Expected result |
|---|---|
| First | `id: '100100'`, level 5, decoder `sshd` |
| Second | `id: '100103'`, level 8 |

Paste the first line six times in the same session: logtest keeps state, so the sixth one
should report `100101`. Repeat with the root line in a new session: root failures end as 100103
but carry the `ssh_failed_login` group that 100101 counts, so they must trigger it too. Then
paste:

```text
Oct  5 10:01:40 ubuntu-endpoint sshd[2340]: Accepted password for labadmin from 10.10.10.50 port 40100 ssh2
```

Expected: `100102`, level 13. Record the actual results in the checklist below. If a
built-in rule wins instead of 100100, note its ID and adjust the parent in the rule file.

## Investigation playbook (when 100102 fires)

1. **Scope:** which account logged in, from where, and when? (`data.dstuser`, `data.srcip`)
2. **Session activity:** filter the dashboard on the agent and the time after the login for
   `sudo`, new users, `authorized_keys` and cron changes (Projects 4 and 5).
3. **Contain:** lock the account (`sudo passwd -l <user>`), kill its sessions
   (`sudo pkill -KILL -u <user>`) and block the source on the endpoint
   (`sudo ufw deny from <ip>`).
4. **Correlate:** run `siemlab correlate` on the manager's `alerts.json`
   ([Project 8](08-alert-correlation.md)) to see whether the same source touched other hosts.
5. Write the report from the [template](../incident-reports/TEMPLATE.md).

## Tuning

- Raise `frequency` in 100101 if legitimate users trip it, but keep 100102 unchanged: a success
  after many failures is significant at any threshold.
- Hardening that removes the risk entirely: `PasswordAuthentication no` and
  `PermitRootLogin no` in `sshd_config`. Keep the rules as a tripwire for misconfiguration.

## Wazuh 5

Integration [`lab-ssh`](../../detections/wazuh5/lab-ssh/). 100100 and 100103 became *SSH failed login* and
*SSH failed login as root*; a failed root login now produces both findings, and `siemlab`
merges them back into one event. Wazuh 5 rules cannot count, so 100101 (brute force: 6
failures from one source within 2 minutes) and 100102 (a success after it) are now
`siemlab correlate`'s `brute_force` and `credential_compromise`. *SSH successful login*
(informational) is new: without it, `siemlab` would never see the login that ends a brute force.

## Validation checklist

- [ ] Rules deployed with `deploy-rules.sh` (validation passed)
- [ ] logtest: 100100, 100103, 100101 and 100102 each observed
- [ ] logtest: six root-only failures trigger 100101
- [ ] Actual trigger count for 100101 recorded: ____
- [ ] Screenshot of the alerts in the dashboard saved to `docs/screenshots/`
- [ ] Wazuh 5: the `lab-ssh` logtest cases pass (`siemlab wazuh5 deploy`)
- [ ] Wazuh 5: six root-only failures, exported and correlated, give one `brute_force` incident
