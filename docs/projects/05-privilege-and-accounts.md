# Project 5: Linux privilege and account monitoring

**Status:** rules written and statically validated in CI; lab validation pending.
**Rules:** [`detections/linux/100400-privilege-and-accounts.xml`](../../detections/linux/100400-privilege-and-accounts.xml),
Sigma [`lnx_user_added_to_admin_group.yml`](../../detections/sigma/linux/lnx_user_added_to_admin_group.yml)

## Objective

Detect the changes an intruder makes to stay in and become root: new accounts, accounts added
to `sudo`/`admin`/`wheel`, interactive root shells through sudo, and repeated sudo failures.

| Rule | Level | Fires when | ATT&CK |
|---|---|---|---|
| 100400 | 8 | A user or group is created (built-in `adduser` group) | T1136.001 |
| 100401 | 12 | `usermod`/`gpasswd` adds an account to sudo, admin or wheel | T1098 |
| 100402 | 10 | `sudo` starts an interactive shell or `su` | T1548.003 |
| 100403 | 10 | sudo reports repeated incorrect passwords | T1548.003 |

## Validate with wazuh-logtest

```text
Oct  5 10:12:01 ubuntu-endpoint useradd[2412]: new user: name=lab-temp, UID=1002, GID=1002, home=/home/lab-temp, shell=/bin/bash, from=/dev/pts/0
Oct  5 10:12:10 ubuntu-endpoint usermod[2419]: add 'lab-temp' to group 'sudo'
Oct  5 10:12:30 ubuntu-endpoint sudo:  labadmin : TTY=pts/0 ; PWD=/home/labadmin ; USER=root ; COMMAND=/bin/bash
```

| Line | Expected |
|---|---|
| useradd | 100400 |
| usermod | 100401 (if a built-in rule wins, add its ID as `<if_sid>` and re-test) |
| sudo | 100402 |

## Validate with routine administration

```bash
sudo useradd -m lab-temp            # 100400
sudo usermod -aG sudo lab-temp      # 100401
sudo -i                             # 100402 (then exit)
sudo userdel -r lab-temp            # clean up
```

## Investigation playbook

1. Correlate with Project 4: an account added to `sudo` is often followed by an
   `authorized_keys` change for that account (persistence that survives a password reset).
2. Check who ran the command (`srcuser`) and how they logged in (Project 2 alerts).
3. Remove the account from the group (`sudo gpasswd -d <user> sudo`) and lock it until explained.

## Wazuh 5

Integration [`lab-linux-accounts`](../../detections/wazuh5/lab-linux-accounts/). All four rules port
directly, matching the program in `process.name` and the text in `message`. 100401 no longer
needs to stand outside the rule tree: Wazuh 5 has no tree, so no built-in rule can claim the
event first.

## Validation checklist

- [ ] logtest results recorded for all three lines
- [ ] Live test produced 100400, 100401, 100402
- [ ] Test account removed
- [ ] Wazuh 5: the `lab-linux-accounts` logtest cases pass
- [x] 100400-100403 verified in CI on a real Wazuh 4.14.8 manager (`siemlab wazuh4 logtest`)
