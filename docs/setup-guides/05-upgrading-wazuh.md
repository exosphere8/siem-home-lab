# 05: Upgrading Wazuh

The lab is pinned to one Wazuh version, recorded in
[`configs/wazuh-version`](../../configs/wazuh-version) (currently **4.14.8**). The server
packages and the Linux agent are held with `apt-mark hold`, so nothing upgrades by accident.
This guide covers the two kinds of upgrade, which have very little in common:

- **Within 4.x** (4.14.8 to 4.14.9, say): an in-place package upgrade. Routine, but it can
  still change how rules match.
- **4.x to 5.x**: not an upgrade at all. Wazuh 5 needs a new deployment, and none of this
  lab's Wazuh rules can be carried across as they are. The lab stays on 4.x for now.

## Upgrading within 4.x

### Before

1. **Read the release notes for every version you skip**, not only the target. Look for
   decoder and rule changes. Example: 4.14.1 made `user` an alias of the `dstuser` static
   field ([#32107](https://github.com/wazuh/wazuh/pull/32107)), and rule 100103 matches on
   `<user>`. A note like that is a test you need to re-run, not trivia.
2. **Take a checkpoint of each VM.** `New-LabVM.ps1` turns automatic checkpoints off, so
   none exist unless you make one. Stop the server first so the indexer is on disk in a
   consistent state:

   ```powershell
   $tag = 'pre-wazuh-4.14.9'
   Stop-VM -Name wazuh-server
   Checkpoint-VM -Name wazuh-server -SnapshotName $tag
   Checkpoint-VM -Name ubuntu-endpoint -SnapshotName $tag
   Start-VM -Name wazuh-server
   ```

   A checkpoint grows as the VM writes, so keep an eye on free space on the host's SSD and
   delete it once the upgrade is verified (step 6 below).
3. **Save what the upgrade can overwrite** on `wazuh-server`:

   ```bash
   sudo cp /etc/wazuh-indexer/jvm.options /etc/wazuh-indexer/jvm.options.old
   apt list --installed 'wazuh-*' filebeat 2>/dev/null | tee ~/versions-before.txt
   ```

   Export any custom dashboards and saved searches from **Dashboard Management > Saved
   objects**.

### Upgrade

Follow the official
[central components upgrade guide](https://documentation.wazuh.com/current/upgrade-guide/upgrading-central-components.html)
for the exact commands. On an all-in-one server the order is **indexer, manager, Filebeat,
dashboard**. What is specific to this lab:

1. **Release the holds first**, or apt will quietly skip the packages:

   ```bash
   sudo apt-mark unhold wazuh-indexer wazuh-manager wazuh-dashboard filebeat
   ```

2. **Check the indexer heap after the indexer upgrade.** The VM has 4 GB for the indexer,
   manager and dashboard together, so the 1 GB heap from
   [`indexer-jvm.options`](../../configs/sanitized/wazuh/indexer-jvm.options) is not optional:

   ```bash
   grep -E '^-Xm[sx]' /etc/wazuh-indexer/jvm.options      # both must be 1g
   ```

3. **Redeploy and re-test the rules after the manager upgrade.** The deploy script refuses
   anything other than 4.x and warns when the version differs from `configs/wazuh-version`:

   ```bash
   sudo bash scripts/deploy/deploy-rules.sh
   ```

   Then run the `wazuh-logtest` cases from **every** project checklist, not a sample. The
   edge cases matter most, for example six root-only SSH failures must still trigger 100101.
   An upgrade that changes which rule an event ends on breaks counting rules silently: see
   the post-mortem linked from the README.

4. **Hold the packages again** and record the new versions:

   ```bash
   sudo apt-mark hold wazuh-indexer wazuh-manager wazuh-dashboard filebeat
   apt list --installed 'wazuh-*' filebeat 2>/dev/null
   ```

5. **Upgrade the agents last**, to exactly the manager's version and never higher:

   ```bash
   # ubuntu-endpoint
   sudo apt-mark unhold wazuh-agent
   sudo apt-get install -y wazuh-agent=4.14.9-1
   sudo apt-mark hold wazuh-agent
   ```

   On `win11-endpoint`, install the new MSI with the same `msiexec` command as in
   [04: Windows agent](04-windows-agent.md); it upgrades in place and keeps the agent's key.

6. **Close out.** On the server, `sudo /var/ossec/bin/agent_control -l` shows both agents
   Active. Then update `configs/wazuh-version` and the version numbers in guides 02-04 (CI
   fails if they disagree), and remove the checkpoints:

   ```powershell
   Remove-VMCheckpoint -VMName wazuh-server, ubuntu-endpoint -Name 'pre-wazuh-4.14.9'
   ```

### Rolling back

Downgrading Wazuh packages is not a supported path, so roll back by restoring the checkpoint:

```powershell
Restore-VMCheckpoint -VMName wazuh-server -Name 'pre-wazuh-4.14.9' -Confirm:$false
```

Anything indexed after the checkpoint is lost with it. Restore the endpoints too if their
agents were already upgraded: a 4.14.9 agent must not report to a 4.14.8 manager.

## Wazuh 5.x: not yet

As of 7 October 2026, Wazuh 5.0.0 is at its first release candidate
([v5.0.0-rc1](https://github.com/wazuh/wazuh/releases/tag/v5.0.0-rc1), 5 October 2026), and
the latest stable release is 4.14.8. The 5.x
[migration guide](https://github.com/wazuh/wazuh-documentation/tree/5.0.0/source/migration-to-5x)
and [release notes](https://github.com/wazuh/wazuh/releases/tag/v5.0.0-rc1) say:

- 4.x cannot be upgraded in place. 5.x is a **new deployment**, and the old one keeps
  running until the new one is validated.
- **Custom XML rules and decoders cannot be migrated.** 5.x rules are written in Sigma
  format and validated against the Wazuh Common Schema (WCS). They are managed through the
  content management system, not by copying files into a rules directory.
- Detection runs in the indexer: detectors evaluate normalized events at configured intervals
  and produce **findings**, which take the place of 4.x alerts. They are stored in
  `wazuh-findings-v5-*` indices.
- The manager configuration moves from `/var/ossec/etc/ossec.conf` to
  `/var/wazuh-manager/etc/wazuh-manager.conf` and cannot be copied across. Filebeat is gone.
- Agent enrollment requires TLS 1.3. 4.x agents can connect to a 5.x manager, but FIM, SCA,
  inventory, active response and vulnerability detection are not fully supported until the
  agents are upgraded.

What that means for each part of this lab:

| Part of the lab | Impact of 5.x |
|---|---|
| 33 Wazuh XML rules | All rewritten. 26 extend built-in 4.x rules or groups that 5.x does not have. 4 are stateful (frequency or `if_matched_*`: 100101, 100102, 100201, 100504), and the 5.x rule documentation describes no counting or time-window option. 3 extend other custom rules. |
| 11 Sigma rules | The best starting point, but field names must change to WCS fields, and the two Sigma v2 correlation rules have no documented 5.x equivalent. |
| `siemlab validate` | The per-project ID blocks (100100, 100200, ...) do not apply: 5.x rule IDs are UUIDs and severities are names, not levels 0-15. |
| `siemlab correlate` | Reads 4.x `alerts.json` lines. 5.x findings are WCS documents in the indexer, so it needs a new loader. |
| `deploy-rules.sh` | Nothing to copy into. The script detects a 5.x manager and stops. |
| Validation with `wazuh-logtest` | Needs a 5.x replacement, since detection moves from the manager to the indexer. |
| 4 GB server VM | Running 4.x and 5.x side by side does not fit in 12 GB of RAM with the Windows endpoint up. Plan a Linux-only session for the parallel run. |

The plan: stay on 4.14, move to 5.x after it is generally available and its documentation has
settled, and keep the existing Sigma rules as the starting point for the rewrite. The
post-mortem linked from the README goes through what is likely to go wrong.
