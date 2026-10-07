# 05: Upgrading Wazuh

The lab is pinned to one Wazuh version, recorded in
[`configs/wazuh-version`](../../configs/wazuh-version) (currently **4.14.8**). The server
packages and the Linux agent are held with `apt-mark hold`, so nothing upgrades by accident.
This guide covers the two kinds of upgrade, which have very little in common:

- **Within 4.x** (4.14.8 to 4.14.9, say): an in-place package upgrade. Routine, but it can
  still change how rules match.
- **4.x to 5.x**: not an upgrade at all. Wazuh 5 needs a new deployment and cannot load
  XML rules. The lab's detections are already rewritten for it in
  [`detections/wazuh5`](../../detections/wazuh5/); this guide shows how to move.

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

## Migrating to Wazuh 5

As of 7 October 2026, Wazuh 5.0.0 is at its first release candidate
([v5.0.0-rc1](https://github.com/wazuh/wazuh/releases/tag/v5.0.0-rc1), 5 October 2026). The
lab's detections are already ported: the
[Wazuh 5 content pack](../../detections/wazuh5/README.md) and `siemlab` are validated in
CI. Run the migration on 5.0 once it is generally available. The release candidate installs
from a staging repository, so use it only on a VM you are ready to throw away.

What Wazuh says ([migration guide](https://github.com/wazuh/wazuh-documentation/tree/5.0.0/source/migration-to-5x),
[rule migration guide](https://github.com/wazuh/wazuh/blob/v5.0.0-rc1/docs/guide/migration/rules-4x-to-5x.md)),
and what this lab does about it:

| Wazuh 5 | In this lab |
|---|---|
| No in-place upgrade: a new deployment, with 4.x kept running until 5.x is validated | A second server VM, `wazuh5-server` (10.10.10.11), for the parallel run |
| XML rules and decoders cannot be migrated; rules are Sigma-format YAML, checked against the Wazuh Common Schema | All 33 rules rewritten in [`detections/wazuh5`](../../detections/wazuh5/), mapped one by one in its `migration.yml` |
| No `frequency`, `timeframe` or rule chaining; no correlation rules ship with 5.0 | The four counting rules moved into `siemlab correlate`, which runs them on Wazuh 5 findings |
| Every matching rule writes its own finding | `siemlab` merges findings of the same event before counting |
| Rules are loaded and tested through the Content Manager API (draft, test, custom spaces) | `siemlab wazuh5 deploy` creates them, runs the logtest cases, and promotes only if all pass |
| Configuration moves from `/var/ossec/etc/ossec.conf` to `/var/wazuh-manager/etc/wazuh-manager.conf`; agent enrollment needs TLS 1.3 | Recreate the settings by hand; never copy the 4.x file |
| 4.x agents connect, but FIM, SCA and inventory are not fully supported until they are upgraded | Project 4 (FIM) is validated only after the agents are on 5.x |

### 1. Build the 5.x server next to the 4.x one

12 GB of RAM fits two 4 GB servers and the Ubuntu endpoint, not the Windows endpoint as well,
so the parallel run is a Linux-only session:

```powershell
.\scripts\hyperv\New-LabVM.ps1 -Role Wazuh5Server -IsoPath D:\iso\ubuntu-server.iso
.\scripts\hyperv\Set-LabState.ps1 -LabProfile Migration -State Running
```

Install Ubuntu as in [01](01-hyperv-network-and-vms.md), with
[`wazuh5-server.yaml`](../../configs/sanitized/netplan/wazuh5-server.yaml) as its netplan
file. Then install Wazuh 5 with the all-in-one assistant from the
[5.x quickstart](https://documentation.wazuh.com/current/quickstart.html), apply the same
1 GB indexer heap and firewall rules as in [02](02-wazuh-server.md) (with the 5.x paths), and
check that the manager, indexer and dashboard are running. The 5.x manager is installed
neither enabled nor started: `sudo systemctl enable --now wazuh-manager`.

### 2. Load and test the content pack

On `wazuh5-server`, from a clone of this repository:

```bash
sudo apt-get install -y python3-venv
python3 -m venv .venv && . .venv/bin/activate && pip install .
siemlab validate --strict
siemlab wazuh5 deploy --dry-run
siemlab wazuh5 deploy --ca /path/to/root-ca.pem          # prompts for the indexer password
```

`deploy` creates the six integrations and their rules in the draft space, promotes them to
the test space, and sends every `logtest.yml` sample through Wazuh's decoders and the rules.
Each case must match exactly the rule titles it lists. The CA is the root certificate from the
installation assistant's certificate bundle; `--insecure` skips verification, for a
throwaway lab VM only. The password can also come from `WAZUH_INDEXER_PASSWORD`, never from
the command line.

A failing case prints what matched. The usual causes, in the order to check them:

1. **The built-in decoder fills a different field.** Run the sample through **Security
   Analytics > Log test** in the dashboard, look at the normalized event, and change the rule
   to the field it shows. This is expected: the rules were written from the documentation,
   not from a running 5.x indexer.
2. **The text is not in `message`.** Some decoders keep the raw line only in
   `event.original`, which the schema does not index. Prefer a decoded field.
3. **A rule matches too much.** `matched_conditions` in the log test shows which condition
   caught the event.

Fix the YAML here, run `siemlab validate`, delete the draft integrations in the dashboard,
and deploy again. When every case passes:

```bash
siemlab wazuh5 deploy --ca /path/to/root-ca.pem --promote-custom
```

Windows and FIM events come from agents, not log files, so they have no logtest samples here;
validate them live once the agents are migrated (step 4).

### 3. Create the detectors

A detector runs the rules of one integration on a schedule. In **Security Analytics >
Detectors > Create detector**, create one per integration: space **Custom**, the
integration, all its rules, and the events index where its events land (find it in
**Discover** by searching for a sample event; it is `wazuh-events-v5-<category>`). A short
interval, such as 1 minute, keeps the delay between an event and its finding small.

### 4. Move the agents

Follow the [agent migration](https://github.com/wazuh/wazuh-documentation/blob/5.0.0/source/migration-to-5x/wazuh-agents.rst)
steps to import the agent registrations from `wazuh-server`, then point each agent at
10.10.10.11 and upgrade it to the 5.x agent of the same version as the manager. Re-run the
live checks in each project page: an SSH brute force, a new account, a changed
`authorized_keys`, a scanner request, and on Windows a failed logon and a cleared log.

### 5. Correlate Wazuh 5 findings

Findings live in the indexer, not in a file. Export them as JSON lines and give them to
`siemlab`, which recognises the format:

```bash
curl -s --cacert /path/to/root-ca.pem -u admin \
  "https://127.0.0.1:9200/wazuh-findings-v5-*/_search?size=10000&sort=@timestamp:asc" \
  | python3 -c 'import json, sys; [print(json.dumps(h["_source"])) for h in json.load(sys.stdin)["hits"]["hits"]]' \
  > findings.json
siemlab correlate findings.json --report-dir reports/
```

A single search returns at most 10,000 findings; for more, narrow it with a time range.

On Wazuh 5 input, `siemlab correlate` also runs the counting that 4.x rules did: a brute force
(6 failed logins from one source within 2 minutes) and content discovery (10 sensitive-path
probes within 1 minute). Without a live lab, try it on the synthetic findings:

```bash
siemlab correlate sample-data/sanitized/findings-wazuh5-synthetic.json
```

It finds the same seven incidents as the 4.x sample.

### 6. Retire 4.x

Once every project's checks pass on 5.x and the agents report only to `wazuh5-server`, export
anything you want to keep from the 4.x dashboard, shut `wazuh-server` down, and keep its VM
for a while before deleting it. Then update `configs/wazuh-version`, the install guides,
and `tests/test_wazuh_version.py`, which still expects a 4.x version.
