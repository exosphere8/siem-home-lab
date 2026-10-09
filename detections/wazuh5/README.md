# Wazuh 5 content pack

The lab's detections rewritten for Wazuh 5. Wazuh 5 cannot load the XML rules in the other
folders of `detections/`: its rules are Sigma-format YAML, they belong to an *integration*,
and the indexer evaluates them against events normalized to the
[Wazuh Common Schema](https://github.com/wazuh/wazuh-indexer-plugins/tree/5.0.0/wcs/stateless/events/main/docs)
(WCS). Every match becomes a *finding* in `wazuh-findings-v5-*`.

**Status:** written against the Wazuh 5.0.0 documentation and the
[4.x-to-5.x rule migration guide](https://github.com/wazuh/wazuh/blob/v5.0.0-rc1/docs/guide/migration/rules-4x-to-5x.md)
(5.0.0 was at release candidate 1 on 7 October 2026). Every rule is validated in CI; none has
run on a Wazuh 5 indexer yet, so all are `status: experimental`.

## Layout

| Path | What it is |
|---|---|
| `<integration>/integration.yml` | The integration resource. Its `metadata.title` is the integration's name, and every rule repeats it in `logsource.product`. |
| `<integration>/rules/*.yml` | One rule resource per file, exactly as the Content Manager API takes it (no `id`: the server assigns one). |
| `<integration>/logtest.yml` | Sample events and the rule titles each one must match, and only those. |
| `migration.yml` | Where every Wazuh 4.x rule went. CI fails if one is missing. |
| `monitors/*.json` | Alerting monitors that count findings in real time: brute force and content discovery. |

| Integration | Category | Rules | Project |
|---|---|---|---|
| `lab-ssh` | access-management | SSH failed login, as root, successful | 2 |
| `lab-windows-auth` | access-management | Failed logon, lockout, RDP, network logon, account created, Administrators, log cleared | 3 |
| `lab-fim` | system-activity | Account databases, sudoers, authorized_keys, cron, systemd, web shells, Startup folder | 4 |
| `lab-linux-accounts` | access-management | Account created, admin group, root shell via sudo, sudo failures | 5 |
| `lab-nginx` | applications | Scanner user agent, sensitive path, path traversal, SQL injection | 6 |
| `lab-suricata` | network-activity | Severity 1, and the three lab signatures | 7 |

The integrations have no decoders of their own. The rules run on events that Wazuh's built-in
integrations decode, which is why the logtest cases matter: they show whether those decoders
fill the fields the rules read.

## What changed from 4.x

- **No counting.** Wazuh 5 rules match one event at a time and have no `frequency`,
  `timeframe` or `if_matched_*`. The four 4.x rules that counted or followed earlier events
  (100101, 100102, 100107, 100201, 100504, 100506) are now correlations in `siemlab correlate`, which runs
  them automatically when its input is Wazuh 5 findings.
- **No rule chains.** `if_sid` and `if_group` are gone, so every rule is self-contained.
- **Every matching rule writes a finding.** In 4.x an event was reported once, by the deepest
  rule. In 5.x a failed root login produces two findings: *SSH failed login* and *SSH failed
  login as root*. `siemlab` merges findings of the same event (`wazuh.event.id`) before
  counting, so one login attempt is still counted once. 4.x rule 100505 existed only to work
  around the old behaviour and was merged into *Web probe for a sensitive path*.
- **Two new informational rules**, *SSH successful login* and *Windows logon from a network
  address*. In 4.x, siemlab saw successful logins through built-in rules; in 5.x a login is
  only visible to siemlab if a rule turns it into a finding.
- **Groups became tags.** The 4.x groups siemlab relies on travel as `lab.<group>` tags, for
  example `lab.authentication_failed`.

## How the fields were chosen

Following the migration guide: a WCS field where the guide documents the 4.x mapping
(`srcip` to `source.ip`, `<user>` to `user.name`, `program_name` to `process.name`, the Windows
event ID to `event.code`, `url` to `url.original`, the FIM path to `file.path`), and the
`message` field for text that 4.x matched with `<match>` or `<regex>`.

The guide suggests `event.original` for raw text, but the WCS stores that field without
indexing it, so a detector may not be able to match on it. The validator warns about any
detection on an unindexed field. Where the decoded field is uncertain, a rule accepts either
the field or the text, for example `1 of admins_*` in the Administrators rule.

## Use it

```bash
siemlab wazuh5 fetch-schema                  # once: the WCS field list, checked by SHA-256
siemlab validate --strict                    # also validates this pack
siemlab wazuh5 deploy --dry-run              # what would be created
siemlab wazuh5 deploy --ca root-ca.pem       # draft -> test, then every logtest case
siemlab wazuh5 deploy --ca root-ca.pem --promote-custom   # and to production if all pass
siemlab wazuh5 monitors --ca root-ca.pem     # create or update the counting monitors
siemlab wazuh5 export --ca root-ca.pem       # findings for `siemlab correlate`
siemlab wazuh5 bundle --out build/wazuh5     # the API request bodies, for inspection
```

The full procedure, including detectors and exporting findings, is in
[05: Upgrading Wazuh](../../docs/setup-guides/05-upgrading-wazuh.md).

## Updating the schema

The WCS field list is `wcs/stateless/events/main/docs/fields.csv` in
[wazuh-indexer-plugins](https://github.com/wazuh/wazuh-indexer-plugins), which is licensed
under the AGPL-3.0, so siemlab does not ship it. `siemlab wazuh5 fetch-schema` downloads it
from tag `5.0.0`, checks its SHA-256, and caches it (`%LOCALAPPDATA%\siemlab` on Windows,
`~/.cache/siemlab` elsewhere; `SIEMLAB_CACHE_DIR` overrides). For a newer release, update
`WCS_TAG` and `WCS_SHA256` in `src/siemlab/schema.py`, or run
`siemlab wazuh5 fetch-schema --from <url-or-file> --no-verify` after reviewing the file.
