# Project 8: Alert correlation with Python

**Status:** built and tested in CI. Runs on synthetic data today and on the live lab's
`alerts.json` once Projects 1-7 are validated.
**Code:** [`src/siemlab/`](../../src/siemlab/)

## Why

Wazuh rules see one event (or one counter) at a time. The questions an analyst asks span many
events: *did the brute force work? What did the intruder do next? Did they move to the other
host?* `siemlab correlate` answers them from the manager's `alerts.json`.

## Correlation rules

| Rule | Severity | Pattern |
|---|---|---|
| `credential_compromise` | critical | 5+ authentication failures from one source, then a success from it (15 min window) |
| `password_spray` | high | Failures for 4+ different accounts from one source |
| `multi_host_activity` | high | One source triggering level 5+ alerts on 2+ hosts |
| `persistence_chain` | high / critical | 2+ persistence or privilege techniques on one host (critical when account creation and privilege are combined) |
| `web_attack_progression` | high / critical | Recon (T1595) then exploitation (T1190) from one source; critical if the web root changes afterwards (T1505.003) |
| `high_severity_alert` | high / critical | Any level 12+ alert that no pattern above explains |

Each incident carries a timeline, the ATT&CK techniques and tactics involved, affected hosts,
source addresses and accounts, and recommended response steps. Reports follow the
[incident template](../incident-reports/TEMPLATE.md).

## Usage

```bash
pip install -e .
# on the manager, alerts live in /var/ossec/logs/alerts/alerts.json
siemlab correlate alerts.json                          # Markdown summary
siemlab correlate alerts.json --report-dir reports/    # one report per incident
siemlab correlate alerts.json --format json --min-severity high
```

Without the lab, generate realistic alerts first. Rule IDs, levels and ATT&CK mappings are
read from `detections/`, so synthetic alerts match the real rules:

```bash
siemlab generate --out sample-data/sanitized/alerts-synthetic.json
siemlab correlate sample-data/sanitized/alerts-synthetic.json
```

The committed sample yields seven incidents. One of them is rendered in
[`EXAMPLE-synthetic-INC-20261005-002.md`](../incident-reports/EXAMPLE-synthetic-INC-20261005-002.md).

## Design notes

- **Pure functions over a normalised model.** `Alert` hides the difference between Linux
  (`data.srcip`) and Windows (`data.win.eventdata.ipAddress`) fields, so each correlation rule
  is a short function that is easy to test in isolation.
- **Sliding windows, not fixed buckets:** a burst that straddles a bucket boundary is still caught.
- **Every alert is explained once at most as a standalone incident.** High-level alerts that are
  already part of a pattern do not produce duplicate incidents.
- **Malformed lines are counted and skipped**, never fatal. One bad line must not hide an attack.

## Wazuh 5

`siemlab correlate` also reads Wazuh 5 findings exported from `wazuh-findings-v5-*` (see
[05: Upgrading Wazuh](../setup-guides/05-upgrading-wazuh.md#5-correlate-wazuh-5-findings)).
It merges the findings of one event (`wazuh.event.id`) into one alert, so an event that
matched two rules is not counted twice. It also runs two correlations only on Wazuh 5 input,
because 4.x rules did this counting and 5.x rules cannot: `brute_force` (6 failed logins from
one source within 2 minutes) and `content_discovery` (10 sensitive-path probes within 1
minute). The synthetic findings correlate to the same incidents as the 4.x sample; a test
keeps it that way.

## Validation checklist

- [ ] Run against the live `alerts.json` after Projects 2-6
- [ ] Compare incidents with what you know happened during the tests; tune thresholds
      (`--window`, `--threshold`) and record the values used here
- [ ] Wazuh 5: run against exported findings and compare with the 4.x run of the same activity
