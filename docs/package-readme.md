# siemlab

**Detection engineering toolkit for Wazuh 4 and Wazuh 5**, with a complete home SOC lab kit.

siemlab validates detection rules before they reach a SIEM, deploys a ready-made Wazuh 5
content pack and tests it against real decoders, correlates alerts into incidents with
written reports, and ships the runbooks and automation to build the lab it was made for.

- **Detections:** 33 Wazuh 4 rules, 30 Wazuh 5 rules in 6 integrations, 11 Sigma rules and 3
  Suricata signatures, mapped to 18 MITRE ATT&CK® techniques. Covers SSH and Windows brute
  force, password spraying, account and privilege changes, file integrity, web attacks and
  network IDS alerts.
- **Wazuh 5 ready:** every 4.x rule is mapped to its Wazuh 5 replacement. siemlab checks
  rules against the Wazuh Common Schema, loads them through the Content Manager API,
  promotes them to production only when every log test passes, and installs alerting
  monitors that do the counting Wazuh 5 rules cannot.
- **Correlation:** turns Wazuh 4 alerts or Wazuh 5 findings into incidents such as "successful
  login after 8 failures" or "persistence chain on a host", each with a timeline, ATT&CK
  techniques and recommended response.
- **Lab kit:** Hyper-V automation, audit policy, rule deployment with rollback, setup guides
  and one investigation runbook per detection project.

## Install

```bash
pip install siemlab              # or: pip install siemlab-0.4.0-py3-none-any.whl
pip install "siemlab[sigma]"     # also validate Sigma rules with pySigma
```

Python 3.11 or newer, on Windows, Linux or macOS. The only required dependency is PyYAML.

## Quick start

```bash
siemlab demo                     # correlate the bundled synthetic Wazuh 4 alerts
siemlab demo --wazuh5            # the same attack, as Wazuh 5 findings

siemlab init my-lab && cd my-lab # copy the lab kit: detections, scripts, configs, runbooks
siemlab wazuh5 fetch-schema      # download the Wazuh Common Schema field list once
siemlab validate --strict        # every rule, statically
```

With a Wazuh indexer (the password is read from `WAZUH_INDEXER_PASSWORD` or a prompt):

```bash
siemlab wazuh5 deploy --ca root-ca.pem                   # draft -> test, then every log test
siemlab wazuh5 deploy --ca root-ca.pem --promote-custom  # and to production if all pass
siemlab wazuh5 monitors --ca root-ca.pem                 # real-time counting monitors
siemlab wazuh5 export --ca root-ca.pem --since 24h       # findings -> exports/findings.json
siemlab correlate exports/findings.json --report-dir reports/
```

## Compatibility

| | Version |
|---|---|
| Wazuh 4 rules and lab guides | 4.14.8 |
| Wazuh 5 content pack | 5.0.0 (written against release candidate 1; rules marked experimental) |
| Python | 3.11, 3.12, 3.13 |

## Documentation

- [Lab overview and roadmap](https://github.com/exosphere8/siem-home-lab#readme)
- [Setup guides](https://github.com/exosphere8/siem-home-lab/tree/main/docs/setup-guides),
  including [upgrading and migrating to Wazuh 5](https://github.com/exosphere8/siem-home-lab/blob/main/docs/setup-guides/05-upgrading-wazuh.md)
- [Wazuh 5 content pack](https://github.com/exosphere8/siem-home-lab/tree/main/detections/wazuh5)
- [Detection coverage and migration map](https://github.com/exosphere8/siem-home-lab/blob/main/docs/detection-coverage.md)
- [Changelog](https://github.com/exosphere8/siem-home-lab/blob/main/CHANGELOG.md)

## License and notices

MIT License, © 2026 Midnight Croissant. Third-party notices, including the MITRE ATT&CK®
attribution, are in
[THIRD_PARTY_NOTICES.md](https://github.com/exosphere8/siem-home-lab/blob/main/THIRD_PARTY_NOTICES.md).
Wazuh® is a registered trademark of Wazuh, Inc.; siemlab is an independent project, not
affiliated with or endorsed by Wazuh, Inc.

Use the lab only on systems you own or are authorised to test.
