# Changelog

All notable changes to siemlab and its lab kit. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Until 1.0.0, a minor version may change the
command line or the content pack layout.

## [0.5.0] - 2026-10-10

### Changed
- **License:** free for noncommercial use under the PolyForm Noncommercial License 1.0.0,
  with a commercial license for commercial use (COMMERCIAL-LICENSE.md). Versions up to and
  including 0.4.0 remain under the MIT License.

## [0.4.0] - 2026-10-09

### Added
- `siemlab wazuh4 logtest` and 31 logtest cases (`detections/logtest/wazuh4.yml`) covering
  every non-FIM Wazuh 4.x rule, including the edge cases (six root-only failures, a login
  after a brute force, ten probes).
- CI runs those cases against the official `wazuh/wazuh-manager` image at the pinned
  version, after deploying the rules with `deploy-rules.sh`; it also loads the lab
  signatures in real Suricata (`suricata -T`).

### Fixed
These were found by the new real-manager tests; none had shown up in static validation.
- SSH brute force (100101) never counted failed root logins, then, once linked, counted every
  failure several times and fired on the 2nd. It now counts 100100 by rule ID, and the new
  100107 counts failed root logins; 100102 follows either.
- Content discovery (100504) fired on the 4th of 10 probes for the same reason. It now counts
  100501 by rule ID, and the new 100506 counts scanner probes (100505).
- The Nginx rules are also children of built-in 31108 and 31516, which claimed scanner
  requests to `/` and probes for `.bak`, `/server-status` and `/.ssh` first.

### Changed
- `deploy-rules.sh` restarts the manager with `wazuh-control` where there is no systemd
  (containers).
- Windows logtest cases go through the analysis queue as Event Channel XML, because Wazuh 4
  logtest never applies the Event Channel decoder. A case fails if its counting rule fires
  before the last event.

## [0.3.0] - 2026-10-09

### Added
- **Installable product.** The wheel carries the whole lab kit (detections, lab scripts,
  configs, runbooks, synthetic samples), so siemlab works outside a clone of the repository.
- `siemlab init DIR` copies the lab kit into a directory of your own.
- `siemlab demo [--wazuh5]` correlates the bundled synthetic data.
- `siemlab wazuh5 monitors` creates or updates two alerting monitors that count findings in
  real time on the indexer: brute force (6 failed logins from one source in 2 minutes) and
  content discovery (10 sensitive-path probes in 1 minute). Wazuh 5 rules cannot count, so
  before this the counting only ran in `siemlab correlate`.
- `siemlab wazuh5 export` exports findings as JSON lines through the scroll API, with no
  10,000-hit limit, for `siemlab correlate`.
- `siemlab wazuh5 fetch-schema` downloads the Wazuh Common Schema field list and checks it
  against a pinned SHA-256.
- CI builds the sdist and wheel, checks them with twine, installs the wheel in a clean
  environment and runs it from an empty directory; it also scans the history for secrets.
- A release workflow that builds and attaches the packages to a GitHub release, with optional
  PyPI publishing. See RELEASING.md.
- THIRD_PARTY_NOTICES.md, this changelog, and a package README for PyPI.

### Changed
- The WCS field list is no longer bundled: it comes from an AGPL-3.0 repository, so it is
  downloaded on demand into the user's cache. Without it, `siemlab validate` skips the field
  check with a warning (an error with `--strict`).
- `--detections` defaults to `./detections`, else the kit installed with siemlab.
- The indexer client moved to `siemlab.indexer` and never shows credentials in its repr.
- Package metadata: author and maintainer with the GitHub noreply address, project URLs,
  classifiers; the version is read from `siemlab.__version__`.

## [0.2.0] - 2026-10-07

### Added
- Wazuh 5 content pack (`detections/wazuh5`): 30 Sigma-format rules in 6 integrations,
  logtest cases, and a migration map covering all 33 Wazuh 4.x rules.
- `siemlab wazuh5 deploy` and `bundle`: load the pack through the Content Manager API,
  promote draft to test, run every logtest case, and promote to custom only if all pass.
- `siemlab correlate` reads Wazuh 5 findings, merges findings of the same event, and runs
  `brute_force` and `content_discovery` on Wazuh 5 input.
- `siemlab generate --format wazuh5` and a synthetic findings sample that correlates to the
  same incidents as the 4.x sample.
- Hyper-V `Wazuh5Server` role and `Migration` session profile.
- The lab is pinned to Wazuh 4.14.8, with an upgrade runbook (setup guide 05).

## [0.1.0] - 2026-10-06

### Added
- Detections for projects 2-7: 33 Wazuh rules, 11 Sigma rules (two Sigma v2 correlations)
  and 3 Suricata signatures, mapped to 18 ATT&CK techniques.
- siemlab: static validation, ATT&CK coverage matrix, synthetic alerts, and correlation of
  Wazuh alerts into incidents with Markdown reports.
- Hyper-V automation, Windows audit policy script, rule deployment with rollback.
- Setup guides, project runbooks, incident report template, security policy and CI.

[0.5.0]: https://github.com/exosphere8/siem-home-lab/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/exosphere8/siem-home-lab/compare/614741b...v0.4.0
[0.3.0]: https://github.com/exosphere8/siem-home-lab/compare/b9ad025...614741b
[0.2.0]: https://github.com/exosphere8/siem-home-lab/compare/08304ea...b9ad025
[0.1.0]: https://github.com/exosphere8/siem-home-lab/tree/08304ea
