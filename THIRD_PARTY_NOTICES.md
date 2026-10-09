# Third-party notices

siemlab and its lab kit are © 2026 Midnight Croissant and dual-licensed: PolyForm
Noncommercial 1.0.0 or a commercial license (see [LICENSE](LICENSE) and
[COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)). They rely on, or refer to, the following
third-party work.

## Bundled in the package

### MITRE ATT&CK®

`siemlab/mitre.py`, the rules in `detections/` and the generated coverage matrix contain
ATT&CK tactic and technique identifiers and names. MITRE grants a non-exclusive,
royalty-free license to use ATT&CK for research, development and commercial purposes,
provided its copyright designation and license are reproduced:

> © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission
> of The MITRE Corporation.

Terms of use: <https://attack.mitre.org/resources/legal-and-branding/terms-of-use/>.
ATT&CK® is a registered trademark of The MITRE Corporation.

## Installed alongside, not bundled

| Project | License | How siemlab uses it |
|---|---|---|
| [PyYAML](https://github.com/yaml/pyyaml) | MIT | Required dependency, installed by pip |
| [pySigma](https://github.com/SigmaHQ/pySigma) | LGPL-2.1 | Optional (`siemlab[sigma]`), used unmodified as a library to validate Sigma rules |

## Downloaded by the user, never bundled

### Wazuh Common Schema field list

`siemlab wazuh5 fetch-schema` downloads `fields.csv` from
[wazuh/wazuh-indexer-plugins](https://github.com/wazuh/wazuh-indexer-plugins) (AGPL-3.0)
into the user's own cache, to check rule fields against it. The package does not contain
that file. The test suite uses a 16-line list of the field names the content pack refers to.

## Trademarks

Wazuh® is a registered trademark of Wazuh, Inc. Sigma, Suricata, Nginx, OpenSearch and
Windows are trademarks of their respective owners. siemlab is an independent project; it is
not affiliated with, sponsored or endorsed by any of them. Their names are used only to
state compatibility.

## Original content

The Wazuh rules, Wazuh 5 rules, Sigma rules, Suricata signatures, lab scripts, runbooks and
synthetic samples in this repository were written for this project. The Sigma rules follow
the public [Sigma specification](https://github.com/SigmaHQ/sigma-specification) but are
not copied from the SigmaHQ rule repository.
