# Security policy

## Scope

This repository holds detection rules, lab automation and a Python toolkit for a private,
isolated home lab. It runs no public service.

## Reporting a problem

If you find a security issue, for example a secret committed by mistake or a script that
could cause harm outside an isolated lab, please **do not open a public issue**. Report it
privately via GitHub's "Report a vulnerability" button on the repository's **Security** tab.
I aim to respond within a week.

Detection gaps and false positives are not security issues: open a normal issue.

## Data handling

- Only synthetic or sanitised data is committed (`sample-data/sanitized/`, `configs/sanitized/`).
- `.gitignore` blocks credentials, keys, Wazuh install files (`wazuh-install-files.tar`,
  `client.keys`), raw logs, packet captures and VM images.
- File-integrity monitoring never records content diffs for `/etc/shadow`, so password hashes
  cannot reach alert data.
