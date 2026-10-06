# Project 6: Web-server (Nginx) security monitoring

**Status:** rules written and statically validated in CI; lab validation pending.
**Rules:** [`detections/web/100500-nginx.xml`](../../detections/web/100500-nginx.xml),
Sigma rules in [`detections/sigma/web/`](../../detections/sigma/web/)

## Objective

Separate the noise of the internet from requests that matter: scanners, probes for secrets,
path traversal and SQL injection, and turn a burst of probes into one meaningful alert.

| Rule | Level | Fires when | ATT&CK |
|---|---|---|---|
| 100500 | 8 | User agent of a known scanner | T1595.002 |
| 100501 | 6 | Request for a sensitive path (`/.env`, `/.git/`, `/wp-login.php`, ...) | T1595.003 |
| 100502 | 10 | Path traversal (`../`, encoded variants, `/etc/passwd`) | T1190 |
| 100503 | 10 | SQL injection patterns | T1190 |
| 100504 | 10 | 10+ sensitive-path probes from one address within 1 minute | T1595.003 |
| 100505 | 8 | A scanner user agent requesting a sensitive path | T1595.002, T1595.003 |

The rules hang off both 31100 (every access-log line) and 31101 (4xx responses), because most
probes get a 404 and 31101 would otherwise claim them first. Wazuh remembers only the final
rule of each event, so a scanner probing `/.env` ends as 100505, not 100501. 100504 therefore
counts the shared group `web_sensitive_probe` instead of one rule ID.

## Validate with wazuh-logtest

```text
10.10.10.50 - - [05/Oct/2026:10:20:01 +0000] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0"
10.10.10.50 - - [05/Oct/2026:10:20:02 +0000] "GET /download.php?file=../../etc/passwd HTTP/1.1" 404 162 "-" "Mozilla/5.0"
10.10.10.50 - - [05/Oct/2026:10:20:03 +0000] "GET /item.php?id=1%20UNION%20SELECT%20name HTTP/1.1" 404 162 "-" "Mozilla/5.0"
10.10.10.50 - - [05/Oct/2026:10:20:04 +0000] "GET / HTTP/1.1" 200 612 "-" "sqlmap/1.8 (https://sqlmap.org)"
```

| Line | Expected |
|---|---|
| 1 | 100501 |
| 2 | 100502 |
| 3 | 100503 (built-in SQL injection rules may win; record which) |
| 4 | 100500 |

## Investigation playbook

1. **Did anything succeed?** The status code and response size matter more than the request.
   A 200 with a large body on `/.env` is an incident, while a stream of 404s is just background noise.
2. Pull every request from the source address (`grep <ip> /var/log/nginx/access.log`) to see
   the full sequence: recon, then targeted requests.
3. Check Project 4 for new script files under `/var/www` after the exploitation attempts.
   `siemlab correlate` links the two automatically ([Project 8](08-alert-correlation.md)).

## Validation checklist

- [ ] logtest results recorded for all four lines
- [ ] Note which built-in web rules (31103-31106) compete, if any: ____
