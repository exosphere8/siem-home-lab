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
| 100504 | 10 | 10+ sensitive-path probes (100501) from one address within 1 minute | T1595.003 |
| 100506 | 10 | 10+ scanner probes (100505) from one address within 1 minute | T1595.002, T1595.003 |
| 100505 | 8 | A scanner user agent requesting a sensitive path | T1595.002, T1595.003 |

The rules hang off 31100 (every access-log line), 31101 (4xx responses), 31108 (simple 2xx/3xx
requests) and 31516 (built-in "suspicious URL"), because each of those built-in rules would
otherwise claim the event first. Wazuh remembers only the final rule of each event, so a
scanner probing `/.env` ends as 100505, not 100501, and has its own counter, 100506.
Counting the shared group `web_sensitive_probe` looked cleaner, but on a real manager it
counted each probe several times (100501 has four parents) and fired on the 4th probe.

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

## Wazuh 5

Integration [`lab-nginx`](../../detections/wazuh5/lab-nginx/), matching `url.original` and
`user_agent.original`. 100505 is gone: it only existed because Wazuh 4 reports the deepest
rule, so a scanner probing `/.env` hid the probe. Wazuh 5 writes a finding for every matching
rule, and the logtest case for a scanner probing `/.git/config` expects both. 100504 (10
probes in a minute) is now `siemlab correlate`'s `content_discovery`.

## Validation checklist

- [ ] logtest results recorded for all four lines
- [ ] Note which built-in web rules (31103-31106) compete, if any: ____
- [ ] Wazuh 5: the `lab-nginx` logtest cases pass, including the two-finding scanner case
- [x] All Nginx rules, including both 10-probe counters, verified in CI on a real Wazuh 4.14.8 manager (`siemlab wazuh4 logtest`)
