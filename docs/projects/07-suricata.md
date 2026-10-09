# Project 7: Suricata network IDS integration (optional)

**Status:** rules written and statically validated in CI; lab validation pending.
**Rules:** [`detections/network/100600-suricata.xml`](../../detections/network/100600-suricata.xml),
signatures [`detections/network/suricata-local.rules`](../../detections/network/suricata-local.rules)

## Objective

Add network-level visibility on `ubuntu-endpoint`: Suricata inspects traffic, writes alerts to
`eve.json`, and the Wazuh agent ships them to the manager next to the host logs.

## Install (ubuntu-endpoint)

```bash
sudo apt-get install -y suricata
sudo sed -i 's|^\(\s*HOME_NET:\).*|\1 "[10.10.10.0/24]"|' /etc/suricata/suricata.yaml
sudo cp detections/network/suricata-local.rules /etc/suricata/rules/local.rules
```

Add `local.rules` under `rule-files:` in `/etc/suricata/suricata.yaml`, check the interface name
(`eth0`) under `af-packet:`, then:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml      # configuration test: must pass
sudo systemctl restart suricata
```

The agent config already collects `/var/log/suricata/eve.json` as JSON.

## Lab signatures and Wazuh rules

| SID | Signature | Wazuh rule | ATT&CK |
|---|---|---|---|
| 1000001 | Many SYNs from one source in 10 s (port scan) | 100601 | T1046 |
| 1000002 | Burst of new SSH connections from one source | 100602 | T1110 |
| 1000003 | Scanner user agent in HTTP | 100603 | T1595.002 |
| any | Any severity-1 alert | 100600 | n/a |

## Validate with wazuh-logtest

Suricata alerts are JSON. Paste this compact event into `wazuh-logtest`:

```json
{"timestamp":"2026-10-05T10:30:00.000000+0000","event_type":"alert","src_ip":"10.10.10.50","src_port":51000,"dest_ip":"10.10.10.20","dest_port":22,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":1000002,"rev":1,"signature":"LAB SSH connection burst","category":"Attempted Administrator Privilege Gain","severity":1}}
```

Expected: 100602. The lab rules are children of both 86601 and the generic severity-1 rule
100600, so they refine it instead of being hidden by it.

## Wazuh 5

Integration [`lab-suricata`](../../detections/wazuh5/lab-suricata/). The rules expect the Suricata decoder to
put the signature ID in `rule.id` and the severity in `event.severity`, the usual convention
for Suricata in the Elastic Common Schema that the WCS follows. The logtest case shows
whether that holds. In Wazuh 5 the severity-1 rule and the signature rules no longer compete:
an alert from a lab signature produces both findings.

## Validation checklist

- [ ] `suricata -T` passes with the lab signatures
- [ ] logtest result recorded: ____
- [ ] eve.json alerts visible in the dashboard
- [ ] Wazuh 5: the `lab-suricata` logtest case passes, or the fields it shows are recorded: ____
- [x] 100600-100603 verified in CI on a real Wazuh 4.14.8 manager (`siemlab wazuh4 logtest`); the signatures load in real Suricata (`suricata -T`)
