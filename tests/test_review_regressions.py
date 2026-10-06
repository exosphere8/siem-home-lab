"""Regression tests for issues found in code review before the first release."""

import json
from datetime import timedelta
from pathlib import Path

import pytest

from conftest import T0, failure, make_alert, success
from siemlab.alerts import Alert, load, parse_lines
from siemlab.correlate import Incident, correlate
from siemlab.report import incident_markdown, summary_markdown
from siemlab.validate import load_catalogue

BASE = {
    "timestamp": "2026-10-05T10:00:00.000+0000",
    "rule": {"id": "100601", "level": 10, "description": "Suricata scan", "groups": ["ids"]},
    "agent": {"name": "ubuntu-endpoint"},
}


# -- alerts ----------------------------------------------------------------------------------


def test_suricata_src_ip_is_recognised():
    doc = {**BASE, "data": {"src_ip": "10.10.10.50", "dest_ip": "10.10.10.20"}}
    assert Alert.from_wazuh(doc).src_ip == "10.10.10.50"


@pytest.mark.parametrize("line", ["null", "[]", "123", '"text"', json.dumps({**BASE, "data": "x"})])
def test_valid_json_that_is_not_an_alert_is_skipped(line):
    result = parse_lines([json.dumps(BASE), line])
    assert (len(result.alerts), result.skipped) == (1, 1)


def test_timestamp_without_offset_is_skipped_not_compared():
    naive = {**BASE, "timestamp": "2026-10-05 10:00:02"}
    result = parse_lines([json.dumps(BASE), json.dumps(naive)])
    assert (len(result.alerts), result.skipped) == (1, 1)


def test_byte_order_mark_does_not_drop_the_first_alert(tmp_path):
    path = tmp_path / "alerts.json"
    path.write_text(json.dumps(BASE) + "\n" + json.dumps(BASE) + "\n", encoding="utf-8-sig")
    result = load(path)
    assert (len(result.alerts), result.skipped) == (2, 0)


def test_group_membership_events_report_the_member_not_the_group():
    doc = {
        **BASE,
        "data": {
            "win": {
                "system": {"eventID": "4732"},
                "eventdata": {
                    "targetUserName": "Administrators",
                    "memberName": "-",
                    "memberSid": "S-1-5-21-1-2-3-1004",
                },
            }
        },
    }
    assert Alert.from_wazuh(doc).user == "S-1-5-21-1-2-3-1004"


# -- correlation -----------------------------------------------------------------------------


def _compromise(start: float, agent: str, user: str) -> list[Alert]:
    return [failure(start + i, agent=agent) for i in range(6)] + [
        success(start + 20, agent=agent, user=user)
    ]


def test_separate_compromises_from_one_source_are_separate_incidents():
    alerts = _compromise(0, "ubuntu-endpoint", "labadmin") + _compromise(7200, "web-01", "www")
    found = [i for i in correlate(alerts) if i.rule == "credential_compromise"]
    assert [i.agents for i in found] == [["ubuntu-endpoint"], ["web-01"]]


def test_follow_up_logins_join_the_same_incident():
    alerts = [*_compromise(0, "ubuntu-endpoint", "labadmin"), success(300, user="labadmin")]
    (incident,) = [i for i in correlate(alerts) if i.rule == "credential_compromise"]
    assert len(incident.alerts) == 8


def _web(second: float, technique: str) -> Alert:
    return make_alert(second, techniques=(technique,), user=None)


def test_unrelated_web_alerts_do_not_suppress_a_real_sequence():
    alerts = [
        _web(-7200, "T1595.003"),  # stray probe two hours earlier
        _web(0, "T1595.003"),
        _web(60, "T1190"),
        _web(7200, "T1190"),  # unrelated attempt two hours later, no recon before it
    ]
    (incident,) = [i for i in correlate(alerts) if i.rule == "web_attack_progression"]
    assert [a.timestamp - T0 for a in incident.alerts] == [timedelta(0), timedelta(seconds=60)]


def test_exploitation_before_reconnaissance_is_not_a_progression():
    alerts = [_web(0, "T1190"), _web(60, "T1595.002")]
    assert all(i.rule != "web_attack_progression" for i in correlate(alerts))


# -- reports ---------------------------------------------------------------------------------


def test_report_times_are_converted_to_utc():
    doc = {
        **BASE,
        "timestamp": "2026-10-06T01:30:00.000+0200",
        "rule": {**BASE["rule"], "level": 13},
    }
    (incident,) = correlate([Alert.from_wazuh(doc)])
    assert incident.id == "INC-20261005-001"
    text = incident_markdown(incident)
    assert "| First seen (UTC) | 2026-10-05 23:30:00 |" in text
    assert "| 23:30:00 |" in text
    assert "2026-10-05 23:30:00" in summary_markdown([incident], alerts=1)


def test_attacker_controlled_names_cannot_break_report_tables():
    inc = Incident("x", "t", "high", "e", "s", [make_alert(0, user="a|b", agent="h|1")])
    text = incident_markdown(inc)
    assert "| Accounts | a\\|b |" in text
    assert "| Hosts | h\\|1 |" in text


# -- validation ------------------------------------------------------------------------------


def _detections(tmp_path: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = tmp_path / "detections" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path / "detections"


def test_duplicate_suricata_sid_across_files(tmp_path):
    rule = 'alert tcp any any -> any any (msg:"x"; sid:1000001; rev:1;)\n'
    detections = _detections(tmp_path, {"network/a.rules": rule, "network/b.rules": rule})
    assert any("duplicate sid" in i.message for i in load_catalogue(detections).errors)


def test_sigma_document_that_is_not_a_mapping(tmp_path):
    detections = _detections(tmp_path, {"sigma/a.yml": "- just\n- a list\n"})
    assert any("not a mapping" in i.message for i in load_catalogue(detections).errors)


BASE_RULE = """title: Base
id: 335fd1ed-d506-4d5d-9340-0b9e4725ef56
name: base_rule
status: experimental
author: me
date: 2026-10-05
level: low
tags: [attack.t1110]
logsource: {product: windows, service: security}
detection: {selection: {EventID: 4625}, condition: selection}
"""
CORRELATION = """title: Burst
id: f7cdea9c-ba44-4e72-a745-a17f20b8651b
status: experimental
author: me
date: 2026-10-05
level: high
correlation:
    type: event_count
    rules: [{ref}]
    group-by: [IpAddress]
    timespan: 2m
    condition: {{gte: 8}}
"""


def test_sigma_correlation_may_reference_a_rule_in_another_file(tmp_path):
    detections = _detections(
        tmp_path,
        {
            "sigma/base.yml": BASE_RULE,
            "sigma/corr.yml": CORRELATION.format(ref="base_rule"),
        },
    )
    errors = [i for i in load_catalogue(detections).errors if "Wazuh" not in i.message]
    assert errors == []  # only Sigma files in this tree, so "no Wazuh rules" is expected


def test_sigma_correlation_with_unknown_reference_is_an_error(tmp_path):
    detections = _detections(
        tmp_path,
        {
            "sigma/base.yml": BASE_RULE,
            "sigma/corr.yml": CORRELATION.format(ref="no_such_rule"),
        },
    )
    assert any("no_such_rule" in i.message for i in load_catalogue(detections).errors)


# -- second review round ---------------------------------------------------------------------


def _technique(second: float, technique: str, rule: str = "1") -> Alert:
    return make_alert(second, rule_id=rule, techniques=(technique,), src_ip=None)


def test_persistence_chain_keeps_repeats_inside_the_window():
    alerts = [
        _technique(0, "T1136.001", "100400"),
        _technique(10, "T1098", "100401"),
        _technique(30, "T1098.004", "100302"),  # same family as T1098, still part of the story
    ]
    (incident,) = correlate(alerts)
    assert [a.rule_id for a in incident.alerts] == ["100400", "100401", "100302"]


def test_separate_chains_on_one_host_are_separate_incidents():
    alerts = [
        _technique(0, "T1053.003"),
        _technique(30, "T1543.002"),
        _technique(7200, "T1136.001"),
        _technique(7210, "T1548.003"),
    ]
    chains = [i for i in correlate(alerts) if i.rule == "persistence_chain"]
    assert len(chains) == 2


def test_password_spray_includes_retries():
    alerts = [failure(i * 10, user=u) for i, u in enumerate("abcdabcd")]
    (incident,) = [i for i in correlate(alerts) if i.rule == "password_spray"]
    assert len(incident.alerts) == 8


def test_second_burst_from_same_source_shortly_after_is_a_new_compromise():
    first = _compromise(0, "ubuntu-endpoint", "labadmin")
    second = [failure(300 + i, agent="web-01", user="www") for i in range(6)] + [
        success(320, agent="web-01", user="www")
    ]
    found = [i for i in correlate([*first, *second]) if i.rule == "credential_compromise"]
    assert [i.agents for i in found] == [["ubuntu-endpoint"], ["web-01"]]


def test_failures_with_the_same_timestamp_as_the_success_count():
    alerts = [failure(0) for _ in range(6)] + [success(0)]
    assert [i.rule for i in correlate(alerts)] == ["credential_compromise"]


def test_aggregate_brute_force_alert_counts_as_one_failure():
    alerts = [failure(i) for i in range(4)] + [
        make_alert(
            5,
            rule_id="100101",
            level=10,
            groups=("authentication_failures",),
            techniques=("T1110.001",),
        ),
        success(10),
    ]
    (incident,) = correlate(alerts)
    assert incident.title.startswith("Successful login after 5 failures")


def test_missing_detections_directory_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_catalogue(tmp_path / "nope")


@pytest.mark.parametrize(
    "content",
    [
        '<rule id="100100" level="5"><if_sid>5700</if_sid><description>d</description></rule>',
        '<group><rule id="100100" level="5"><description>d</description></rule></group>',
    ],
)
def test_rules_outside_a_named_group_are_rejected(tmp_path, content):
    detections = _detections(tmp_path, {"linux/100100-a.xml": content})
    assert any("top level" in i.message for i in load_catalogue(detections).errors)


def test_suricata_continuations_actions_and_quoted_keywords(tmp_path):
    rules = (
        'alert tcp any any -> any any (msg:"multi"; \\n'
        "    sid:1000011; rev:1;)\n"
        'rejectboth tcp any any -> any 23 (msg:"telnet"; sid:1000010; rev:1;)\n'
        'alert tcp any any -> any any (msg:"note sid:500; here"; sid:1000012; rev:1;)\n'
    )
    cat = load_catalogue(_detections(tmp_path, {"network/x.rules": rules}))
    assert [i for i in cat.errors if "Wazuh" not in i.message] == []
    assert cat.suricata_sids == [1000011, 1000010, 1000012]


def test_badly_encoded_byte_does_not_abort_loading(tmp_path):
    path = tmp_path / "alerts.json"
    lines = [json.dumps(BASE), json.dumps({**BASE, "full_log": "x"}), json.dumps(BASE)]
    raw = "\n".join(lines).encode("utf-8").replace(b'"x"', b'"caf\xe9"')
    path.write_bytes(raw)
    assert len(load(path).alerts) == 3


def test_non_positive_window_is_rejected_by_the_cli():
    from siemlab import cli

    with pytest.raises(SystemExit):
        cli.main(["correlate", "alerts.json", "--window", "-1"])


def test_generator_rejects_unknown_rule_ids(detections):
    from siemlab.generate import AlertFactory

    with pytest.raises(ValueError, match="neither"):
        AlertFactory(detections).alert(
            T0, 999999, "ubuntu-endpoint", data={}, full_log="", location="", decoder=""
        )
