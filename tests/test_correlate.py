from datetime import timedelta

from conftest import failure, make_alert, success
from siemlab.correlate import Config, correlate


def rules(incidents):
    return [i.rule for i in incidents]


def test_brute_force_followed_by_success_is_a_critical_compromise():
    alerts = [failure(i * 5) for i in range(6)] + [success(40, user="labadmin")]
    (incident,) = correlate(alerts)
    assert incident.rule == "credential_compromise"
    assert incident.severity == "critical"
    assert "labadmin" in incident.summary
    assert incident.id == "INC-20261005-001"
    assert len(incident.alerts) == 7


def test_success_without_enough_failures_is_not_an_incident():
    alerts = [failure(0), failure(5), success(10)]
    assert correlate(alerts) == []


def test_failures_outside_the_window_do_not_count():
    old = [failure(i) for i in range(6)]
    later = success(3600)
    assert correlate([*old, later], Config(window=timedelta(minutes=15))) == []


def test_success_from_a_different_source_is_not_linked():
    alerts = [failure(i) for i in range(6)] + [success(30, src_ip="10.10.10.1")]
    assert "credential_compromise" not in rules(correlate(alerts))


def test_password_spray_needs_distinct_accounts():
    spray = [failure(i * 10, user=u) for i, u in enumerate(["a", "b", "c", "d"])]
    (incident,) = correlate(spray)
    assert incident.rule == "password_spray"
    assert incident.users == ["a", "b", "c", "d"]

    same_user = [failure(i * 10, user="a") for i in range(4)]
    assert correlate(same_user) == []


def test_multi_host_activity_from_one_source():
    alerts = [
        make_alert(0, level=6, agent="ubuntu-endpoint"),
        make_alert(60, level=6, agent="win11-endpoint"),
    ]
    (incident,) = correlate(alerts)
    assert incident.rule == "multi_host_activity"
    assert incident.agents == ["ubuntu-endpoint", "win11-endpoint"]


def test_low_level_noise_on_several_hosts_is_ignored():
    alerts = [make_alert(0, level=3, agent="a"), make_alert(5, level=3, agent="b")]
    assert correlate(alerts) == []


def test_persistence_chain_is_critical_with_account_creation_and_privilege():
    alerts = [
        make_alert(0, techniques=("T1136.001",), src_ip=None),
        make_alert(30, techniques=("T1098",), src_ip=None),
    ]
    (incident,) = correlate(alerts)
    assert incident.rule == "persistence_chain"
    assert incident.severity == "critical"
    assert incident.entity == "host ubuntu-endpoint"


def test_two_persistence_techniques_without_privilege_are_high():
    alerts = [
        make_alert(0, techniques=("T1053.003",), src_ip=None),
        make_alert(30, techniques=("T1098.004",), src_ip=None),
    ]
    (incident,) = correlate(alerts)
    assert incident.severity == "high"  # critical needs account creation plus privilege


def test_single_persistence_technique_repeated_is_not_a_chain():
    alerts = [make_alert(i, techniques=("T1053.003",), src_ip=None) for i in range(3)]
    assert correlate(alerts) == []


def test_web_attack_progression_with_and_without_web_shell():
    recon = make_alert(0, techniques=("T1595.003",), user=None)
    exploit = make_alert(60, techniques=("T1190",), user=None)
    (incident,) = correlate([recon, exploit])
    assert (incident.rule, incident.severity) == ("web_attack_progression", "high")

    shell = make_alert(120, techniques=("T1505.003",), src_ip=None, user=None)
    found = correlate([recon, exploit, shell])
    web = next(i for i in found if i.rule == "web_attack_progression")
    assert web.severity == "critical"
    assert shell in web.alerts


def test_exploit_long_after_recon_is_not_linked():
    recon = make_alert(0, techniques=("T1595.002",), user=None)
    exploit = make_alert(7200, techniques=("T1190",), user=None)
    assert correlate([recon, exploit]) == []


def test_unexplained_high_level_alert_becomes_its_own_incident():
    lone = make_alert(0, rule_id="100206", level=12, src_ip=None, description="log cleared")
    (incident,) = correlate([lone])
    assert (incident.rule, incident.severity, incident.title) == (
        "high_severity_alert",
        "high",
        "log cleared",
    )
    assert correlate([make_alert(0, level=13, src_ip=None)])[0].severity == "critical"


def test_high_level_alert_already_in_an_incident_is_not_duplicated():
    alerts = [failure(i) for i in range(6)] + [success(30, level=13)]
    assert rules(correlate(alerts)) == ["credential_compromise"]


def test_incidents_are_ordered_by_severity_then_time_and_numbered():
    spray = [failure(100 + i, user=u) for i, u in enumerate("abcd")]
    lone = make_alert(0, level=13, src_ip=None)
    found = correlate([*spray, lone])
    assert [i.severity for i in found] == ["critical", "high"]
    assert [i.id[-3:] for i in found] == ["001", "002"]


def test_to_dict_is_serialisable():
    import json

    alerts = [failure(i * 5) for i in range(6)] + [success(40)]
    payload = json.dumps([i.to_dict() for i in correlate(alerts)])
    assert "credential_compromise" in payload
