import json
from datetime import UTC, datetime

import pytest

from siemlab.alerts import Alert, parse_lines, parse_timestamp

LINUX = {
    "timestamp": "2026-10-05T10:00:01.123+0000",
    "rule": {
        "id": "100101",
        "level": 10,
        "description": "SSH: brute force",
        "groups": ["local", "sshd", "authentication_failures"],
        "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"]},
    },
    "agent": {"id": "001", "name": "ubuntu-endpoint", "ip": "10.10.10.20"},
    "data": {"srcip": "10.10.10.50", "dstuser": "root"},
    "full_log": "Failed password for root from 10.10.10.50 port 4000 ssh2",
}

WINDOWS = {
    "timestamp": "2026-10-05T10:00:02.000+0200",
    "rule": {
        "id": "100200",
        "level": 5,
        "description": "Windows failed logon",
        "groups": "windows",
    },
    "agent": {"name": "win11-endpoint"},
    "data": {"win": {"eventdata": {"ipAddress": "10.10.10.50", "targetUserName": "admin"}}},
}


def test_linux_alert_is_normalised():
    a = Alert.from_wazuh(LINUX)
    assert a.timestamp == datetime(2026, 10, 5, 10, 0, 1, 123000, tzinfo=UTC)
    assert (a.rule_id, a.level, a.agent, a.agent_ip) == (
        "100101",
        10,
        "ubuntu-endpoint",
        "10.10.10.20",
    )
    assert (a.src_ip, a.user) == ("10.10.10.50", "root")
    assert a.has_group("authentication_failures")
    assert a.has_technique("T1110")
    assert a.tactics == ("Credential Access",)


def test_windows_fields_map_to_the_same_attributes():
    a = Alert.from_wazuh(WINDOWS)
    assert (a.src_ip, a.user) == ("10.10.10.50", "admin")
    assert a.groups == ("windows",)  # a bare string is accepted as a one-item list
    assert a.timestamp.utcoffset().total_seconds() == 7200


@pytest.mark.parametrize("value", ["-", "::1", "127.0.0.1", "  ", None])
def test_placeholder_addresses_count_as_missing(value):
    doc = json.loads(json.dumps(LINUX))
    doc["data"]["srcip"] = value
    assert Alert.from_wazuh(doc).src_ip is None


def test_syscheck_path_is_exposed_as_file():
    doc = {**LINUX, "syscheck": {"path": "/etc/passwd"}}
    assert Alert.from_wazuh(doc).file == "/etc/passwd"


def test_parse_lines_sorts_and_skips_malformed(caplog):
    later = {**LINUX, "timestamp": "2026-10-05T11:00:00.000+0000"}
    lines = [json.dumps(later), "not json", "", json.dumps({"rule": {}}), json.dumps(LINUX)]
    result = parse_lines(lines)
    assert [a.timestamp.hour for a in result.alerts] == [10, 11]
    assert result.skipped == 2
    assert "line 2" in caplog.text


@pytest.mark.parametrize(
    "text",
    ["2026-10-05T10:00:01.123+0000", "2026-10-05T10:00:01.123+00:00", "2026-10-05T10:00:01Z"],
)
def test_timestamp_formats(text):
    assert parse_timestamp(text).hour == 10
