import json

import pytest

from siemlab import cli
from siemlab.alerts import parse_lines
from siemlab.correlate import correlate
from siemlab.generate import ATTACKER, SCENARIOS, generate


def test_generation_is_deterministic(detections):
    assert generate(detections, seed=3) == generate(detections, seed=3)
    assert generate(detections, seed=3) != generate(detections, seed=4)


def test_generated_alerts_use_the_real_rule_metadata(detections):
    docs = generate(detections, ["ssh-compromise"])
    brute = next(d for d in docs if d["rule"]["id"] == "100101")
    assert brute["rule"]["level"] == 10
    assert "authentication_failures" in brute["rule"]["groups"]
    assert brute["rule"]["mitre"]["id"] == ["T1110.001"]
    assert ATTACKER in brute["rule"]["description"]  # $(srcip) was substituted
    assert "$(" not in "".join(d["rule"]["description"] for d in docs)


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("benign", set()),
        ("ssh-compromise", {"credential_compromise", "persistence_chain"}),
        ("windows-spray", {"password_spray"}),
        ("windows-persistence", {"persistence_chain", "high_severity_alert"}),
        ("web-attack", {"web_attack_progression"}),
    ],
)
def test_each_scenario_produces_its_story(detections, scenario, expected):
    lines = [json.dumps(d) for d in generate(detections, [scenario])]
    incidents = correlate(parse_lines(lines).alerts)
    assert {i.rule for i in incidents} == expected


def test_all_scenarios_together(detections):
    lines = [json.dumps(d) for d in generate(detections)]
    rules = sorted(i.rule for i in correlate(parse_lines(lines).alerts))
    assert "multi_host_activity" in rules  # the attacker hit both endpoints
    assert rules.count("persistence_chain") == 2


def test_unknown_scenario(detections):
    with pytest.raises(ValueError, match="unknown scenario"):
        generate(detections, ["nope"])
    assert "benign" in SCENARIOS


def test_cli_end_to_end(tmp_path, capsys, detections):
    alerts = tmp_path / "alerts.json"
    reports = tmp_path / "reports"
    assert cli.main(["--detections", str(detections), "generate", "--out", str(alerts)]) == 0
    code = cli.main(
        [
            "--detections",
            str(detections),
            "correlate",
            str(alerts),
            "--report-dir",
            str(reports),
            "--fail-on-incident",
        ]
    )
    out = capsys.readouterr().out
    assert code == 2
    assert "Correlation summary" in out
    files = sorted(p.name for p in reports.iterdir())
    assert files[0] == "INC-20261005-001.md"
    text = (reports / files[0]).read_text(encoding="utf-8")
    for section in (
        "## Summary",
        "## MITRE ATT&CK",
        "## Timeline",
        "## Recommended response",
        "## Analyst notes",
    ):
        assert section in text


def test_cli_json_and_severity_filter(tmp_path, capsys, detections):
    alerts = tmp_path / "alerts.json"
    cli.main(["--detections", str(detections), "generate", "--out", str(alerts)])
    capsys.readouterr()
    assert (
        cli.main(["correlate", str(alerts), "--format", "json", "--min-severity", "critical"]) == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["incidents"]
    assert {i["severity"] for i in payload["incidents"]} == {"critical"}


def test_cli_validate_and_coverage(tmp_path, capsys, detections):
    assert cli.main(["--detections", str(detections), "validate", "--strict"]) == 0
    target = tmp_path / "coverage.md"
    assert cli.main(["--detections", str(detections), "coverage", "--check", str(target)]) == 1
    assert cli.main(["--detections", str(detections), "coverage", "--write", str(target)]) == 0
    assert cli.main(["--detections", str(detections), "coverage", "--check", str(target)]) == 0
    assert cli.main(["--detections", str(detections), "coverage"]) == 0
    assert "ATT&CK coverage" in capsys.readouterr().out


def test_cli_missing_file_is_a_clean_error(tmp_path):
    assert cli.main(["correlate", str(tmp_path / "missing.json")]) == 1


def test_cli_stdout_generation(capsys, detections):
    assert cli.main(["--detections", str(detections), "generate", "--scenario", "benign"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert all(json.loads(line)["agent"]["name"] for line in lines)


def test_non_console_streams_are_switched_to_utf8(monkeypatch):
    import io
    import sys

    fake = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", fake)
    cli._configure_streams()
    assert fake.encoding == "utf-8"
