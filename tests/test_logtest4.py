"""Wazuh 4.x logtest cases, with a fake logtest socket."""

import pytest

from conftest import REPO
from siemlab import logtest4
from siemlab.cli import main
from siemlab.validate import load_catalogue

CASES = REPO / "detections" / "logtest" / "wazuh4.yml"


def test_cases_name_real_rules():
    ids = {str(r.id) for r in load_catalogue(REPO / "detections").wazuh}
    cases = logtest4.load_cases(CASES)
    assert len(cases) >= 26
    assert {c.rule for c in cases} <= ids


def fake(rule_for_last: dict, calls: list):
    def call(command, params):
        calls.append(command)
        if command == "remove_session":
            return {"error": 0}
        return {"error": 0, "data": {"token": "t", "output": {"rule": rule_for_last}}}

    return call


def test_run_case_passes_and_fails():
    case = logtest4.Case("x", "/l", "syslog", ("a",), "100100", 5)
    calls: list = []
    ok = logtest4.run_case(fake({"id": "100100", "level": 5}, calls), case)
    assert ok.passed
    assert calls == ["log_processing", "remove_session"]
    twice = logtest4.Case("x", "/l", "syslog", ("a", "b"), "100100", 5)
    early = logtest4.run_case(fake({"id": "100100", "level": 5}, []), twice)
    assert not early.passed  # fired before the last event
    assert "rules per event: 100100 100100" in logtest4.describe(early)
    bad = logtest4.run_case(fake({"id": "5716", "level": 5}, []), case)
    assert not bad.passed
    assert "FAIL" in logtest4.describe(bad)
    none = logtest4.run_case(fake({}, []), case)
    assert none.rule is None


def test_logtest_errors_are_failures():
    case = logtest4.Case("x", "/l", "syslog", ("a",), "1")
    result = logtest4.run_case(lambda c, p: {"error": 7, "message": "bad"}, case)
    assert "bad" in (result.error or "")


@pytest.mark.parametrize(
    "doc",
    [{}, {"cases": [1]}, {"cases": [{"events": []}]}, {"cases": [{"events": ["a"], "expect": {}}]}],
)
def test_malformed_cases(doc):
    with pytest.raises(ValueError, match="case"):
        logtest4.parse_cases(doc)


def test_json_cases_and_cli_without_socket(tmp_path, caplog):
    path = tmp_path / "c.json"
    path.write_text('{"cases": [{"events": ["a"], "expect": {"rule": 1}}]}', encoding="utf-8")
    assert logtest4.load_cases(path)[0].rule == "1"
    assert main(["wazuh4", "logtest", "--cases", str(path), "--socket", str(tmp_path / "s")]) == 1
