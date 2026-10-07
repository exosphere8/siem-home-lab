"""Wazuh 5 findings through siemlab: loading, merging, counting, the CLI, and deployment."""

from __future__ import annotations

import dataclasses
import json
import threading
from collections.abc import Iterator
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from conftest import REPO, failure, make_alert
from siemlab import alerts, correlate, deploy5, wazuh5
from siemlab.cli import main
from siemlab.validate import load_catalogue

SAMPLE4 = REPO / "sample-data" / "sanitized" / "alerts-synthetic.json"
SAMPLE5 = REPO / "sample-data" / "sanitized" / "findings-wazuh5-synthetic.json"


def finding(
    title: str = "SSH failed login",
    level: str = "low",
    *,
    event_id: str = "e1",
    tags: tuple[str, ...] = ("lab.authentication_failed",),
    when: str = "2026-10-05T10:00:00Z",
    **event: Any,
) -> dict[str, Any]:
    return {
        "@timestamp": when,
        "source": {"ip": "10.10.10.50"},
        "user": {"name": "root"},
        **event,
        "wazuh": {
            "agent": {"name": "ubuntu-endpoint"},
            "event": {"id": event_id},
            "rule": {
                "id": title.lower().replace(" ", "-"),
                "title": title,
                "level": level,
                "tags": [level, "lab-ssh", *tags],
                "mitre": {
                    "technique": {"id": ["T1110"], "name": ["Brute Force"]},
                    "subtechnique": {"id": ["T1110.001"], "name": ["x"]},
                    "tactic": {"id": ["TA0006"], "name": ["Credential Access"]},
                },
            },
        },
    }


def lines(*docs: dict[str, Any]) -> list[str]:
    return [json.dumps(d) for d in docs]


# -- loading ---------------------------------------------------------------------------------


def test_a_finding_becomes_an_alert():
    loaded = alerts.parse_lines(lines(finding()))
    assert loaded.wazuh5
    assert loaded.skipped == 0
    (a,) = loaded.alerts
    assert (a.src_ip, a.user, a.agent, a.level) == ("10.10.10.50", "root", "ubuntu-endpoint", 5)
    assert a.has_group("authentication_failed")
    assert a.techniques == ("T1110.001", "T1110")
    assert a.tactics == ("Credential Access",)
    assert a.description == "SSH failed login"
    assert a.event_id == "e1"


def test_findings_of_one_event_merge_into_one_alert():
    loaded = alerts.parse_lines(
        lines(
            finding("SSH failed login", "low"),
            finding("SSH failed login as root", "medium", tags=("lab.root",)),
            finding("SSH failed login", "low", event_id="e2"),
        )
    )
    assert loaded.merged == 1
    assert len(loaded.alerts) == 2
    merged = next(a for a in loaded.alerts if a.event_id == "e1")
    assert merged.description == "SSH failed login as root"  # the most severe rule wins
    assert merged.level == 8
    assert set(merged.groups) == {"authentication_failed", "root"}


def test_wcs_authentication_outcome_sets_the_group():
    success = finding(
        "Login",
        "informational",
        tags=(),
        event={"category": ["authentication"], "outcome": "success"},
    )
    failed = finding(
        "Fail",
        "low",
        tags=(),
        event_id="e2",
        event={"category": ["authentication"], "outcome": "failure"},
    )
    a, b = alerts.parse_lines(lines(success, failed)).alerts
    assert a.has_group("authentication_success")
    assert b.has_group("authentication_failed")


@pytest.mark.parametrize(
    "doc",
    [
        {"@timestamp": "2026-10-05T10:00:00Z", "wazuh": {"rule": {"level": "low"}}},  # no title
        {"@timestamp": "2026-10-05T10:00:00", "wazuh": {"rule": {"title": "x"}}},  # no offset
    ],
)
def test_bad_findings_are_skipped(doc):
    assert alerts.parse_lines(lines(doc)).skipped == 1


def test_from_wazuh5_rejects_non_findings():
    with pytest.raises(TypeError):
        alerts.Alert.from_wazuh5([])
    with pytest.raises(TypeError):
        alerts.Alert.from_wazuh5({"@timestamp": "x", "wazuh": {"rule": "x"}})
    assert not alerts.is_wazuh5({"timestamp": "x", "rule": {}})


# -- counting in siemlab ---------------------------------------------------------------------


def _burst(n: int, step: float = 10, **kw: Any) -> list[alerts.Alert]:
    return [failure(i * step, **kw) for i in range(n)]


def test_brute_force_needs_stateful_mode():
    burst = _burst(6)
    assert correlate.correlate(burst) == []
    (inc,) = correlate.correlate(burst, correlate.Config(stateful=True))
    assert inc.rule == "brute_force"
    assert inc.severity == "high"
    assert len(inc.alerts) == 6


def test_brute_force_threshold_and_window():
    cfg = correlate.Config(stateful=True)
    assert correlate.correlate(_burst(5), cfg) == []  # 5 < 6
    assert correlate.correlate(_burst(6, step=30), cfg) == []  # spread over 2.5 minutes


def test_brute_force_does_not_repeat_a_compromise():
    burst = _burst(8)
    success = make_alert(100, rule_id="5715", level=3, groups=("authentication_success",))
    incidents = correlate.correlate([*burst, success], correlate.Config(stateful=True))
    assert [i.rule for i in incidents] == ["credential_compromise"]


def test_content_discovery_counts_sensitive_probes():
    probes = [
        dataclasses.replace(
            make_alert(i * 3, rule_id="probe", groups=("web_sensitive_probe",)), url=f"/p{i}"
        )
        for i in range(10)
    ]
    (inc,) = correlate.correlate(probes, correlate.Config(stateful=True))
    assert inc.rule == "content_discovery"
    assert inc.severity == "medium"
    assert correlate.correlate(probes[:9], correlate.Config(stateful=True)) == []


def test_new_thresholds_are_validated():
    with pytest.raises(ValueError, match="windows"):
        correlate.Config(burst_window=timedelta(0))
    with pytest.raises(ValueError, match="thresholds"):
        correlate.Config(discovery_probes=0)


# -- the synthetic samples and the CLI -------------------------------------------------------


def _incidents(path: Path, capsys: pytest.CaptureFixture[str]) -> list[tuple[str, str, str]]:
    assert main(["correlate", str(path), "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    return sorted((i["rule"], i["severity"], i["entity"]) for i in out["incidents"])


def test_the_migration_keeps_every_incident(capsys):
    """Correlating the 5.x findings finds the same incidents as the 4.x alerts."""
    assert _incidents(SAMPLE5, capsys) == _incidents(SAMPLE4, capsys)


def test_committed_findings_sample_is_reproducible(tmp_path):
    out = tmp_path / "f.json"
    assert main(["generate", "--format", "wazuh5", "--out", str(out)]) == 0
    assert out.read_text(encoding="utf-8") == SAMPLE5.read_text(encoding="utf-8")


def test_correlate_reports_the_source(capsys):
    main(["correlate", str(SAMPLE5), "--format", "json"])
    assert json.loads(capsys.readouterr().out)["source"] == "wazuh5"


def test_bundle_and_dry_run(tmp_path, capsys):
    assert main(["wazuh5", "bundle", "--out", str(tmp_path)]) == 0
    assert (tmp_path / "manifest.json").exists()
    assert main(["wazuh5", "deploy", "--dry-run"]) == 0
    assert "lab-ssh (access-management)" in capsys.readouterr().out


def test_deploy_refuses_unverified_tls_and_missing_password(monkeypatch, caplog):
    assert main(["wazuh5", "deploy", "--url", "https://10.10.10.10:9200"]) == 1
    assert "--ca" in caplog.text
    monkeypatch.delenv("WAZUH_INDEXER_PASSWORD", raising=False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert main(["wazuh5", "deploy", "--url", "http://127.0.0.1:1"]) == 1
    assert "WAZUH_INDEXER_PASSWORD" in caplog.text


def test_commands_needing_the_pack_fail_without_it(tmp_path):
    detections = tmp_path / "detections"
    (detections / "linux").mkdir(parents=True)
    src = REPO / "detections" / "linux" / "100100-ssh-bruteforce.xml"
    (detections / "linux" / src.name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    assert main(["--detections", str(detections), "wazuh5", "bundle", "--out", "x"]) == 1


# -- deployment against a fake Content Manager API -------------------------------------------


class FakeContentManager(BaseHTTPRequestHandler):
    """Just enough of the Content Manager API, with the state on the server class."""

    def log_message(self, *args: Any) -> None:  # keep test output quiet
        pass

    def _reply(self, code: int, body: Any) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        state = self.server.state  # type: ignore[attr-defined]
        state["calls"].append(("GET", self.path))
        self._reply(200, {"changes": {"integrations": [], "rules": [], "policy": []}})

    def do_POST(self) -> None:
        state = self.server.state  # type: ignore[attr-defined]
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        state["calls"].append(("POST", self.path))
        assert self.headers["Authorization"].startswith("Basic ")
        path = self.path.removeprefix(deploy5.API)
        if path == "/integrations":
            title = body["resource"]["metadata"]["title"]
            if title in state["existing"]:
                return self._reply(409, {"message": "exists", "status": 409})
            return self._reply(201, {"message": f"id-{title}", "status": 201})
        if path == "/rules":
            return self._reply(201, {"message": "rule-id", "status": 201})
        if path == "/promote":
            state["promoted"].append(body["space"])
            return self._reply(200, {"message": "Promotion completed successfully"})
        if path == "/logtest":
            return self._reply(200, {"status": 200, "message": state["logtest"](body)})
        return self._reply(404, {"message": "no such endpoint"})


@pytest.fixture
def fake_api() -> Iterator[tuple[str, dict[str, Any]]]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeContentManager)
    expected = {c.event: c.expect for c in _pack().logtests}
    server.state = {  # type: ignore[attr-defined]
        "calls": [],
        "promoted": [],
        "existing": set(),
        "logtest": lambda body: {
            "normalization": {"output": {}},
            "detection": {
                "status": "success",
                "matches": [{"rule": {"title": t}} for t in expected[body["event"]]],
            },
        },
    }
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", server.state  # type: ignore[attr-defined]
    server.shutdown()
    server.server_close()


def _pack() -> wazuh5.Pack:
    pack = wazuh5.load_pack(REPO / "detections" / "wazuh5", [])
    assert pack is not None
    return pack


def _cm(url: str) -> deploy5.ContentManager:
    return deploy5.ContentManager(url, "admin", "secret")


def test_deploy_creates_promotes_and_tests(fake_api):
    url, state = fake_api
    result = deploy5.deploy(_pack(), _cm(url), promote_custom=True, say=lambda m: None)
    assert len(result.integration_ids) == 6
    assert len(result.rule_ids) == len(_pack().rules)
    assert result.failed == []
    assert result.promoted_to_custom
    assert state["promoted"] == ["draft", "test"]
    assert ("GET", f"{deploy5.API}/promote?space=draft") in state["calls"]


def test_failed_logtest_blocks_promotion_to_custom(fake_api):
    url, state = fake_api
    state["logtest"] = lambda body: {"detection": {"status": "success", "matches": []}}
    result = deploy5.deploy(_pack(), _cm(url), promote_custom=True, say=lambda m: None)
    assert result.failed
    assert not result.promoted_to_custom
    assert state["promoted"] == ["draft"]


def test_normalization_and_detection_errors_are_failures(fake_api):
    url, state = fake_api
    state["logtest"] = lambda body: {
        "normalization": {"status": "error", "error": {"message": "bad"}},
        "detection": {"status": "skipped"},
    }
    result = deploy5.deploy(_pack(), _cm(url), say=lambda m: None)
    assert all("normalization" in (r.error or "") for r in result.failed)
    state["logtest"] = lambda body: {"detection": {"status": "skipped", "reason": "no policy"}}
    result = deploy5.deploy(_pack(), _cm(url), say=lambda m: None)
    assert all("no policy" in (r.error or "") for r in result.failed)


def test_existing_integration_stops_the_deploy(fake_api):
    url, state = fake_api
    state["existing"].add("lab-fim")
    with pytest.raises(deploy5.DeployError, match="already exists in the draft space"):
        deploy5.deploy(_pack(), _cm(url), say=lambda m: None)
    assert state["promoted"] == []


def test_cli_deploy_end_to_end(fake_api, monkeypatch, capsys):
    url, state = fake_api
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "secret")
    assert main(["wazuh5", "deploy", "--url", url]) == 0
    assert "passed" in capsys.readouterr().out
    state["logtest"] = lambda body: {"detection": {"status": "success", "matches": []}}
    assert main(["wazuh5", "deploy", "--url", url]) == 1
    assert "FAIL" in capsys.readouterr().out
    state["existing"].add("lab-fim")
    assert main(["wazuh5", "deploy", "--url", url]) == 1


def test_client_reports_http_errors_and_non_json(fake_api):
    url, _ = fake_api
    code, body = _cm(url).request("POST", "/nowhere", {})
    assert code == 404
    assert body == {"message": "no such endpoint"}
    assert deploy5._json(b"not json") == "not json"
    assert deploy5._json(b"") is None


def test_tls_options():
    insecure = deploy5.ContentManager("https://x:9200", "a", "b", insecure=True)
    assert insecure._context is not None
    assert not insecure._context.check_hostname
    verified = deploy5.ContentManager("https://x:9200", "a", "b")
    assert verified._context is not None
    assert verified._context.check_hostname


def test_catalogue_still_loads_without_the_pack(detections):
    assert load_catalogue(detections).errors == []
