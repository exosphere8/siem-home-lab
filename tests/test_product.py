"""The packaged product: the lab kit, the schema download, monitors and findings export."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import fake_indexer
from conftest import REPO
from siemlab import __version__, deploy5, export5, kit, schema, wazuh5
from siemlab.cli import main
from siemlab.indexer import IndexerClient, IndexerError
from siemlab.validate import Issue

CSV = (
    "ECS_Version,Indexed,Field_Set,Field,Type,Level,Normalization,Example,Description\n"
    "9.1.0,true,source,source.ip,ip,core,,,IP address of the source.\n"
    "9.1.0,false,event,event.original,keyword,core,,,Raw text.\n"
    '9.1.0,true,base,message,match_only_text,core,,,"Log message, optimized."\n'
)


# -- the lab kit -----------------------------------------------------------------------------


def test_kit_is_the_checkout_when_running_from_source():
    assert kit.root() == REPO


def test_detections_default_to_the_kit_outside_a_lab(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert kit.detections_dir() == REPO / "detections"
    (tmp_path / "detections").mkdir()
    assert kit.detections_dir() == Path("detections")


def test_init_copies_the_kit_and_refuses_to_overwrite(tmp_path, capsys):
    dest = tmp_path / "my-lab"
    assert main(["init", str(dest)]) == 0
    for name in (
        "detections/wazuh5/migration.yml",
        "scripts/deploy/deploy-rules.sh",
        "docs/setup-guides/05-upgrading-wazuh.md",
        "LICENSE",
        "README.md",
    ):
        assert (dest / name).is_file(), name
    assert not list(dest.rglob("__pycache__"))
    assert "Lab kit copied" in capsys.readouterr().out
    assert main(["init", str(dest)]) == 1  # not empty
    assert main(["init", str(dest), "--force"]) == 0


def test_an_initialised_kit_validates_on_its_own(tmp_path, monkeypatch, capsys):
    dest = tmp_path / "lab"
    kit.init(dest)
    monkeypatch.chdir(dest)
    assert main(["validate", "--strict"]) == 0
    assert "30 Wazuh 5 rules" in capsys.readouterr().err


def test_kit_errors_when_not_installed(monkeypatch, tmp_path):
    monkeypatch.setattr(kit, "root", lambda: None)
    with pytest.raises(FileNotFoundError):
        kit.init(tmp_path / "x")
    with pytest.raises(FileNotFoundError):
        kit.sample("alerts-synthetic.json")
    monkeypatch.chdir(tmp_path)
    assert kit.detections_dir() == Path("detections")


def test_missing_sample_is_reported():
    with pytest.raises(FileNotFoundError, match=r"nope\.json"):
        kit.sample("nope.json")


@pytest.mark.parametrize(("flag", "source"), [([], "wazuh4"), (["--wazuh5"], "wazuh5")])
def test_demo_correlates_the_bundled_samples(flag, source, capsys):
    assert main(["demo", *flag, "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["source"] == source
    assert len(out["incidents"]) == 7


def test_version_comes_from_the_package(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert __version__ in capsys.readouterr().out


# -- the WCS schema --------------------------------------------------------------------------


def test_convert_marks_unindexed_fields():
    text = schema.convert(CSV)
    assert "source.ip\n" in text
    assert "event.original noindex" in text
    with pytest.raises(schema.SchemaError, match="not a WCS"):
        schema.convert("a,b\n1,2\n")
    with pytest.raises(schema.SchemaError, match="empty"):
        schema.convert("Field,Indexed\n")


def test_fetch_verifies_and_caches(tmp_path, monkeypatch):
    monkeypatch.delenv("SIEMLAB_WCS_FIELDS")
    source = tmp_path / "fields.csv"
    source.write_text(CSV, encoding="utf-8")
    with pytest.raises(schema.SchemaError, match="SHA-256"):
        schema.fetch(str(source))  # the pinned hash is for the real file
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    path = schema.fetch(str(source), digest)
    assert path.parent == schema.cache_dir()
    assert schema.load() == {"event.original": False, "message": True, "source.ip": True}


def test_fetch_reports_unreadable_sources(tmp_path):
    with pytest.raises(schema.SchemaError, match="could not read"):
        schema.fetch(str(tmp_path / "missing.csv"), None)


def test_cli_fetch_schema(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("SIEMLAB_WCS_FIELDS")
    source = tmp_path / "fields.csv"
    source.write_text(CSV, encoding="utf-8")
    assert main(["wazuh5", "fetch-schema", "--from", str(source)]) == 1  # hash differs
    assert main(["wazuh5", "fetch-schema", "--from", str(source), "--no-verify"]) == 0
    assert "3 fields saved" in capsys.readouterr().err


def test_cache_dir_follows_the_platform(monkeypatch, tmp_path):
    monkeypatch.delenv("SIEMLAB_CACHE_DIR")
    monkeypatch.setattr(schema.sys, "platform", "linux")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert schema.cache_dir() == tmp_path / "siemlab"
    monkeypatch.setattr(schema.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert schema.cache_dir() == tmp_path / "local" / "siemlab"


def test_without_the_schema_fields_are_not_checked(monkeypatch, tmp_path):
    monkeypatch.setenv("SIEMLAB_WCS_FIELDS", str(tmp_path / "absent.txt"))
    issues: list[Issue] = []
    wazuh5.load_pack(REPO / "detections" / "wazuh5", issues)
    assert [i.severity for i in issues] == ["warning"]
    assert "fetch-schema" in issues[0].message


# -- monitors --------------------------------------------------------------------------------


def _pack() -> wazuh5.Pack:
    pack = wazuh5.load_pack(REPO / "detections" / "wazuh5", [])
    assert pack is not None
    return pack


def test_pack_monitors_count_tagged_findings():
    monitors = {m.file: m for m in _pack().monitors}
    assert set(monitors) == {"monitors/brute-force.json", "monitors/content-discovery.json"}
    assert monitors["monitors/brute-force.json"].tags == ("lab.authentication_failed",)
    query = monitors["monitors/brute-force.json"].doc["inputs"][0]["search"]["query"]
    agg = query["aggregations"]["composite_agg"]
    assert agg["aggs"]["events"] == {"cardinality": {"field": "wazuh.event.id"}}


def _monitor_issues(tmp_path: Path, doc: Any) -> list[str]:
    pack_dir = tmp_path / "detections" / "wazuh5"
    (pack_dir / "monitors").mkdir(parents=True)
    (pack_dir / "migration.yml").write_text("rules: {}\n", encoding="utf-8")
    text = doc if isinstance(doc, str) else json.dumps(doc)
    (pack_dir / "monitors" / "m.json").write_text(text, encoding="utf-8")
    issues: list[Issue] = []
    wazuh5.load_pack(pack_dir, issues)
    return [i.message for i in issues if i.severity == "error"]


def _good_monitor() -> dict[str, Any]:
    path = REPO / "detections" / "wazuh5" / "monitors" / "brute-force.json"
    doc: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return doc


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d.update(monitor_type="query_level_monitor"), "bucket_level_monitor"),
        (lambda d: d.update(name=""), "missing name"),
        (lambda d: d.update(id="x"), "remove 'id'"),
        (lambda d: d.update(enabled="yes"), "enabled must be"),
        (lambda d: d["schedule"]["period"].update(unit="SECONDS"), "schedule.period"),
        (lambda d: d["inputs"][0]["search"].update(indices=["wazuh-events-v5-*"]), "findings"),
        (lambda d: d.update(inputs=[]), "exactly one search input"),
        (lambda d: d["inputs"][0]["search"]["query"].pop("aggregations"), "composite_agg"),
        (lambda d: d.update(triggers=[]), "at least one trigger"),
        (
            lambda d: d["triggers"][0]["bucket_level_trigger"].update(severity="9"),
            "severity 1-5",
        ),
        (lambda d: d["inputs"][0]["search"]["query"].update(query={}), "filter on wazuh.rule.tags"),
        (lambda d: None, "no pack rule carries the tag 'lab.authentication_failed'"),
    ],
)
def test_monitor_errors(tmp_path, change, message):
    doc = _good_monitor()
    change(doc)
    assert any(message in m for m in _monitor_issues(tmp_path, doc)), message


def test_monitor_must_be_a_json_object(tmp_path):
    assert any("invalid JSON" in m for m in _monitor_issues(tmp_path, "{"))
    assert any("JSON object" in m for m in _monitor_issues(tmp_path / "b", "[]"))


def test_monitor_tag_filters_are_found_in_any_form():
    query = {"bool": {"filter": [{"terms": {"wazuh.rule.tags": ["a.b", "c.d"]}}]}}
    nested = {"x": [{"term": {"wazuh.rule.tags": {"value": "e.f"}}}]}
    assert list(wazuh5._walk_tag_filters(query)) == ["a.b", "c.d"]
    assert list(wazuh5._walk_tag_filters(nested)) == ["e.f"]


def test_duplicate_monitor_names_are_errors():
    pack = _pack()
    pack.monitors.append(pack.monitors[0])
    issues: list[Issue] = []
    wazuh5._check_monitor_tags(pack, issues)
    assert any("used twice" in i.message for i in issues)


def test_monitors_are_created_then_updated():
    pack = _pack()
    with fake_indexer.running() as (url, state):
        client = IndexerClient(url, "admin", "test-only")
        first = deploy5.deploy_monitors(pack, client, say=lambda m: None)
        assert len(state["monitors"]) == 2
        second = deploy5.deploy_monitors(pack, client, say=lambda m: None)
        assert first == second
        assert len(state["monitors"]) == 2  # updated, not duplicated
        assert sorted(state["updated"]) == sorted(first.values())


def test_cli_monitors(monkeypatch, capsys):
    assert main(["wazuh5", "monitors", "--dry-run"]) == 0
    assert "lab.web_sensitive_probe" in capsys.readouterr().out
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "test-only")
    with fake_indexer.running() as (url, _):
        assert main(["wazuh5", "monitors", "--url", url]) == 0
    assert "2 monitor(s) in place" in capsys.readouterr().out


# -- export ----------------------------------------------------------------------------------

F1 = {"@timestamp": "2026-10-05T10:00:00Z", "wazuh": {"rule": {"title": "a"}}}
F2 = {"@timestamp": "2026-10-05T10:00:01Z", "wazuh": {"rule": {"title": "b"}}}


def test_export_pages_through_every_finding_and_clears_the_scroll(tmp_path):
    with fake_indexer.running(pages=[[F1], [F2]]) as (url, state):
        client = IndexerClient(url, "admin", "test-only")
        assert list(export5.iter_findings(client, since="24h")) == [F1, F2]
        assert state["cleared"] == [["3"]]
        search = next(c for c in state["calls"] if "scroll=" in c[1])
        assert search[1].startswith("/wazuh-findings-v5-*/_search")


def test_export_rejects_a_bad_age():
    with pytest.raises(ValueError, match="--since"):
        export5._query("yesterday")
    assert export5._query(None) == {"match_all": {}}


def test_export_clears_the_scroll_even_when_it_fails():
    with fake_indexer.running(pages=[[F1], [F2]], scroll_error=True) as (url, state):
        client = IndexerClient(url, "admin", "test-only")
        with pytest.raises(IndexerError, match="continue the scroll"):
            list(export5.iter_findings(client))
        assert state["cleared"] == [["1"]]


def test_cli_export_writes_json_lines_that_correlate(tmp_path, monkeypatch, capsys):
    sample = REPO / "sample-data" / "sanitized" / "findings-wazuh5-synthetic.json"
    findings = [json.loads(line) for line in sample.read_text(encoding="utf-8").splitlines()]
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "test-only")
    out = tmp_path / "exports" / "findings.json"
    with fake_indexer.running(pages=[findings[:20], findings[20:]]) as (url, _):
        assert main(["wazuh5", "export", "--url", url, "--out", str(out)]) == 0
    assert f"wrote {len(findings)} finding(s)" in capsys.readouterr().err
    assert main(["correlate", str(out), "--format", "json"]) == 0
    assert len(json.loads(capsys.readouterr().out)["incidents"]) == 7


def test_cli_indexer_errors_are_reported(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "test-only")
    out = tmp_path / "findings.json"
    with fake_indexer.running(search_error=True) as (url, _):
        assert main(["wazuh5", "export", "--url", url, "--out", str(out)]) == 1
    assert "HTTP 500" in caplog.text
