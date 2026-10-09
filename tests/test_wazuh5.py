"""The Wazuh 5 content pack: validation, migration map, bundle, and synthetic findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from siemlab import wazuh5
from siemlab.validate import Issue, load_catalogue


def _pack_issues(detections: Path) -> tuple[wazuh5.Pack, list[Issue]]:
    cat = load_catalogue(detections)
    issues: list[Issue] = []
    pack = wazuh5.load_pack(detections / "wazuh5", issues)
    assert pack is not None
    wazuh5.check_migration(pack, cat, issues)
    return pack, issues


def test_repository_pack_is_valid_and_maps_every_4x_rule(detections):
    pack, issues = _pack_issues(detections)
    assert issues == []
    assert len(pack.integrations) == 6
    assert len(pack.rules) >= 28
    assert set(pack.migration) == {r.id for r in load_catalogue(detections).wazuh}
    assert all(r.doc["status"] == "experimental" for r in pack.rules)


def test_counting_rules_moved_to_siemlab(detections):
    pack, _ = _pack_issues(detections)
    moved = {k for k, v in pack.migration.items() if v["to"].startswith("siemlab:")}
    assert moved == {100101, 100102, 100107, 100201, 100504, 100506}


def test_wcs_field_list_marks_unindexed_fields():
    fields = wazuh5.wcs_fields()
    assert fields is not None
    assert fields["source.ip"] is True
    assert fields["event.original"] is False
    assert "win.eventdata.ipAddress" not in fields


# -- validation errors, on a minimal pack ----------------------------------------------------

GOOD_RULE: dict[str, Any] = {
    "metadata": {"title": "Test rule", "author": "lab", "references": []},
    "status": "experimental",
    "level": "low",
    "logsource": {"product": "lab-test"},
    "detection": {"condition": "selection", "selection": {"source.ip|cidr": "10.0.0.0/8"}},
    "tags": ["attack.credential-access", "attack.t1110.001"],
    "mitre": {
        "tactic": {"id": ["TA0006"], "name": ["Credential Access"]},
        "technique": {"id": ["T1110"], "name": ["Brute Force"]},
        "subtechnique": {"id": ["T1110.001"], "name": ["Brute Force: Password Guessing"]},
    },
}


def _write_pack(
    tmp_path: Path,
    rule: dict[str, Any] | None = None,
    integration: dict[str, Any] | None = None,
    logtest: Any = None,
) -> Path:
    detections = tmp_path / "detections"
    integ_dir = detections / "wazuh5" / "lab-test"
    (integ_dir / "rules").mkdir(parents=True)
    integ = integration or {
        "metadata": {"title": "lab-test", "author": "lab"},
        "category": "security",
    }
    (integ_dir / "integration.yml").write_text(yaml.safe_dump(integ), encoding="utf-8")
    (integ_dir / "rules" / "rule.yml").write_text(
        yaml.safe_dump(rule if rule is not None else GOOD_RULE), encoding="utf-8"
    )
    if logtest is not None:
        (integ_dir / "logtest.yml").write_text(yaml.safe_dump(logtest), encoding="utf-8")
    (detections / "wazuh5" / "migration.yml").write_text("rules: {}\n", encoding="utf-8")
    return detections


def _issues(tmp_path: Path, **kw: Any) -> list[str]:
    issues: list[Issue] = []
    wazuh5.load_pack(_write_pack(tmp_path, **kw) / "wazuh5", issues)
    return [f"{i.severity}: {i.message}" for i in issues]


def _with(**changes: Any) -> dict[str, Any]:
    rule = json.loads(json.dumps(GOOD_RULE))
    for path, value in changes.items():
        target = rule
        *parents, last = path.split("__")
        for key in parents:
            target = target[key]
        if value is None:
            del target[last]
        else:
            target[last] = value
    return rule


def test_minimal_pack_is_valid(tmp_path):
    assert _issues(tmp_path) == []


@pytest.mark.parametrize(
    ("rule", "message"),
    [
        (
            _with(detection={"condition": "selection", "selection": {"win.eventID": "4625"}}),
            "'win.eventID' is not a WCS field",
        ),
        (
            _with(detection={"condition": "selection", "selection": {"source.ip|near": "x"}}),
            "unsupported modifier 'near'",
        ),
        (
            _with(detection={"condition": "selection", "selection": {"message|re": "(unclosed"}}),
            "invalid regex",
        ),
        (
            _with(detection={"condition": "selection and filter", "selection": {"message": "x"}}),
            "unknown selection 'filter'",
        ),
        (
            _with(detection={"condition": "1 of sel_*", "selection": {"message": "x"}}),
            "unknown selection 'sel_*'",
        ),
        (_with(detection={"selection": {"message": "x"}}), "needs a 'condition'"),
        (_with(logsource={"product": "linux"}), "logsource.product must be 'lab-test'"),
        (_with(level="severe"), "level must be one of"),
        (_with(status="draft"), "status must be one of"),
        (_with(id="0b1d"), "remove 'id'"),
        (_with(enabled="yes"), "enabled must be true or false"),
        (_with(metadata__title=None), "missing metadata.title"),
        (_with(tags=["credential access"]), "not a namespace.name pair"),
        (_with(mitre__technique__name=["Brute force"]), "is named 'Brute Force'"),
        (_with(mitre__technique__name=[]), "parallel id and name lists"),
        (
            _with(mitre__tactic={"id": ["TA0001"], "name": ["Credential Access"]}),
            "tactic TA0001 is not 'Credential Access'",
        ),
        (
            _with(mitre__technique={"id": ["T1078"], "name": ["Valid Accounts"]}),
            "add its parent to mitre.technique",
        ),
        (
            _with(mitre__subtechnique={"id": ["T1110"], "name": ["Brute Force"]}),
            "is a technique, not a sub-technique",
        ),
        (
            _with(detection={"condition": "selection", "selection": {"message": [{"a": 1}]}}),
            "values must be strings",
        ),
        (
            _with(detection={"condition": "selection", "selection": []}),
            "must be a non-empty value list",
        ),
        (_with(detection={"condition": "selection"}), "no selection or keywords"),
        (_with(detection={"condition": "selection", "selection": {}}), "non-empty map"),
    ],
)
def test_rule_errors(tmp_path, rule, message):
    found = _issues(tmp_path, rule=rule)
    assert any(message in i for i in found if i.startswith("error")), found


def test_unindexed_field_and_unused_selection_are_warnings(tmp_path):
    rule = _with(
        detection={
            "condition": "selection",
            "selection": {"event.original|contains": "x"},
            "spare": {"message": "y"},
        }
    )
    found = _issues(tmp_path, rule=rule)
    assert any("not indexed" in i for i in found if i.startswith("warning"))
    assert any("'spare' is not used" in i for i in found if i.startswith("warning"))
    assert not [i for i in found if i.startswith("error")]


def test_missing_attack_tag_is_a_warning(tmp_path):
    found = _issues(tmp_path, rule=_with(tags=["attack.credential-access"]))
    assert found == ["warning: tags lack attack.t1110.001"]


@pytest.mark.parametrize(
    ("integration", "message"),
    [
        ({"metadata": {"title": "lab test", "author": "x"}, "category": "security"}, "no spaces"),
        ({"metadata": {"title": "lab-other", "author": "x"}, "category": "security"}, "directory"),
        ({"metadata": {"title": "lab-test"}, "category": "security"}, "metadata.author"),
        ({"metadata": {"title": "lab-test", "author": "x"}, "category": "Security"}, "category"),
        (
            {"metadata": {"title": "lab-test", "author": "x"}, "category": "security", "id": "1"},
            "remove 'id'",
        ),
    ],
)
def test_integration_errors(tmp_path, integration, message):
    assert any(message in i for i in _issues(tmp_path, integration=integration))


def test_logtest_must_name_rules_of_its_integration(tmp_path):
    logtest = {"logtest": [{"location": "/x", "event": "y", "expect": ["Nope"]}]}
    assert any("no rule titled 'Nope'" in i for i in _issues(tmp_path, logtest=logtest))
    assert any("expected a 'logtest' list" in i for i in _issues(tmp_path / "b", logtest={}))
    bad_case = {"logtest": [{"event": "y"}]}
    assert any("needs location, event" in i for i in _issues(tmp_path / "c", logtest=bad_case))


def test_missing_pack_returns_none(tmp_path):
    assert wazuh5.load_pack(tmp_path / "nowhere", []) is None


def test_invalid_yaml_and_missing_files(tmp_path):
    detections = _write_pack(tmp_path)
    pack_dir = detections / "wazuh5"
    (pack_dir / "lab-test" / "rules" / "rule.yml").write_text("a: [", encoding="utf-8")
    (pack_dir / "migration.yml").unlink()
    (pack_dir / "orphan").mkdir()
    issues: list[Issue] = []
    wazuh5.load_pack(pack_dir, issues)
    text = [str(i) for i in issues]
    assert any("invalid YAML" in t for t in text)
    assert any("missing migration.yml" in t for t in text)
    assert any("missing integration.yml" in t for t in text)


def test_migration_errors(tmp_path, detections):
    cat = load_catalogue(detections)
    pack, _ = _pack_issues(detections)
    pack.migration = dict(pack.migration)
    del pack.migration[100100]
    pack.migration[999] = {"to": "siemlab:brute_force"}
    pack.migration[100101] = {"to": "siemlab:magic"}
    pack.migration[100200] = {"to": "lab-ssh/rules/ssh-failed-login.yml"}
    pack.migration[100202] = {"to": "lab-x/rules/none.yml"}
    issues: list[Issue] = []
    wazuh5.check_migration(pack, cat, issues)
    text = "\n".join(str(i) for i in issues)
    assert "Wazuh 4.x rule 100100 is not mapped" in text
    assert "999 is not a Wazuh 4.x rule" in text
    assert "unknown correlation 'siemlab:magic'" in text
    assert "does not say it was migrated from 100200" in text
    assert "no rule file 'lab-x/rules/none.yml'" in text
    assert "migration.yml does not map 100100 here" in text


def test_duplicate_titles_are_errors(tmp_path):
    detections = _write_pack(tmp_path)
    rules = detections / "wazuh5" / "lab-test" / "rules"
    (rules / "copy.yml").write_text(yaml.safe_dump(GOOD_RULE), encoding="utf-8")
    issues: list[Issue] = []
    wazuh5.load_pack(detections / "wazuh5", issues)
    assert any("also used by" in i.message for i in issues)


# -- bundle and synthetic findings -----------------------------------------------------------


def test_bundle_writes_api_bodies_and_manifest(detections, tmp_path):
    pack, _ = _pack_issues(detections)
    wazuh5.bundle(pack, tmp_path)
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert [m["title"] for m in manifest] == [i.title for i in pack.integrations]
    ssh = next(m for m in manifest if m["title"] == "lab-ssh")
    body = json.loads((tmp_path / ssh["rules"][0]).read_text(encoding="utf-8"))
    assert set(body) == {"resource"}
    assert body["resource"]["logsource"]["product"] == "lab-ssh"
    cases = json.loads((tmp_path / ssh["logtest"]).read_text(encoding="utf-8"))
    assert cases
    assert all(set(c) == {"location", "event", "expect"} for c in cases)


def test_one_4x_alert_becomes_a_finding_per_matching_rule(detections):
    pack, _ = _pack_issues(detections)
    cat = load_catalogue(detections)
    alert = {
        "timestamp": "2026-10-05T10:00:03.000+0000",
        "id": "1.2",
        "rule": {"id": "100103"},
        "agent": {"id": "001", "name": "ubuntu-endpoint"},
        "data": {"srcip": "10.10.10.50", "dstuser": "root"},
        "full_log": "sshd[1]: Failed password for root from 10.10.10.50",
    }
    findings = wazuh5.findings_from_wazuh4([alert], pack, cat)
    assert sorted(f["wazuh"]["rule"]["title"] for f in findings) == [
        "SSH failed login",
        "SSH failed login as root",
    ]
    assert len({f["wazuh"]["event"]["id"] for f in findings}) == 1
    assert findings[0]["source"]["ip"] == "10.10.10.50"
    assert findings[0]["@timestamp"] == "2026-10-05T10:00:03.000Z"


def test_windows_member_events_name_the_member(detections):
    pack, _ = _pack_issues(detections)
    alert = {
        "timestamp": "2026-10-05T11:00:00.000+0000",
        "id": "9",
        "rule": {"id": "100205"},
        "agent": {"id": "002", "name": "win11-endpoint"},
        "data": {"win": {"system": {"eventID": "4732"}, "eventdata": {"memberName": "lab"}}},
    }
    (found,) = wazuh5.findings_from_wazuh4([alert], pack, load_catalogue(detections))
    assert found["user"]["name"] == "lab"
    assert found["event"]["code"] == "4732"
