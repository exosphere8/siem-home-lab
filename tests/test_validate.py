from pathlib import Path

import pytest

from siemlab.validate import coverage_markdown, load_catalogue


def test_repository_detections_have_no_errors(detections):
    cat = load_catalogue(detections)
    assert cat.errors == []
    assert len(cat.wazuh) >= 30
    assert len(cat.sigma) >= 10
    assert cat.suricata_sids == [1000001, 1000002, 1000003]


def test_coverage_document_is_up_to_date(detections):
    doc = detections.parent / "docs" / "detection-coverage.md"
    expected = coverage_markdown(load_catalogue(detections))
    assert doc.read_text(encoding="utf-8").replace("\r\n", "\n") == expected, (
        "run: siemlab coverage --write docs/detection-coverage.md"
    )


def _write(tmp_path: Path, name: str, text: str) -> Path:
    detections = tmp_path / "detections"
    path = detections / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return detections


RULE = (
    '<rule id="{id}" level="{level}"><if_sid>5700</if_sid><description>{desc}</description>'
    "<mitre><id>{mitre}</id></mitre></rule>"
)


def _rules(*bodies: str) -> str:
    return '<group name="local,">' + "".join(bodies) + "</group>"


@pytest.mark.parametrize(
    ("filename", "content", "message"),
    [
        ("linux/100100-a.xml", "<group name='x'><rule id='1'", "invalid XML"),
        (
            "linux/100100-a.xml",
            _rules(RULE.format(id=100100, level=20, desc="d", mitre="T1110")),
            "outside 0-16",
        ),
        (
            "linux/100100-a.xml",
            _rules(RULE.format(id=100100, level=5, desc="", mitre="T1110")),
            "missing <description>",
        ),
        (
            "linux/100100-a.xml",
            _rules(RULE.format(id=100100, level=5, desc="d", mitre="X1")),
            "malformed ATT&CK",
        ),
        (
            "linux/100100-a.xml",
            _rules(RULE.format(id=100250, level=5, desc="d", mitre="T1110")),
            "outside the file's block",
        ),
        (
            "linux/999-a.xml",
            _rules(RULE.format(id=5000, level=5, desc="d", mitre="T1110")),
            "custom range",
        ),
        (
            "linux/100100-a.xml",
            _rules(
                '<rule id="100100" level="5" frequency="5"><if_matched_sid>100199</if_matched_sid>'
                "<description>d</description></rule>"
            ),
            "without timeframe",
        ),
        (
            "linux/100100-a.xml",
            _rules(
                '<rule id="100100" level="5"><if_sid>100199</if_sid>'
                "<description>d</description></rule>"
            ),
            "unknown custom rule 100199",
        ),
    ],
)
def test_wazuh_errors_are_caught(tmp_path, filename, content, message):
    cat = load_catalogue(_write(tmp_path, filename, content))
    assert any(message in i.message for i in cat.errors), cat.issues


def test_duplicate_ids_across_files(tmp_path):
    body = _rules(RULE.format(id=100100, level=5, desc="d", mitre="T1110"))
    _write(tmp_path, "linux/100100-a.xml", body)
    detections = _write(tmp_path, "web/100100-b.xml", body)
    assert any("duplicate id" in i.message for i in load_catalogue(detections).errors)


def test_unknown_technique_is_only_a_warning(tmp_path):
    detections = _write(
        tmp_path,
        "linux/100100-a.xml",
        _rules(RULE.format(id=100100, level=5, desc="d", mitre="T9999")),
    )
    cat = load_catalogue(detections)
    assert cat.errors == []
    assert any("T9999" in i.message for i in cat.issues)


SIGMA = """title: T
id: {id}
status: experimental
author: me
date: 2026-10-05
level: low
tags: [attack.t1110]
logsource: {{product: linux, service: sshd}}
detection:
    keywords: ['x']
    condition: keywords
"""


def test_sigma_structure_and_duplicate_ids(tmp_path):
    good = SIGMA.format(id="d175d403-44ec-4f1d-88c0-03ccb4ad7404")
    _write(tmp_path, "sigma/a.yml", good)
    _write(tmp_path, "sigma/b.yml", good)
    detections = _write(
        tmp_path, "sigma/c.yml", SIGMA.format(id="not-a-uuid").replace("logsource", "nologsource")
    )
    messages = [i.message for i in load_catalogue(detections).errors]
    assert any("duplicate Sigma id" in m for m in messages)
    assert any("not a UUID" in m for m in messages)
    assert any("missing 'logsource'" in m for m in messages)


def test_sigma_invalid_yaml(tmp_path):
    detections = _write(tmp_path, "sigma/a.yml", "title: [unclosed")
    assert any("invalid YAML" in i.message for i in load_catalogue(detections).errors)


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ('alert tcp any any -> any any (msg:"x"; sid:5; rev:1;)', "outside the local range"),
        ('alert tcp any any -> any any (msg:"x"; rev:1;)', "missing sid"),
        ("alert tcp any any -> any any (sid:1000001; rev:1;)", "missing msg"),
        ("this is not a rule", "not a Suricata rule"),
    ],
)
def test_suricata_errors(tmp_path, line, message):
    detections = _write(tmp_path, "network/local.rules", f"# comment\n{line}\n")
    assert any(message in i.message for i in load_catalogue(detections).errors)


def test_suricata_duplicate_sid(tmp_path):
    rule = 'alert tcp any any -> any any (msg:"x"; sid:1000001; rev:1;)'
    detections = _write(tmp_path, "network/local.rules", f"{rule}\n{rule}\n")
    assert any("duplicate sid" in i.message for i in load_catalogue(detections).errors)
