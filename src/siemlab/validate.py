"""Static validation of the detection content, and the ATT&CK coverage matrix built from it.

Checks (errors fail CI, warnings are reported):

Wazuh rules (``detections/**/*.xml``)
  * well-formed XML; every rule has an ``id``, a ``level`` (0-16) and a description;
  * IDs are unique, inside the custom range 100000-119999, and inside the block named by
    the file (``100200-....xml`` holds 100200-100299, or 100350-100399 for ``100350-...``);
  * references to *custom* parents (``if_sid`` / ``if_matched_sid``) point at rules that exist;
  * frequency rules have ``timeframe`` and an ``if_matched_*`` parent;
  * ATT&CK IDs are well-formed (warning if the lab's technique table does not know them);
    rules without a mapping are listed in the coverage report rather than flagged.

Sigma rules (``detections/sigma/**/*.yml``)
  * parsed with pySigma when installed (rule references in correlations are resolved);
  * otherwise a structural check of the required keys;
  * IDs unique; detection rules carry an ``attack.tXXXX`` tag.

Suricata rules (``detections/**/*.rules``)
  * every rule has ``msg``, a unique ``sid`` in the local range 1000000-1999999, and ``rev``.

The Wazuh 5 content pack (``detections/wazuh5``) is validated by :mod:`siemlab.wazuh5`.
"""

from __future__ import annotations

import re
import uuid
import xml.etree.ElementTree as ET
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from . import mitre

if TYPE_CHECKING:
    from .wazuh5 import Pack

CUSTOM_RANGE = range(100000, 120000)
SURICATA_LOCAL_RANGE = range(1000000, 2000000)
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
_FILE_BLOCK = re.compile(r"^(\d{6})-")


@dataclass(frozen=True)
class Issue:
    severity: str  # "error" | "warning"
    location: str
    message: str

    def __str__(self) -> str:
        return f"{self.severity.upper():7} {self.location}: {self.message}"


@dataclass(frozen=True)
class WazuhRule:
    id: int
    level: int
    description: str
    groups: tuple[str, ...]
    techniques: tuple[str, ...]
    parents: tuple[int, ...]
    matched_parents: tuple[int, ...]
    file: str


@dataclass(frozen=True)
class SigmaInfo:
    id: str
    title: str
    level: str
    kind: str  # "rule" | "correlation"
    techniques: tuple[str, ...]
    file: str


@dataclass
class Catalogue:
    wazuh: list[WazuhRule] = field(default_factory=list)
    sigma: list[SigmaInfo] = field(default_factory=list)
    suricata_sids: list[int] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "error"]

    def by_id(self) -> dict[int, WazuhRule]:
        return {r.id: r for r in self.wazuh}


def _ids(text: str | None) -> tuple[int, ...]:
    if not text:
        return ()
    return tuple(int(x) for x in re.split(r"[,\s]+", text.strip()) if x.isdigit())


def _split_groups(text: str | None) -> list[str]:
    return [g for g in (text or "").replace(" ", "").split(",") if g]


# -- Wazuh -----------------------------------------------------------------------------------


def parse_wazuh_file(path: Path, root: Path, issues: list[Issue]) -> list[WazuhRule]:
    rel = path.relative_to(root).as_posix()
    try:
        # Wazuh rule files have several top-level <group> elements: wrap them to parse.
        tree = ET.fromstring(f"<root>{path.read_text(encoding='utf-8')}</root>")
    except ET.ParseError as exc:
        issues.append(Issue("error", rel, f"invalid XML: {exc}"))
        return []

    rules: list[WazuhRule] = []
    for child in tree:
        if child.tag == "var":
            continue
        if child.tag != "group" or child.get("name") is None:
            label = f"<{child.tag}>" if child.tag != "group" else "<group> without a name"
            issues.append(
                Issue("error", rel, f"{label} at top level: Wazuh only accepts named <group>s")
            )
    for group in tree.findall("group"):
        if group.get("name") is None:
            continue
        outer = _split_groups(group.get("name"))
        for rule in group.findall("rule"):
            where = f"{rel} rule {rule.get('id', '?')}"
            try:
                rule_id, level = int(rule.get("id", "")), int(rule.get("level", ""))
            except ValueError:
                issues.append(Issue("error", where, "missing or non-numeric id/level"))
                continue
            description = (rule.findtext("description") or "").strip()
            techniques = tuple((e.text or "").strip() for e in rule.findall("mitre/id"))
            inner = [g for e in rule.findall("group") for g in _split_groups(e.text)]
            frequency = rule.get("frequency")
            matched = _ids(rule.findtext("if_matched_sid"))

            if not 0 <= level <= 16:
                issues.append(Issue("error", where, f"level {level} outside 0-16"))
            if not description:
                issues.append(Issue("error", where, "missing <description>"))
            if frequency and not rule.get("timeframe"):
                issues.append(Issue("error", where, "frequency rule without timeframe"))
            if frequency and not (matched or rule.find("if_matched_group") is not None):
                issues.append(Issue("error", where, "frequency rule without if_matched_*"))
            for t in techniques:
                if not _TECHNIQUE.match(t):
                    issues.append(Issue("error", where, f"malformed ATT&CK id {t!r}"))
                elif t not in mitre.TECHNIQUES:
                    issues.append(Issue("warning", where, f"{t} missing from siemlab.mitre"))

            rules.append(
                WazuhRule(
                    id=rule_id,
                    level=level,
                    description=description,
                    groups=tuple(dict.fromkeys(outer + inner)),
                    techniques=techniques,
                    parents=_ids(rule.findtext("if_sid")),
                    matched_parents=matched,
                    file=rel,
                )
            )
    return rules


def _check_wazuh(rules: list[WazuhRule], issues: list[Issue]) -> None:
    seen: dict[int, str] = {}
    known = {r.id for r in rules}
    for r in rules:
        where = f"{r.file} rule {r.id}"
        if r.id in seen:
            issues.append(Issue("error", where, f"duplicate id (also in {seen[r.id]})"))
        seen.setdefault(r.id, r.file)
        if r.id not in CUSTOM_RANGE:
            issues.append(Issue("error", where, "id outside the custom range 100000-119999"))
        block = _FILE_BLOCK.match(Path(r.file).name)
        if block:
            start = int(block.group(1))
            if not start <= r.id < start + 100 - (start % 100):
                issues.append(Issue("error", where, f"id outside the file's block {start}+"))
        for parent in (*r.parents, *r.matched_parents):
            if parent in CUSTOM_RANGE and parent not in known:
                issues.append(Issue("error", where, f"references unknown custom rule {parent}"))


# -- Sigma -----------------------------------------------------------------------------------


def _sigma_techniques(tags: Iterable[Any]) -> tuple[str, ...]:
    out = []
    for tag in tags or ():
        text = str(tag).lower()
        if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", text):
            out.append(text.split(".", 1)[1].upper())
    return tuple(out)


def _pysigma_parse(text: str) -> tuple[Any, str | None]:
    """Parse one file with pySigma, the reference parser. Returns (collection, error).

    Rule references (correlations naming their base rules) are resolved later, across all
    files at once, so a correlation may live in a different file from its base rule.
    """
    try:
        from sigma.collection import SigmaCollection
    except ImportError:  # pragma: no cover - pySigma is a dev dependency
        return None, None
    try:
        return SigmaCollection.from_yaml(text, resolve_references=False), None
    except Exception as exc:  # pySigma raises many exception types
        return None, str(exc)


def _pysigma_resolve(collections: list[Any], issues: list[Issue]) -> None:
    if not collections:
        return
    from sigma.collection import SigmaCollection

    try:
        SigmaCollection.merge(collections)  # resolves references across every file
    except Exception as exc:  # pySigma raises many exception types
        issues.append(Issue("error", "detections/sigma", f"pySigma: {exc}"))


def parse_sigma_file(
    path: Path, root: Path, issues: list[Issue], collections: list[Any] | None = None
) -> list[SigmaInfo]:
    rel = path.relative_to(root).as_posix()
    text = path.read_text(encoding="utf-8")
    try:
        docs = [d for d in yaml.safe_load_all(text) if d]
    except yaml.YAMLError as exc:
        issues.append(Issue("error", rel, f"invalid YAML: {exc}"))
        return []

    collection, error = _pysigma_parse(text)
    if error:
        issues.append(Issue("error", rel, f"pySigma: {error}"))
    elif collection is not None and collections is not None:
        collections.append(collection)

    infos = []
    for doc in docs:
        if not isinstance(doc, dict):
            issues.append(Issue("error", rel, "YAML document is not a mapping"))
            continue
        title = str(doc.get("title", ""))
        where = f"{rel} '{title or '?'}'"
        kind = "correlation" if "correlation" in doc else "rule"
        required: tuple[str, ...] = ("title", "id", "status", "level", "author", "date")
        required += ("correlation",) if kind == "correlation" else ("logsource", "detection")
        for key in required:
            if key not in doc:
                issues.append(Issue("error", where, f"missing '{key}'"))
        try:
            uuid.UUID(str(doc.get("id", "")))
        except ValueError:
            issues.append(Issue("error", where, "id is not a UUID"))
        techniques = _sigma_techniques(doc.get("tags", ()))
        if kind == "rule" and not techniques:
            issues.append(Issue("warning", where, "no attack.tXXXX tag"))
        infos.append(
            SigmaInfo(str(doc.get("id")), title, str(doc.get("level", "")), kind, techniques, rel)
        )
    return infos


# -- Suricata --------------------------------------------------------------------------------

_SID = re.compile(r"\bsid\s*:\s*(\d+)\s*;")


_ACTION = re.compile(r"^(alert|drop|pass|reject(src|dst|both)?)\s")
_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')


def _suricata_rules(text: str) -> list[tuple[int, str]]:
    """(first line number, rule text) with backslash continuation lines joined."""
    rules: list[tuple[int, str]] = []
    pending, start = "", 0
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not pending and (not line or line.startswith("#")):
            continue
        if not pending:
            start = number
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        rules.append((start, pending + line))
        pending = ""
    if pending:
        rules.append((start, pending.strip()))
    return rules


def parse_suricata_file(path: Path, root: Path, issues: list[Issue]) -> list[int]:
    rel = path.relative_to(root).as_posix()
    sids = []
    for number, line in _suricata_rules(path.read_text(encoding="utf-8")):
        where = f"{rel}:{number}"
        if not _ACTION.match(line) or not line.endswith(")"):
            issues.append(Issue("error", where, "not a Suricata rule (action ... (options;))"))
            continue
        options = _QUOTED.sub('""', line)  # keywords inside msg/content strings do not count
        for keyword in ("msg:", "rev:"):
            if keyword not in options:
                issues.append(Issue("error", where, f"missing {keyword[:-1]}"))
        match = _SID.search(options)
        if not match:
            issues.append(Issue("error", where, "missing sid"))
            continue
        sid = int(match.group(1))
        if sid not in SURICATA_LOCAL_RANGE:
            issues.append(Issue("error", where, f"sid {sid} outside the local range"))
        if sid in sids:
            issues.append(Issue("error", where, f"duplicate sid {sid}"))
        sids.append(sid)
    return sids


# -- entry points ----------------------------------------------------------------------------


def load_catalogue(detections: Path) -> Catalogue:
    if not detections.is_dir():
        raise FileNotFoundError(f"detections directory not found: {detections}")
    root = detections.parent
    cat = Catalogue()
    for path in sorted(detections.rglob("*.xml")):
        cat.wazuh.extend(parse_wazuh_file(path, root, cat.issues))
    collections: list[Any] = []
    for path in sorted(detections.rglob("*.yml")):
        if {"wazuh5", "logtest"} & set(path.relative_to(detections).parts):
            continue  # Wazuh 5 rules are Sigma-like but not Sigma: see siemlab.wazuh5
        cat.sigma.extend(parse_sigma_file(path, root, cat.issues, collections))
    _pysigma_resolve(collections, cat.issues)
    sid_files: dict[int, str] = {}
    for path in sorted(detections.rglob("*.rules")):
        rel = path.relative_to(root).as_posix()
        for sid in parse_suricata_file(path, root, cat.issues):
            if sid_files.get(sid, rel) != rel:
                cat.issues.append(
                    Issue("error", rel, f"duplicate sid {sid} (also in {sid_files[sid]})")
                )
            sid_files.setdefault(sid, rel)
            cat.suricata_sids.append(sid)
    if not cat.wazuh:
        cat.issues.append(Issue("error", str(detections), "no Wazuh rules found"))
    _check_wazuh(cat.wazuh, cat.issues)
    seen: dict[str, str] = {}
    for s in cat.sigma:
        if s.id in seen:
            cat.issues.append(Issue("error", s.file, f"duplicate Sigma id {s.id} ({seen[s.id]})"))
        seen.setdefault(s.id, s.file)
    cat.wazuh.sort(key=lambda r: r.id)
    return cat


def coverage_markdown(cat: Catalogue, pack: Pack | None = None) -> str:
    """Deterministic Markdown: ATT&CK coverage matrix plus the full Wazuh rule catalogue."""
    wazuh_by_t: dict[str, list[int]] = defaultdict(list)
    sigma_by_t: dict[str, list[str]] = defaultdict(list)
    wazuh5_by_t: dict[str, list[str]] = defaultdict(list)
    for r in cat.wazuh:
        for t in r.techniques:
            wazuh_by_t[t].append(r.id)
    for s in cat.sigma:
        for t in s.techniques:
            sigma_by_t[t].append(s.title)
    for w in pack.rules if pack else ():
        for t in w.techniques:
            wazuh5_by_t[t].append(w.title)
    techniques = sorted(
        set(wazuh_by_t) | set(sigma_by_t) | set(wazuh5_by_t),
        key=lambda t: (
            mitre.TACTIC_ORDER.index(mitre.tactic(t))
            if mitre.tactic(t) in mitre.TACTIC_ORDER
            else 99,
            t,
        ),
    )

    lines = [
        "# Detection coverage",
        "",
        "<!-- Generated by `siemlab coverage --write docs/detection-coverage.md`. Do not edit",
        "     by hand: CI fails if this file is out of date with the rules in detections/. -->",
        "",
        f"{len(cat.wazuh)} Wazuh rules, {len(cat.sigma)} Sigma rules and "
        f"{len(cat.suricata_sids)} Suricata signatures cover {len(techniques)} ATT&CK techniques.",
        *(
            [
                f"The Wazuh 5 content pack has {len(pack.rules)} rules in "
                f"{len(pack.integrations)} integrations; see "
                "[Wazuh 5 migration](#wazuh-5-migration).",
            ]
            if pack
            else []
        ),
        "Every rule is **written and statically validated in CI**. Lab validation status is",
        "tracked per project in the README roadmap.",
        "",
        "## ATT&CK coverage",
        "",
        "| Tactic | Technique | Wazuh rules | Sigma rules | Wazuh 5 rules |",
        "|---|---|---|---|---|",
    ]
    for t in techniques:
        rules = ", ".join(str(i) for i in sorted(wazuh_by_t.get(t, []))) or "-"
        sigma = "<br>".join(sorted(sigma_by_t.get(t, []))) or "-"
        wazuh5 = "<br>".join(sorted(wazuh5_by_t.get(t, []))) or "-"
        lines.append(
            f"| {mitre.tactic(t)} | [{t}]({mitre.url(t)}) {mitre.name(t)} | {rules} | {sigma} "
            f"| {wazuh5} |"
        )
    unmapped = [str(r.id) for r in cat.wazuh if not r.techniques]
    if unmapped:
        lines += [
            "",
            f"Rules without a technique mapping (generic escalations): {', '.join(unmapped)}.",
        ]
    lines += [
        "",
        "## Wazuh rule catalogue",
        "",
        "| ID | Level | Description | ATT&CK | File |",
        "|---|---|---|---|---|",
    ]
    for r in cat.wazuh:
        desc = r.description.replace("|", "\\|")
        lines.append(
            f"| {r.id} | {r.level} | {desc} | {', '.join(r.techniques) or '-'} | `{r.file}` |"
        )
    lines += [
        "",
        "## Sigma rules",
        "",
        "| Title | Type | Level | ATT&CK | File |",
        "|---|---|---|---|---|",
    ]
    for s in sorted(cat.sigma, key=lambda s: (s.file, s.title)):
        lines.append(
            f"| {s.title} | {s.kind} | {s.level} | {', '.join(s.techniques) or '-'} | `{s.file}` |"
        )
    if pack:
        lines += _migration_markdown(cat, pack)
    return "\n".join(lines) + "\n"


def _migration_markdown(cat: Catalogue, pack: Pack) -> list[str]:
    by_file = pack.rule_by_file()
    lines = [
        "",
        "## Wazuh 5 migration",
        "",
        "Where each Wazuh 4.x rule went (`detections/wazuh5/migration.yml`). Wazuh 5 rules match",
        "one event at a time, so the rules that count events moved into `siemlab correlate`.",
        "",
        "| 4.x rule | Level | Wazuh 5 | Level | Note |",
        "|---|---|---|---|---|",
    ]
    for r in cat.wazuh:
        entry = pack.migration.get(r.id, {})
        target = str(entry.get("to", "-"))
        note = str(entry.get("note", "")).replace("|", "\\|")
        if target in by_file:
            new = by_file[target]
            lines.append(f"| {r.id} | {r.level} | {new.title} | {new.level} | {note} |")
        else:
            lines.append(f"| {r.id} | {r.level} | `{target}` | - | {note} |")
    new_rules = [w.title for w in pack.rules if not w.sources]
    if new_rules:
        lines += ["", f"New in the Wazuh 5 pack (4.x used built-in rules): {', '.join(new_rules)}."]
    return lines
