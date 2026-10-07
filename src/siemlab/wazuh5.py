"""The Wazuh 5 content pack in ``detections/wazuh5``: load, validate, bundle, and convert.

Wazuh 5 replaces XML rules with Sigma-format rules that the indexer evaluates against events
normalized to the Wazuh Common Schema (WCS). Rules belong to an *integration*, and every
match becomes a *finding* in ``wazuh-findings-v5-*``. The pack layout is::

    detections/wazuh5/
      migration.yml                 where every Wazuh 4.x rule went
      <integration>/integration.yml the integration resource (its title names the integration)
      <integration>/rules/*.yml     one rule resource per file, exactly as the API takes it
      <integration>/logtest.yml     sample events and the rule titles each must match

Checks (errors fail CI, warnings are reported):

  * integrations: a valid title and author, and one of the eight categories Wazuh accepts;
  * rules: required fields and closed value sets, ``logsource.product`` equal to the
    integration title, unique titles, no ``id`` (the server assigns it);
  * detection fields exist in the WCS (``data/wcs-events-5.0.0.txt``), modifiers are ones
    Wazuh supports, regular expressions compile, and the condition names real selections;
    a field the WCS stores without indexing is a warning, because a rule on it may never match;
  * MITRE blocks have parallel ``id``/``name`` arrays whose names and tactics agree with
    :mod:`siemlab.mitre`;
  * every Wazuh 4.x rule appears in ``migration.yml``, pointing at a rule that names it in
    its references, or at the siemlab correlation that replaces it;
  * logtest expectations name rules of the same integration.
"""

from __future__ import annotations

import copy
import fnmatch
import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from . import mitre
from .validate import Catalogue, Issue

CATEGORIES = frozenset(
    {
        "access-management",
        "applications",
        "cloud-services",
        "network-activity",
        "other",
        "security",
        "system-activity",
        "unclassified",
    }
)
LEVELS = ("informational", "low", "medium", "high", "critical")
STATUSES = frozenset({"stable", "experimental", "test", "deprecated", "unsupported"})
MODIFIERS = frozenset(
    {
        "contains",
        "startswith",
        "endswith",
        "re",
        "i",
        "m",
        "s",
        "exists",
        "cidr",
        "all",
        "base64",
        "base64offset",
        "wide",
        "windash",
        "lt",
        "lte",
        "gt",
        "gte",
    }
)
# The correlations in siemlab.correlate that stand in for Wazuh 4.x counting rules.
SIEMLAB_TARGETS = frozenset({"brute_force", "credential_compromise", "content_discovery"})

_TITLE = re.compile(r'^[^\s\\/:*?"<>|]+$')
_TAG = re.compile(r"^[a-z0-9_-]+\.[a-z0-9_.-]+$")
_MIGRATED = re.compile(r"^Migrated from Wazuh 4\.x rule (\d+)$")
_CONDITION_WORDS = frozenset({"and", "or", "not", "of", "all", "them"})


def wcs_fields() -> dict[str, bool]:
    """WCS event field -> whether it is indexed (searchable)."""
    text = resources.files("siemlab").joinpath("data/wcs-events-5.0.0.txt").read_text("utf-8")
    fields: dict[str, bool] = {}
    for line in text.splitlines():
        if line and not line.startswith("#"):
            name, _, flag = line.partition(" ")
            fields[name] = flag != "noindex"
    return fields


@dataclass(frozen=True)
class Integration:
    title: str
    category: str
    directory: str
    doc: dict[str, Any]


@dataclass(frozen=True)
class Rule:
    title: str
    level: str
    integration: str
    file: str  # relative to the pack, e.g. lab-ssh/rules/ssh-failed-login.yml
    sources: tuple[int, ...]  # Wazuh 4.x rule IDs it was migrated from
    techniques: tuple[str, ...]  # technique and sub-technique IDs
    tags: tuple[str, ...]
    doc: dict[str, Any]


@dataclass(frozen=True)
class LogtestCase:
    integration: str
    location: str
    event: str
    expect: tuple[str, ...]


@dataclass
class Pack:
    integrations: list[Integration] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)
    migration: dict[int, dict[str, str]] = field(default_factory=dict)
    logtests: list[LogtestCase] = field(default_factory=list)

    def rule_by_file(self) -> dict[str, Rule]:
        return {r.file: r for r in self.rules}

    def rule_by_title(self) -> dict[str, Rule]:
        return {r.title: r for r in self.rules}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _yaml(path: Path, root: Path, issues: list[Issue]) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        issues.append(Issue("error", path.relative_to(root).as_posix(), f"invalid YAML: {exc}"))
        return None


# -- loading ---------------------------------------------------------------------------------


def load_pack(pack_dir: Path, issues: list[Issue]) -> Pack | None:
    """Load and validate the pack. Returns None when the directory does not exist."""
    if not pack_dir.is_dir():
        return None
    root = pack_dir.parent.parent  # repository root: locations read detections/wazuh5/...
    pack = Pack()
    fields = wcs_fields()
    for directory in sorted(p for p in pack_dir.iterdir() if p.is_dir()):
        integration = _load_integration(directory, root, issues)
        if integration is None:
            continue
        pack.integrations.append(integration)
        for path in sorted((directory / "rules").glob("*.yml")):
            rule = _load_rule(path, pack_dir, root, integration, fields, issues)
            if rule is not None:
                pack.rules.append(rule)
        logtest = directory / "logtest.yml"
        if logtest.exists():
            pack.logtests.extend(_load_logtests(logtest, root, integration, issues))
    _check_unique(pack, issues)
    _check_logtests(pack, issues)
    migration = pack_dir / "migration.yml"
    if migration.exists():
        doc = _yaml(migration, root, issues)
        rules = doc.get("rules") if isinstance(doc, dict) else None
        if isinstance(rules, dict):
            pack.migration = {
                int(k): v for k, v in rules.items() if isinstance(v, dict) and str(k).isdigit()
            }
        else:
            issues.append(Issue("error", _rel(migration, root), "expected a 'rules' mapping"))
    else:
        issues.append(Issue("error", _rel(pack_dir, root), "missing migration.yml"))
    return pack


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _load_integration(directory: Path, root: Path, issues: list[Issue]) -> Integration | None:
    path = directory / "integration.yml"
    where = _rel(path, root)
    if not path.exists():
        issues.append(Issue("error", _rel(directory, root), "missing integration.yml"))
        return None
    doc = _yaml(path, root, issues)
    if not isinstance(doc, dict):
        issues.append(Issue("error", where, "integration must be a mapping"))
        return None
    meta = _mapping(doc.get("metadata"))
    title = str(meta.get("title", ""))
    if not _TITLE.match(title):
        issues.append(Issue("error", where, f"title {title!r} must be non-empty, no spaces"))
    elif title != directory.name:
        issues.append(Issue("error", where, f"title {title!r} differs from its directory"))
    if not meta.get("author"):
        issues.append(Issue("error", where, "missing metadata.author"))
    category = str(doc.get("category", ""))
    if category not in CATEGORIES:
        issues.append(Issue("error", where, f"category {category!r} is not one Wazuh accepts"))
    if "id" in doc:
        issues.append(Issue("error", where, "remove 'id': the server assigns it"))
    return Integration(title, category, directory.name, doc)


def _load_rule(
    path: Path,
    pack_dir: Path,
    root: Path,
    integration: Integration,
    fields: Mapping[str, bool],
    issues: list[Issue],
) -> Rule | None:
    doc = _yaml(path, root, issues)
    rel = _rel(path, root)
    if not isinstance(doc, dict):
        issues.append(Issue("error", rel, "rule must be a mapping"))
        return None
    meta = _mapping(doc.get("metadata"))
    title = str(meta.get("title", "")).strip()
    where = f"{rel} '{title or '?'}'"
    if not title:
        issues.append(Issue("error", where, "missing metadata.title"))
    if "id" in doc:
        issues.append(Issue("error", where, "remove 'id': the server assigns it"))
    if doc.get("status") not in STATUSES:
        issues.append(Issue("error", where, f"status must be one of {sorted(STATUSES)}"))
    level = str(doc.get("level", ""))
    if level not in LEVELS:
        issues.append(Issue("error", where, f"level must be one of {list(LEVELS)}"))
    if not isinstance(doc.get("enabled", True), bool):
        issues.append(Issue("error", where, "enabled must be true or false"))
    logsource = _mapping(doc.get("logsource"))
    if logsource.get("product") != integration.title:
        issues.append(Issue("error", where, f"logsource.product must be {integration.title!r}"))
    _check_detection(doc.get("detection"), fields, where, issues)
    tags = tuple(str(t) for t in doc.get("tags") or ())
    for tag in tags:
        if not _TAG.match(tag):
            issues.append(Issue("error", where, f"tag {tag!r} is not a namespace.name pair"))
    techniques = _check_mitre(doc.get("mitre"), tags, where, issues)

    sources: list[int] = []
    for ref in meta.get("references") or ():
        match = _MIGRATED.match(str(ref))
        if match:
            sources.append(int(match.group(1)))
    return Rule(
        title=title,
        level=level,
        integration=integration.title,
        file=path.relative_to(pack_dir).as_posix(),
        sources=tuple(sources),
        techniques=techniques,
        tags=tags,
        doc=doc,
    )


def _check_detection(
    detection: Any, fields: Mapping[str, bool], where: str, issues: list[Issue]
) -> None:
    if not isinstance(detection, dict) or not isinstance(detection.get("condition"), str):
        issues.append(Issue("error", where, "detection needs a 'condition' string"))
        return
    searches = {k: v for k, v in detection.items() if k != "condition"}
    if not searches:
        issues.append(Issue("error", where, "detection has no selection or keywords"))
    for name, search in searches.items():
        if isinstance(search, list):  # keywords: values only, matched anywhere in the event
            if not search or not all(isinstance(v, (str, int)) for v in search):
                issues.append(Issue("error", where, f"{name!r} must be a non-empty value list"))
            continue
        if not isinstance(search, dict) or not search:
            issues.append(Issue("error", where, f"selection {name!r} must be a non-empty map"))
            continue
        for key, value in search.items():
            _check_field(str(key), value, fields, f"{where} {name}", issues)

    used: set[str] = set()
    for token in re.findall(r"[A-Za-z_][\w*]*", detection["condition"]):
        if token in _CONDITION_WORDS:
            continue
        matched = fnmatch.filter(searches, token) if "*" in token else [token] * (token in searches)
        if not matched:
            issues.append(Issue("error", where, f"condition names unknown selection {token!r}"))
        used.update(matched)
    for name in sorted(set(searches) - used):
        issues.append(Issue("warning", where, f"selection {name!r} is not used in the condition"))


def _check_field(
    key: str, value: Any, fields: Mapping[str, bool], where: str, issues: list[Issue]
) -> None:
    name, *modifiers = key.split("|")
    if name not in fields:
        issues.append(Issue("error", where, f"{name!r} is not a WCS field"))
    elif not fields[name]:
        issues.append(
            Issue("warning", where, f"{name!r} is not indexed in the WCS: verify with logtest")
        )
    for modifier in modifiers:
        if modifier not in MODIFIERS:
            issues.append(Issue("error", where, f"unsupported modifier {modifier!r}"))
    values = value if isinstance(value, list) else [value]
    if not values or not all(isinstance(v, (str, int, bool)) for v in values):
        issues.append(Issue("error", where, f"{key}: values must be strings, numbers or booleans"))
        return
    if "re" in modifiers:
        flags = re.IGNORECASE if "i" in modifiers else 0
        for v in values:
            try:
                re.compile(str(v), flags)
            except re.error as exc:
                issues.append(Issue("error", where, f"{key}: invalid regex: {exc}"))


def _check_mitre(
    block: Any, tags: tuple[str, ...], where: str, issues: list[Issue]
) -> tuple[str, ...]:
    if block is None:
        return ()
    if not isinstance(block, dict):
        issues.append(Issue("error", where, "mitre must be a mapping"))
        return ()
    pairs: dict[str, list[tuple[str, str]]] = {}
    for part in ("tactic", "technique", "subtechnique"):
        entry = block.get(part)
        if entry is None:
            pairs[part] = []
            continue
        ids = entry.get("id") if isinstance(entry, dict) else None
        names = entry.get("name") if isinstance(entry, dict) else None
        if not isinstance(ids, list) or not isinstance(names, list) or len(ids) != len(names):
            issues.append(Issue("error", where, f"mitre.{part} needs parallel id and name lists"))
            pairs[part] = []
            continue
        pairs[part] = [(str(i), str(n)) for i, n in zip(ids, names, strict=True)]

    techniques = [i for i, _ in pairs["technique"]]
    for tid, tname in pairs["technique"] + pairs["subtechnique"]:
        expected = mitre.technique_name(tid)
        if expected is None:
            issues.append(Issue("warning", where, f"{tid} missing from siemlab.mitre"))
        elif expected != tname:
            issues.append(Issue("error", where, f"{tid} is named {expected!r}, not {tname!r}"))
    for sid, _ in pairs["subtechnique"]:
        if "." not in sid:
            issues.append(Issue("error", where, f"{sid} is a technique, not a sub-technique"))
        elif sid.split(".")[0] not in techniques:
            issues.append(Issue("error", where, f"{sid}: add its parent to mitre.technique"))
    for tid in techniques:
        if "." in tid:
            issues.append(Issue("error", where, f"{tid} belongs under mitre.subtechnique"))

    detected = [s for s, _ in pairs["subtechnique"]] + [
        t for t in techniques if not any(s.startswith(t + ".") for s, _ in pairs["subtechnique"])
    ]
    tactics = dict(pairs["tactic"])
    for t in detected:
        tactic = mitre.tactic(t)
        tactic_id = mitre.TACTIC_IDS.get(tactic)
        if tactic_id and tactics.get(tactic_id) != tactic:
            issues.append(Issue("error", where, f"{t} needs tactic {tactic_id} {tactic}"))
        if f"attack.{t.lower()}" not in tags:
            issues.append(Issue("warning", where, f"tags lack attack.{t.lower()}"))
    for tactic_id, tactic_name in pairs["tactic"]:
        if mitre.TACTIC_IDS.get(tactic_name) != tactic_id:
            issues.append(Issue("error", where, f"tactic {tactic_id} is not {tactic_name!r}"))
    return tuple(detected)


def _load_logtests(
    path: Path, root: Path, integration: Integration, issues: list[Issue]
) -> list[LogtestCase]:
    doc = _yaml(path, root, issues)
    cases = doc.get("logtest") if isinstance(doc, dict) else None
    if not isinstance(cases, list):
        issues.append(Issue("error", _rel(path, root), "expected a 'logtest' list"))
        return []
    out = []
    for n, case in enumerate(cases, start=1):
        if not isinstance(case, dict) or not all(k in case for k in ("location", "event")):
            issues.append(Issue("error", f"{_rel(path, root)} case {n}", "needs location, event"))
            continue
        expect = case.get("expect") or []
        out.append(
            LogtestCase(
                integration.title,
                str(case["location"]),
                str(case["event"]),
                tuple(str(t) for t in expect),
            )
        )
    return out


def _check_unique(pack: Pack, issues: list[Issue]) -> None:
    seen: dict[str, str] = {}
    for r in pack.rules:
        if r.title and r.title in seen:
            issues.append(Issue("error", r.file, f"title {r.title!r} also used by {seen[r.title]}"))
        seen.setdefault(r.title, r.file)


def _check_logtests(pack: Pack, issues: list[Issue]) -> None:
    titles = {(r.integration, r.title) for r in pack.rules}
    for case in pack.logtests:
        for title in case.expect:
            if (case.integration, title) not in titles:
                issues.append(
                    Issue("error", f"{case.integration}/logtest.yml", f"no rule titled {title!r}")
                )


def check_migration(pack: Pack, cat: Catalogue, issues: list[Issue]) -> None:
    """Every Wazuh 4.x rule must be accounted for, and every claim must be backed by a rule."""
    where = "detections/wazuh5/migration.yml"
    by_file = pack.rule_by_file()
    old_ids = {r.id for r in cat.wazuh}
    for rule_id in sorted(old_ids - set(pack.migration)):
        issues.append(Issue("error", where, f"Wazuh 4.x rule {rule_id} is not mapped"))
    for rule_id, entry in sorted(pack.migration.items()):
        target = str(entry.get("to", ""))
        if rule_id not in old_ids:
            issues.append(Issue("error", where, f"{rule_id} is not a Wazuh 4.x rule here"))
        if target.startswith("siemlab:"):
            if target.removeprefix("siemlab:") not in SIEMLAB_TARGETS:
                issues.append(Issue("error", where, f"{rule_id}: unknown correlation {target!r}"))
        elif target not in by_file:
            issues.append(Issue("error", where, f"{rule_id}: no rule file {target!r}"))
        elif rule_id not in by_file[target].sources:
            issues.append(
                Issue("error", where, f"{target} does not say it was migrated from {rule_id}")
            )
    for r in pack.rules:
        for rule_id in r.sources:
            if pack.migration.get(rule_id, {}).get("to") != r.file:
                issues.append(Issue("error", r.file, f"migration.yml does not map {rule_id} here"))


# -- bundle for the Content Manager API ------------------------------------------------------


def bundle(pack: Pack, out: Path) -> list[Path]:
    """Write the JSON request bodies deploy-wazuh5-content.sh sends, plus a manifest."""
    written: list[Path] = []

    def write(rel: str, obj: Any) -> None:
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8", newline="\n")
        written.append(path)

    manifest = []
    for integ in pack.integrations:
        rules = [r for r in pack.rules if r.integration == integ.title]
        write(f"integrations/{integ.title}.json", {"resource": integ.doc})
        rule_files = []
        for r in rules:
            name = f"rules/{integ.title}/{Path(r.file).stem}.json"
            write(name, {"resource": r.doc})
            rule_files.append(name)
        cases = [c for c in pack.logtests if c.integration == integ.title]
        write(
            f"logtest/{integ.title}.json",
            [{"location": c.location, "event": c.event, "expect": list(c.expect)} for c in cases],
        )
        manifest.append(
            {
                "integration": f"integrations/{integ.title}.json",
                "title": integ.title,
                "rules": rule_files,
                "logtest": f"logtest/{integ.title}.json",
            }
        )
    write("manifest.json", manifest)
    return written


# -- Wazuh 4.x alerts -> Wazuh 5 findings (synthetic data) -----------------------------------

# The event behind a 4.x aggregate or built-in alert, as the 5.x rule that would see it.
# Aggregates (100101, 100201, 100504) replace the alert of the event that triggered them, and
# 100102 replaces the successful login.
EVENT_RULES_4X: dict[int, tuple[str, ...]] = {
    100101: ("lab-ssh/rules/ssh-failed-login.yml",),
    100102: ("lab-ssh/rules/ssh-successful-login.yml",),
    100201: ("lab-windows-auth/rules/win-failed-logon.yml",),
    100504: ("lab-nginx/rules/web-sensitive-path-probe.yml",),
    5715: ("lab-ssh/rules/ssh-successful-login.yml",),
    60106: ("lab-windows-auth/rules/win-network-logon.yml",),
}


def _flatten(data: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, Mapping):
            out.update(_flatten(value, f"{prefix}{key}."))
        else:
            out[f"{prefix}{key}"] = value
    return out


def _wcs_event(doc: Mapping[str, Any]) -> dict[str, Any]:
    """The WCS event a 4.x alert was made from (the fields siemlab reads)."""
    data = _flatten(doc.get("data") or {})
    event: dict[str, Any] = {
        "@timestamp": _iso(str(doc["timestamp"])),
        "event": {"original": doc.get("full_log", "")},
        "message": doc.get("full_log", ""),
        "wazuh": {
            "agent": {"id": doc["agent"]["id"], "name": doc["agent"]["name"]},
            "event": {"id": hashlib.sha1(str(doc["id"]).encode()).hexdigest()[:16]},
            "protocol": {"location": doc.get("location", "")},
        },
    }
    src = data.get("srcip") or data.get("src_ip") or data.get("win.eventdata.ipAddress")
    if src:
        event["source"] = {"ip": src}
    user = data.get("dstuser") or data.get("srcuser") or data.get("win.eventdata.targetUserName")
    if data.get("win.system.eventID") in {"4732"}:
        user = data.get("win.eventdata.memberName") or data.get("win.eventdata.memberSid")
    if user:
        event["user"] = {"name": user}
    if data.get("url"):
        event["url"] = {"original": data["url"]}
    if data.get("win.system.eventID"):
        event["event"]["code"] = str(data["win.system.eventID"])
    if isinstance(doc.get("syscheck"), Mapping) and doc["syscheck"].get("path"):
        event["file"] = {"path": doc["syscheck"]["path"]}
    return event


def _iso(timestamp: str) -> str:
    # 2026-10-05T09:10:02.123+0000 -> 2026-10-05T09:10:02.123Z
    return re.sub(r"\+0000$", "Z", timestamp)


def finding(event: Mapping[str, Any], rule: Rule) -> dict[str, Any]:
    """An enriched finding: the event plus the rule under ``wazuh.rule``."""
    doc: dict[str, Any] = copy.deepcopy(dict(event))
    rule_doc: dict[str, Any] = {
        "id": hashlib.sha1(rule.file.encode()).hexdigest()[:32],
        "title": rule.title,
        "level": rule.level,
        "status": rule.doc.get("status"),
        "tags": [rule.level, rule.integration, *rule.tags],
    }
    if isinstance(rule.doc.get("mitre"), dict):
        rule_doc["mitre"] = rule.doc["mitre"]
    doc["wazuh"]["rule"] = rule_doc
    return doc


def findings_from_wazuh4(
    docs: Iterable[Mapping[str, Any]], pack: Pack, cat: Catalogue
) -> list[dict[str, Any]]:
    """Convert synthetic 4.x alerts into the findings the 5.x pack would produce.

    One 4.x alert is one event. In 5.x that event produces a finding for *every* matching rule:
    the rule the 4.x alert ended on, plus the migrated versions of its custom parent rules.
    """
    by_file = pack.rule_by_file()
    old = cat.by_id()
    out: list[dict[str, Any]] = []
    for doc in docs:
        rule_id = int(doc["rule"]["id"])
        files: list[str] = list(EVENT_RULES_4X.get(rule_id, ()))
        queue = [rule_id]
        while queue:
            current = queue.pop()
            target = str(pack.migration.get(current, {}).get("to", ""))
            if target in by_file and target not in files:
                files.append(target)
            if current in old:
                queue.extend(p for p in old[current].parents if p in old)
        event = _wcs_event(doc)
        out.extend(finding(event, by_file[f]) for f in files)
    return out
