"""Load Wazuh alerts (``/var/ossec/logs/alerts/alerts.json``) into a normalised model.

Wazuh writes one JSON object per line. Linux sources put the attacker address and account
in ``data.srcip`` / ``data.dstuser``; Windows event-channel alerts put them in
``data.win.eventdata.ipAddress`` / ``targetUserName``. :class:`Alert` hides that difference
so correlation logic can ask simple questions: who, where, when, which technique.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Wazuh timestamps look like 2026-10-05T10:00:01.123+0000 (no colon in the offset).
_OFFSET = re.compile(r"([+-]\d{2})(\d{2})$")
_EMPTY_VALUES = {"", "-", "::1", "127.0.0.1", "localhost"}
# Group-membership events: targetUserName is the *group*; the account is the member.
_WINDOWS_MEMBER_EVENTS = {"4728", "4729", "4732", "4733", "4756", "4757"}


def parse_timestamp(value: str) -> datetime:
    """Parse a Wazuh timestamp. A timestamp without a UTC offset is rejected, not guessed."""
    text = _OFFSET.sub(r"\1:\2", value.strip().replace("Z", "+00:00"))
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp {value!r} has no UTC offset")
    return parsed


def _get(obj: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text in _EMPTY_VALUES else text


def _as_list(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, list):
        return tuple(str(v) for v in value)
    return (str(value),)


@dataclass(frozen=True)
class Alert:
    timestamp: datetime
    rule_id: str
    level: int
    description: str
    groups: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    tactics: tuple[str, ...] = ()
    agent: str = "unknown"
    agent_ip: str | None = None
    src_ip: str | None = None
    user: str | None = None
    url: str | None = None
    file: str | None = None
    full_log: str = ""
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    @classmethod
    def from_wazuh(cls, doc: Any) -> Alert:
        if not isinstance(doc, dict):
            raise TypeError(f"alert must be a JSON object, not {type(doc).__name__}")
        rule = doc.get("rule") or {}
        data = doc.get("data") or {}
        win = _get(data, "win", "eventdata") or {}
        if not (isinstance(rule, dict) and isinstance(data, dict) and isinstance(win, dict)):
            raise TypeError("'rule', 'data' and 'data.win.eventdata' must be JSON objects")
        event_id = str(_get(data, "win", "system", "eventID") or "")
        if event_id in _WINDOWS_MEMBER_EVENTS:
            win_user = (
                win.get("memberName") if _clean(win.get("memberName")) else win.get("memberSid")
            )
        else:
            win_user = win.get("targetUserName")
        return cls(
            timestamp=parse_timestamp(str(doc["timestamp"])),
            rule_id=str(rule["id"]),
            level=int(rule.get("level", 0)),
            description=str(rule.get("description", "")),
            groups=_as_list(rule.get("groups")),
            techniques=_as_list(_get(rule, "mitre", "id")),
            tactics=_as_list(_get(rule, "mitre", "tactic")),
            agent=str(_get(doc, "agent", "name") or "unknown"),
            agent_ip=_clean(_get(doc, "agent", "ip")),
            # srcip: syslog decoders; src_ip: Suricata eve.json; ipAddress: Windows events.
            src_ip=_clean(data.get("srcip") or data.get("src_ip") or win.get("ipAddress")),
            user=_clean(data.get("dstuser") or data.get("srcuser") or win_user),
            url=_clean(data.get("url")),
            file=_clean(_get(doc, "syscheck", "path")),
            full_log=str(doc.get("full_log", "")),
            raw=doc,
        )

    def has_group(self, *names: str) -> bool:
        return any(g in self.groups for g in names)

    def has_technique(self, *prefixes: str) -> bool:
        """True if any MITRE id starts with one of ``prefixes`` (T1110 matches T1110.001)."""
        return any(t.startswith(p) for t in self.techniques for p in prefixes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "rule_id": self.rule_id,
            "level": self.level,
            "description": self.description,
            "agent": self.agent,
            "src_ip": self.src_ip,
            "user": self.user,
            "techniques": list(self.techniques),
        }


@dataclass
class LoadResult:
    alerts: list[Alert]
    skipped: int = 0


def parse_lines(lines: Iterable[str]) -> LoadResult:
    """Parse JSON-lines alerts; malformed lines are counted and skipped, never fatal."""
    alerts: list[Alert] = []
    skipped = 0
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            alerts.append(Alert.from_wazuh(json.loads(line)))
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            skipped += 1
            log.warning("line %d: skipped (%s: %s)", number, type(exc).__name__, exc)
    alerts.sort(key=lambda a: a.timestamp)
    return LoadResult(alerts, skipped)


def load(path: str | Path) -> LoadResult:
    # utf-8-sig: files saved by Windows tools often start with a byte-order mark.
    # errors="replace": one badly encoded byte must not abort the whole file.
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        return parse_lines(f)


def iter_json_lines(alerts: Iterable[dict[str, Any]]) -> Iterator[str]:
    for doc in alerts:
        yield json.dumps(doc, separators=(",", ":"), sort_keys=True)
