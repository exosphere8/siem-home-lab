"""Render incidents as Markdown incident reports.

The structure matches docs/incident-reports/TEMPLATE.md, so generated and hand-written
reports read the same.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from .correlate import Incident

SEVERITY_BADGE = {
    "critical": "🔴 Critical",
    "high": "🟠 High",
    "medium": "🟡 Medium",
    "low": "🟢 Low",
}
TIMELINE_LIMIT = 40


def _utc(when: datetime) -> datetime:
    """Wazuh stamps alerts with the manager's local offset; reports always show UTC."""
    return when.astimezone(UTC)


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _duration(incident: Incident) -> str:
    seconds = int((incident.last_seen - incident.first_seen).total_seconds())
    minutes, secs = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m {secs:02d}s" if hours else f"{minutes}m {secs:02d}s"


def incident_markdown(incident: Incident, *, source: str = "") -> str:
    lines = [
        f"# {incident.id}: {incident.title}",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Severity | {SEVERITY_BADGE[incident.severity]} |",
        "| Status | Open: needs analyst review |",
        f"| Correlation rule | `{incident.rule}` |",
        f"| Entity | {_cell(incident.entity)} |",
        f"| First seen (UTC) | {_utc(incident.first_seen):%Y-%m-%d %H:%M:%S} |",
        f"| Last seen (UTC) | {_utc(incident.last_seen):%Y-%m-%d %H:%M:%S} "
        f"({_duration(incident)}) |",
        f"| Hosts | {_cell(', '.join(incident.agents))} |",
        f"| Source IPs | {_cell(', '.join(incident.src_ips) or 'n/a')} |",
        f"| Accounts | {_cell(', '.join(incident.users) or 'n/a')} |",
        f"| Alerts | {len(incident.alerts)} (max level {incident.max_level}) |",
    ]
    if source:
        lines.append(f"| Evidence source | {_cell(source)} |")
    lines += ["", "## Summary", "", incident.summary, "", "## MITRE ATT&CK", ""]
    if incident.techniques:
        lines += ["| Technique | Link |", "|---|---|"]
        for t in incident.techniques:
            path = t.replace(".", "/")
            lines.append(f"| {t} | https://attack.mitre.org/techniques/{path}/ |")
        if incident.tactics:
            lines += ["", f"Tactics: {', '.join(incident.tactics)}"]
    else:
        lines.append("No technique mapping on the contributing alerts.")

    lines += [
        "",
        "## Timeline",
        "",
        "| Time (UTC) | Host | Rule | Level | Event |",
        "|---|---|---|---|---|",
    ]
    shown = incident.alerts[:TIMELINE_LIMIT]
    for a in shown:
        parts = (a.src_ip and f"src={a.src_ip}", a.user and f"user={a.user}")
        who = " ".join(x for x in parts if x)
        event = f"{a.description}" + (f" ({who})" if who else "")
        lines.append(
            f"| {_utc(a.timestamp):%H:%M:%S} | {_cell(a.agent)} | {a.rule_id} | {a.level} "
            f"| {_cell(event)} |"
        )
    if len(incident.alerts) > TIMELINE_LIMIT:
        lines.append(f"| ... | | | | {len(incident.alerts) - TIMELINE_LIMIT} more alerts |")

    lines += ["", "## Recommended response", ""]
    lines += [f"{n}. {step}" for n, step in enumerate(incident.response, start=1)]
    lines += [
        "",
        "## Analyst notes",
        "",
        "- **Verdict:** _true positive / benign true positive / false positive_",
        "- **Root cause:**",
        "- **Actions taken:**",
        "- **Detection improvements:**",
        "",
    ]
    return "\n".join(lines)


def summary_markdown(incidents: Sequence[Incident], *, alerts: int, skipped: int = 0) -> str:
    lines = [
        "# Correlation summary",
        "",
        f"{alerts} alerts analysed, {len(incidents)} incident(s)"
        + (f", {skipped} malformed line(s) skipped" if skipped else "")
        + ".",
        "",
    ]
    if incidents:
        lines += ["| ID | Severity | Title | First seen (UTC) | Hosts |", "|---|---|---|---|---|"]
        for inc in incidents:
            lines.append(
                f"| {inc.id} | {SEVERITY_BADGE[inc.severity]} | {_cell(inc.title)} | "
                f"{_utc(inc.first_seen):%Y-%m-%d %H:%M:%S} | {_cell(', '.join(inc.agents))} |"
            )
    return "\n".join(lines) + "\n"
