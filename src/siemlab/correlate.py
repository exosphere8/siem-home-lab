"""Correlate individual Wazuh alerts into incidents.

A single alert answers "did something suspicious happen?". An incident answers "what is the
story?": a brute force that ended in a successful login, one source touching several hosts,
an account created and then made an administrator. Each correlation rule below turns a
pattern across alerts into one :class:`Incident` with a severity, a timeline, the ATT&CK
techniques involved, and a recommended response.

Wazuh 4.x counts events itself (frequency rules such as 100101). Wazuh 5 rules match one event
at a time, so with ``Config(stateful=True)`` siemlab also does that counting: see
:data:`STATEFUL_RULES`.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .alerts import Alert

SEVERITIES = ("critical", "high", "medium", "low")

AUTH_FAILURE_GROUPS = ("authentication_failed", "invalid_login")
AUTH_SUCCESS_GROUPS = ("authentication_success",)
PERSISTENCE_TECHNIQUES = ("T1136", "T1098", "T1053", "T1547", "T1543", "T1505.003", "T1548")


@dataclass(frozen=True)
class Config:
    window: timedelta = timedelta(minutes=15)
    brute_force_threshold: int = 5
    spray_users: int = 4
    multi_host_min: int = 2
    multi_host_min_level: int = 5
    standalone_level: int = 12
    # Counting that Wazuh 4.x rules did and Wazuh 5 rules cannot (100101, 100201, 100504).
    stateful: bool = False
    burst_failures: int = 6
    burst_window: timedelta = timedelta(minutes=2)
    discovery_probes: int = 10
    discovery_window: timedelta = timedelta(minutes=1)

    def __post_init__(self) -> None:
        if min(self.window, self.burst_window, self.discovery_window) <= timedelta(0):
            raise ValueError("correlation windows must be positive")
        thresholds = (
            self.brute_force_threshold,
            self.spray_users,
            self.multi_host_min,
            self.burst_failures,
            self.discovery_probes,
        )
        if min(thresholds) < 1:
            raise ValueError("thresholds must be at least 1")


@dataclass
class Incident:
    rule: str
    title: str
    severity: str
    entity: str
    summary: str
    alerts: list[Alert]
    response: tuple[str, ...] = ()
    id: str = ""

    def __post_init__(self) -> None:
        self.alerts = sorted(self.alerts, key=lambda a: (a.timestamp, a.rule_id))

    def add(self, alert: Alert) -> None:
        self.alerts = sorted([*self.alerts, alert], key=lambda a: (a.timestamp, a.rule_id))

    @property
    def first_seen(self) -> datetime:
        return self.alerts[0].timestamp

    @property
    def last_seen(self) -> datetime:
        return self.alerts[-1].timestamp

    @property
    def agents(self) -> list[str]:
        return sorted({a.agent for a in self.alerts})

    @property
    def src_ips(self) -> list[str]:
        return sorted({a.src_ip for a in self.alerts if a.src_ip})

    @property
    def users(self) -> list[str]:
        return sorted({a.user for a in self.alerts if a.user})

    @property
    def techniques(self) -> list[str]:
        return sorted({t for a in self.alerts for t in a.techniques})

    @property
    def tactics(self) -> list[str]:
        return sorted({t for a in self.alerts for t in a.tactics})

    @property
    def max_level(self) -> int:
        return max(a.level for a in self.alerts)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "rule": self.rule,
            "title": self.title,
            "severity": self.severity,
            "entity": self.entity,
            "summary": self.summary,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "agents": self.agents,
            "src_ips": self.src_ips,
            "users": self.users,
            "techniques": self.techniques,
            "tactics": self.tactics,
            "response": list(self.response),
            "alerts": [a.to_dict() for a in self.alerts],
        }


Rule = Callable[[Sequence[Alert], Config], list[Incident]]


def _by(alerts: Iterable[Alert], key: Callable[[Alert], str | None]) -> dict[str, list[Alert]]:
    groups: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        k = key(a)
        if k:
            groups[k].append(a)
    return groups


def _is_failure(a: Alert) -> bool:
    # An aggregate brute-force alert (100101, 100201) replaces the failed login that triggered
    # it, so it stands for one more failure; lockouts and other aggregates do not.
    return a.has_group(*AUTH_FAILURE_GROUPS) or (
        a.has_group("authentication_failures") and a.has_technique("T1110.001")
    )


def _is_success(a: Alert) -> bool:
    return a.has_group(*AUTH_SUCCESS_GROUPS)


def _window_before(alerts: Sequence[Alert], end: datetime, window: timedelta) -> list[Alert]:
    return [a for a in alerts if end - window <= a.timestamp <= end]


def _windows(
    items: Sequence[Alert],
    window: timedelta,
    score: Callable[[Sequence[Alert]], int],
    threshold: int,
) -> list[list[Alert]]:
    """Non-overlapping time windows whose score reaches ``threshold``.

    Scans forward in time. At the first alert whose window ``[t, t + window]`` qualifies, the
    window is emitted with *every* alert inside it (repeats included), and scanning resumes
    after it, so a later, separate burst becomes its own incident.
    """
    found: list[list[Alert]] = []
    i, n = 0, len(items)
    while i < n:
        limit = items[i].timestamp + window
        j = i
        while j < n and items[j].timestamp <= limit:
            j += 1
        span = list(items[i:j])
        if score(span) >= threshold:
            found.append(span)
            i = j
        else:
            i += 1
    return found


# -- correlation rules ----------------------------------------------------------------------


def credential_compromise(alerts: Sequence[Alert], cfg: Config) -> list[Incident]:
    """Repeated authentication failures from one source, then a success from that source.

    Every success preceded (within the window) by enough failures not already explained by an
    earlier incident starts a new incident, so separate compromises stay separate. A success
    without a new burst shortly after an incident is a follow-up login and joins it.
    """
    incidents: list[Incident] = []
    for ip, items in _by(alerts, lambda a: a.src_ip).items():
        used: set[int] = set()
        current: Incident | None = None
        for success in (a for a in items if _is_success(a)):
            recent = _window_before(items, success.timestamp, cfg.window)
            failures = [
                a for a in recent if _is_failure(a) and a is not success and id(a) not in used
            ]
            if len(failures) < cfg.brute_force_threshold:
                if current is not None and success.timestamp - current.last_seen <= cfg.window:
                    current.add(success)  # a follow-up login in the same story
                continue
            used.update(id(a) for a in failures)
            in_current = {id(a) for a in current.alerts} if current else set()
            related = [
                a
                for a in recent
                if a is not success and not _is_failure(a) and id(a) not in in_current
            ]
            accounts = sorted({a.user for a in failures if a.user})
            current = Incident(
                "credential_compromise",
                f"Successful login after {len(failures)} failures from {ip}",
                "critical",
                f"source {ip}",
                f"{len(failures)} failed logins from {ip} (accounts: "
                f"{', '.join(accounts) or 'unknown'}) were followed by a successful login as "
                f"'{success.user or 'unknown'}' on {success.agent}. Treat the account as "
                "compromised until proven otherwise.",
                [*failures, *related, success],
                (
                    f"Disable or reset the password of '{success.user or 'the account'}' "
                    f"and kill its sessions on {success.agent}.",
                    f"Block {ip} at the host firewall while investigating.",
                    "Review everything the account did after the login: commands, sudo, "
                    "new users, new SSH keys, cron jobs.",
                    "Check whether the same source reached other hosts.",
                ),
            )
            incidents.append(current)
    return incidents


def password_spray(alerts: Sequence[Alert], cfg: Config) -> list[Incident]:
    """Failures for many different accounts from one source inside the window."""
    incidents = []
    for ip, items in _by(alerts, lambda a: a.src_ip).items():
        failures = [a for a in items if _is_failure(a) and a.user]
        for span in _windows(
            failures, cfg.window, lambda w: len({a.user for a in w}), cfg.spray_users
        ):
            users = sorted({a.user for a in span if a.user})
            incidents.append(
                Incident(
                    "password_spray",
                    f"Password spraying from {ip} against {len(users)} accounts",
                    "high",
                    f"source {ip}",
                    f"{ip} failed to log in as {len(users)} different accounts within "
                    f"{_fmt(cfg.window)}: {', '.join(users)}.",
                    span,
                    (
                        f"Block {ip} and check whether any of these accounts later logged in "
                        "successfully from anywhere.",
                        "Confirm account lockout and MFA policies cover the targeted accounts.",
                    ),
                )
            )
    return incidents


def multi_host_activity(alerts: Sequence[Alert], cfg: Config) -> list[Incident]:
    """One source triggering meaningful alerts on several hosts: scanning or lateral movement."""
    incidents = []
    for ip, items in _by(alerts, lambda a: a.src_ip).items():
        notable = [a for a in items if a.level >= cfg.multi_host_min_level]
        for span in _windows(
            notable, cfg.window, lambda w: len({a.agent for a in w}), cfg.multi_host_min
        ):
            hosts = sorted({a.agent for a in span})
            incidents.append(
                Incident(
                    "multi_host_activity",
                    f"{ip} triggered alerts on {len(hosts)} hosts",
                    "high",
                    f"source {ip}",
                    f"Within {_fmt(cfg.window)}, {ip} triggered alerts of level "
                    f">= {cfg.multi_host_min_level} on {', '.join(hosts)}. One source touching "
                    "several hosts suggests scanning or lateral movement.",
                    span,
                    (
                        f"Identify what {ip} is. If it is inside the lab, isolate it and "
                        "investigate it as a compromised host.",
                        "Compare the timelines on each affected host.",
                    ),
                )
            )
    return incidents


def persistence_chain(alerts: Sequence[Alert], cfg: Config) -> list[Incident]:
    """Two or more different persistence or privilege techniques on one host in the window."""
    incidents = []
    for agent, items in _by(alerts, lambda a: a.agent).items():
        relevant = [a for a in items if a.has_technique(*PERSISTENCE_TECHNIQUES)]
        for span in _windows(relevant, cfg.window, lambda w: len(_families(w)), 2):
            families = _families(span)
            privileged = "T1098" in families or "T1548" in families
            incidents.append(
                Incident(
                    "persistence_chain",
                    f"Persistence chain on {agent}: {', '.join(sorted(families))}",
                    "critical" if privileged and "T1136" in families else "high",
                    f"host {agent}",
                    f"{len(families)} different persistence or privilege techniques were seen "
                    f"on {agent} within {_fmt(cfg.window)}. Separately each can be routine "
                    "admin work; together they match how an intruder keeps access.",
                    span,
                    (
                        "Confirm with the system owner whether these changes were planned.",
                        "If not: remove the new accounts, keys, scheduled tasks or services, "
                        "and rotate credentials of every account that was used.",
                        f"Check how access to {agent} was obtained in the first place.",
                    ),
                )
            )
    return incidents


def web_attack_progression(alerts: Sequence[Alert], cfg: Config) -> list[Incident]:
    """Reconnaissance, then exploitation attempts from the same source, plus web-root changes.

    Each exploitation attempt is linked only to reconnaissance in the window *before* it, so
    unrelated probes hours earlier or later neither create nor suppress an incident. Linked
    attempts less than one window apart form one incident.
    """
    incidents = []
    for ip, items in _by(alerts, lambda a: a.src_ip).items():
        recon = [a for a in items if a.has_technique("T1595")]
        clusters: list[tuple[list[Alert], list[Alert]]] = []  # (recon, exploits)
        for exploit in (a for a in items if a.has_technique("T1190")):
            before = [
                r
                for r in recon
                if exploit.timestamp - cfg.window <= r.timestamp <= exploit.timestamp
            ]
            if not before:
                continue
            if clusters and exploit.timestamp - clusters[-1][1][-1].timestamp <= cfg.window:
                seen = {id(r) for r in clusters[-1][0]}
                clusters[-1][0].extend(r for r in before if id(r) not in seen)
                clusters[-1][1].append(exploit)
            else:
                clusters.append((before, [exploit]))

        for probes, exploits in clusters:
            targets = {a.agent for a in exploits}
            webshell = [
                a
                for a in alerts
                if a.agent in targets
                and a.has_technique("T1505.003")
                and exploits[0].timestamp <= a.timestamp <= exploits[-1].timestamp + cfg.window
            ]
            incidents.append(
                Incident(
                    "web_attack_progression",
                    f"Web attack from {ip}: reconnaissance then exploitation attempts"
                    + (" then web-root change" if webshell else ""),
                    "critical" if webshell else "high",
                    f"source {ip}",
                    f"{ip} probed {len(probes)} time(s) and then sent {len(exploits)} "
                    f"exploitation attempt(s) to {', '.join(sorted(targets))}"
                    + (
                        f"; files under the web root changed {len(webshell)} time(s) afterwards, "
                        "which is how web shells appear."
                        if webshell
                        else "; no web-root changes were seen afterwards."
                    ),
                    [*probes, *exploits, *webshell],
                    (
                        f"Block {ip} and review the web server's responses to its requests "
                        "(status codes and sizes) to see whether any attempt succeeded.",
                        "Diff the web root against a known-good copy."
                        if webshell
                        else "Keep file-integrity monitoring on the web root enabled.",
                    ),
                )
            )
    return incidents


def brute_force(
    alerts: Sequence[Alert], cfg: Config, covered: set[int] | None = None
) -> list[Incident]:
    """Many failed logins from one source in a short window (Wazuh 4.x rules 100101, 100201).

    Failures already part of another incident (a compromise, a spray) are not counted again.
    """
    covered = covered or set()
    incidents = []
    for ip, items in _by(alerts, lambda a: a.src_ip).items():
        failures = [a for a in items if _is_failure(a) and id(a) not in covered]
        for span in _windows(failures, cfg.burst_window, len, cfg.burst_failures):
            accounts = sorted({a.user for a in span if a.user})
            hosts = sorted({a.agent for a in span})
            incidents.append(
                Incident(
                    "brute_force",
                    f"Brute force from {ip}: {len(span)} failed logins in {_fmt(cfg.burst_window)}",
                    "high",
                    f"source {ip}",
                    f"{ip} failed to log in {len(span)} times within {_fmt(cfg.burst_window)} "
                    f"on {', '.join(hosts)} (accounts: {', '.join(accounts) or 'unknown'}). "
                    "No successful login from this source followed in the data.",
                    span,
                    (
                        f"Block {ip} and check whether it logs in successfully later.",
                        "Confirm root login and password authentication are disabled where "
                        "they should be.",
                    ),
                )
            )
    return incidents


def content_discovery(
    alerts: Sequence[Alert], cfg: Config, covered: set[int] | None = None
) -> list[Incident]:
    """Many probes for sensitive web paths from one source (Wazuh 4.x rule 100504)."""
    covered = covered or set()
    incidents = []
    for ip, items in _by(alerts, lambda a: a.src_ip).items():
        probes = [a for a in items if a.has_group("web_sensitive_probe") and id(a) not in covered]
        for span in _windows(probes, cfg.discovery_window, len, cfg.discovery_probes):
            urls = sorted({a.url for a in span if a.url})
            incidents.append(
                Incident(
                    "content_discovery",
                    f"Content discovery from {ip}: {len(span)} sensitive-path probes",
                    "medium",
                    f"source {ip}",
                    f"{ip} requested {len(span)} sensitive paths within "
                    f"{_fmt(cfg.discovery_window)}, for example "
                    f"{', '.join(urls[:3]) or 'unknown'}. That is a wordlist scan.",
                    span,
                    (
                        f"Check whether any request from {ip} got a 200 response.",
                        "Make sure none of the probed files exist under the web root.",
                    ),
                )
            )
    return incidents


StatefulRule = Callable[[Sequence[Alert], Config, set[int]], list[Incident]]

# Run after CORRELATION_RULES when Config.stateful is set, on alerts they did not explain.
STATEFUL_RULES: tuple[StatefulRule, ...] = (brute_force, content_discovery)


def standalone_high_severity(
    alerts: Sequence[Alert], cfg: Config, covered: set[int] | None = None
) -> list[Incident]:
    """Any high-level alert that no correlation explained still deserves an incident."""
    covered = covered or set()
    incidents = []
    for a in alerts:
        if a.level >= cfg.standalone_level and id(a) not in covered:
            incidents.append(
                Incident(
                    "high_severity_alert",
                    a.description,
                    "critical" if a.level >= 13 else "high",
                    f"host {a.agent}",
                    f"Rule {a.rule_id} (level {a.level}) fired on {a.agent} and is not part of "
                    "a larger pattern. High-level rules are designed to be investigated on "
                    "their own.",
                    [a],
                    ("Investigate the alert and its surrounding events on the host.",),
                )
            )
    return incidents


CORRELATION_RULES: tuple[Rule, ...] = (
    credential_compromise,
    password_spray,
    multi_host_activity,
    persistence_chain,
    web_attack_progression,
)


def correlate(alerts: Sequence[Alert], cfg: Config | None = None) -> list[Incident]:
    """Run every correlation rule. Incidents are ordered by severity, then time, and numbered."""
    cfg = cfg or Config()
    ordered = sorted(alerts, key=lambda a: a.timestamp)
    incidents = [inc for rule in CORRELATION_RULES for inc in rule(ordered, cfg)]
    covered = {id(a) for inc in incidents for a in inc.alerts}
    if cfg.stateful:
        for stateful_rule in STATEFUL_RULES:
            found = stateful_rule(ordered, cfg, covered)
            incidents += found
            covered |= {id(a) for inc in found for a in inc.alerts}
    incidents += standalone_high_severity(ordered, cfg, covered)
    incidents.sort(key=lambda i: (SEVERITIES.index(i.severity), i.first_seen, i.rule))
    for number, inc in enumerate(incidents, start=1):
        inc.id = f"INC-{inc.first_seen.astimezone(UTC):%Y%m%d}-{number:03d}"
    return incidents


def _families(alerts: Iterable[Alert]) -> set[str]:
    """Persistence technique families present (T1098.004 counts as T1098)."""
    return {
        p for a in alerts for t in a.techniques for p in PERSISTENCE_TECHNIQUES if t.startswith(p)
    }


def _fmt(window: timedelta) -> str:
    minutes = int(window.total_seconds() // 60)
    return f"{minutes} min" if minutes else f"{int(window.total_seconds())} s"
