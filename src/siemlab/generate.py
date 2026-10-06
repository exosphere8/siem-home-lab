"""Synthetic Wazuh alerts for the lab's attack scenarios.

The output has the shape of ``/var/ossec/logs/alerts/alerts.json`` (one JSON object per line),
so the correlation engine, tests and documentation can be exercised before, or without,
the live lab. Rule IDs, levels, groups and ATT&CK mappings are read from the real files in
``detections/``, so generated alerts cannot drift from the rules they imitate.

Every address is inside the lab network from docs/architecture/lab-architecture.md:
10.10.10.50 plays the attacker (the reserved test VM), 10.10.10.1 the administrator's host.
Output is deterministic for a given seed.
"""

from __future__ import annotations

import random
import re
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import mitre
from .validate import WazuhRule, load_catalogue

ATTACKER = "10.10.10.50"
ADMIN_HOST = "10.10.10.1"
AGENTS = {
    "ubuntu-endpoint": ("001", "10.10.10.20"),
    "win11-endpoint": ("002", "10.10.10.30"),
}
START = datetime(2026, 10, 5, 9, 0, 0, tzinfo=UTC)

# Built-in Wazuh rules the scenarios also need (not part of this repository's detections).
BUILTIN: dict[int, tuple[int, str, tuple[str, ...]]] = {
    5715: (3, "sshd: authentication success.", ("syslog", "sshd", "authentication_success")),
    60106: (3, "Windows logon success.", ("windows", "windows_security", "authentication_success")),
    31108: (0, "Ignored URLs (simple queries).", ("web", "accesslog")),
}


class AlertFactory:
    def __init__(self, detections: Path, seed: int = 7) -> None:
        self.rules = load_catalogue(detections).by_id()
        self.rng = random.Random(seed)
        self._counter = 0

    def _rule(self, rule_id: int) -> dict[str, Any]:
        if rule_id in self.rules:
            r: WazuhRule = self.rules[rule_id]
            level, description, groups, techniques = (
                r.level,
                r.description,
                r.groups,
                r.techniques,
            )
        elif rule_id in BUILTIN:
            level, description, groups = BUILTIN[rule_id]
            techniques = ()
        else:
            raise ValueError(f"rule {rule_id} is neither in detections/ nor a known built-in")
        rule: dict[str, Any] = {
            "id": str(rule_id),
            "level": level,
            "description": description,
            "groups": list(groups),
            "firedtimes": 1,
        }
        if techniques:
            rule["mitre"] = {
                "id": list(techniques),
                "tactic": sorted({mitre.tactic(t) for t in techniques}),
                "technique": [mitre.name(t) for t in techniques],
            }
        return rule

    def alert(
        self,
        when: datetime,
        rule_id: int,
        agent: str,
        *,
        data: dict[str, Any],
        full_log: str,
        location: str,
        decoder: str,
        syscheck: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._counter += 1
        agent_id, agent_ip = AGENTS[agent]
        rule = self._rule(rule_id)
        flat = _flatten(data)
        if syscheck:
            flat["file"] = syscheck["path"]
        rule["description"] = re.sub(
            r"\$\(([\w.]+)\)", lambda m: str(flat.get(m.group(1), m.group(0))), rule["description"]
        )
        doc: dict[str, Any] = {
            "timestamp": f"{when:%Y-%m-%dT%H:%M:%S}.{when.microsecond // 1000:03d}+0000",
            "rule": rule,
            "agent": {"id": agent_id, "name": agent, "ip": agent_ip},
            "manager": {"name": "wazuh-server"},
            "id": f"{int(when.timestamp())}.{self._counter * 1371}",
            "full_log": full_log,
            "decoder": {"name": decoder},
            "data": data,
            "location": location,
        }
        if syscheck:
            doc["syscheck"] = syscheck
        return doc

    def jitter(self, seconds: float) -> timedelta:
        return timedelta(seconds=seconds + self.rng.uniform(0, 1.5))


def _flatten(data: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in data.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(_flatten(value, f"{name}."))
        else:
            out[name] = value
    out.update({k.split(".")[-1]: v for k, v in list(out.items())})  # $(srcip) and $(win.x.y)
    return out


def _syslog(when: datetime, host: str, program: str, message: str) -> str:
    return f"{when:%b} {when.day:2d} {when:%H:%M:%S} {host} {program}: {message}"


# -- scenarios -------------------------------------------------------------------------------


def ssh_compromise(f: AlertFactory, start: datetime) -> Iterator[dict[str, Any]]:
    """Password guessing over SSH that succeeds, followed by persistence on the host."""
    host = "ubuntu-endpoint"
    t = start
    users = ["root", "admin", "labadmin", "root", "labadmin", "admin", "labadmin", "root"]
    for n, user in enumerate(users, start=1):
        t += f.jitter(4)
        port = 40000 + n
        line = _syslog(
            t, host, "sshd[2301]", f"Failed password for {user} from {ATTACKER} port {port} ssh2"
        )
        data = {"srcip": ATTACKER, "srcport": str(port), "dstuser": user}
        # Wazuh reports one rule per event: the 6th failure fires the brute-force rule instead.
        rule = 100101 if n == 6 else 100103 if user == "root" else 100100
        yield f.alert(
            t, rule, host, data=data, full_log=line, location="/var/log/auth.log", decoder="sshd"
        )
    t += f.jitter(20)
    line = _syslog(
        t, host, "sshd[2340]", f"Accepted password for labadmin from {ATTACKER} port 40100 ssh2"
    )
    yield f.alert(
        t,
        100102,
        host,
        data={"srcip": ATTACKER, "dstuser": "labadmin"},
        full_log=line,
        location="/var/log/auth.log",
        decoder="sshd",
    )
    t += f.jitter(45)
    line = _syslog(
        t, host, "sudo", "labadmin : TTY=pts/0 ; PWD=/home/labadmin ; USER=root ; COMMAND=/bin/bash"
    )
    yield f.alert(
        t,
        100402,
        host,
        data={"srcuser": "labadmin", "dstuser": "root"},
        full_log=line,
        location="/var/log/auth.log",
        decoder="sudo",
    )
    t += f.jitter(30)
    line = _syslog(
        t,
        host,
        "useradd[2412]",
        "new user: name=svc-backup, UID=1002, GID=1002, home=/home/svc-backup",
    )
    yield f.alert(
        t,
        100400,
        host,
        data={"dstuser": "svc-backup"},
        full_log=line,
        location="/var/log/auth.log",
        decoder="useradd",
    )
    t += f.jitter(10)
    line = _syslog(t, host, "usermod[2419]", "add 'svc-backup' to group 'sudo'")
    yield f.alert(
        t,
        100401,
        host,
        data={"dstuser": "svc-backup"},
        full_log=line,
        location="/var/log/auth.log",
        decoder="usermod",
    )
    t += f.jitter(25)
    path = "/home/svc-backup/.ssh/authorized_keys"
    yield f.alert(
        t,
        100302,
        host,
        data={},
        full_log=f"File '{path}' added",
        location="syscheck",
        decoder="syscheck_new_entry",
        syscheck={"path": path, "event": "added", "mode": "realtime"},
    )


def windows_password_spray(f: AlertFactory, start: datetime) -> Iterator[dict[str, Any]]:
    """One source trying a handful of accounts on the Windows endpoint."""
    host = "win11-endpoint"
    t = start
    accounts = [
        "administrator",
        "labuser",
        "backup",
        "helpdesk",
        "guest",
        "svc-sql",
        "labuser",
        "administrator",
    ]
    for n, account in enumerate(accounts, start=1):
        t += f.jitter(9)
        data = {
            "win": {
                "system": {"eventID": "4625", "channel": "Security"},
                "eventdata": {"targetUserName": account, "ipAddress": ATTACKER, "logonType": "3"},
            }
        }
        log = (
            f"An account failed to log on. Account Name: {account} "
            f"Source Network Address: {ATTACKER}"
        )
        rule = 100201 if n == 8 else 100200  # the 8th failure fires the aggregate rule
        yield f.alert(
            t,
            rule,
            host,
            data=data,
            full_log=log,
            location="EventChannel",
            decoder="windows_eventchannel",
        )


def windows_persistence(f: AlertFactory, start: datetime) -> Iterator[dict[str, Any]]:
    """A new local admin account, then the Security log is cleared."""
    host = "win11-endpoint"
    t = start

    def event(event_id: str, rule: int, extra: dict[str, str], text: str) -> dict[str, Any]:
        data = {
            "win": {
                "system": {"eventID": event_id, "channel": "Security", "computer": host},
                "eventdata": {"subjectUserName": "labuser", **extra},
            }
        }
        return f.alert(
            t,
            rule,
            host,
            data=data,
            full_log=text,
            location="EventChannel",
            decoder="windows_eventchannel",
        )

    t += f.jitter(5)
    yield event(
        "4720",
        100204,
        {"targetUserName": "support$"},
        "A user account was created. New Account: support$",
    )
    t += f.jitter(12)
    yield event(
        "4732",
        100205,
        {
            "targetUserName": "Administrators",
            "targetSid": "S-1-5-32-544",
            "memberSid": "S-1-5-21-1000-1000-1000-1004",
        },
        "A member was added to a security-enabled local group. Group: Administrators",
    )
    t += f.jitter(90)
    yield event("1102", 100206, {}, "The audit log was cleared.")


def web_attack(f: AlertFactory, start: datetime) -> Iterator[dict[str, Any]]:
    """Scanner recon, exploitation attempts, then a script appears under the web root."""
    host = "ubuntu-endpoint"
    t = start
    ua = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"

    def request(rule: int, url: str, status: int, agent: str = ua) -> dict[str, Any]:
        line = (
            f'{ATTACKER} - - [{t:%d/%b/%Y:%H:%M:%S} +0000] "GET {url} HTTP/1.1" {status} 162 '
            f'"-" "{agent}"'
        )
        return f.alert(
            t,
            rule,
            host,
            data={"srcip": ATTACKER, "url": url, "id": str(status)},
            full_log=line,
            location="/var/log/nginx/access.log",
            decoder="web-accesslog",
        )

    t += f.jitter(2)
    yield request(100500, "/", 200)
    for path in ("/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/.aws/credentials"):
        t += f.jitter(1)
        yield request(100501, path, 404, "Mozilla/5.0")
    t += f.jitter(40)
    yield request(100502, "/download.php?file=../../../../etc/passwd", 200, "Mozilla/5.0")
    t += f.jitter(15)
    yield request(
        100503,
        "/item.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
        200,
        "sqlmap/1.8.4#stable (https://sqlmap.org)",
    )
    t += f.jitter(60)
    path = "/var/www/html/uploads/thumb.php"
    yield f.alert(
        t,
        100305,
        host,
        data={},
        full_log=f"File '{path}' added",
        location="syscheck",
        decoder="syscheck_new_entry",
        syscheck={"path": path, "event": "added", "mode": "realtime"},
    )


def benign_activity(f: AlertFactory, start: datetime) -> Iterator[dict[str, Any]]:
    """Normal administration noise: routine logins from the admin host, plus one typo."""
    host = "ubuntu-endpoint"
    t = start
    for hour in range(3):
        t = start + timedelta(hours=hour, minutes=f.rng.randint(0, 40))
        line = _syslog(
            t,
            host,
            "sshd[1102]",
            f"Accepted publickey for labadmin from {ADMIN_HOST} port 50122 ssh2",
        )
        yield f.alert(
            t,
            5715,
            host,
            data={"srcip": ADMIN_HOST, "dstuser": "labadmin"},
            full_log=line,
            location="/var/log/auth.log",
            decoder="sshd",
        )
    t += f.jitter(30)
    line = _syslog(
        t, host, "sshd[1188]", f"Failed password for labadmin from {ADMIN_HOST} port 50199 ssh2"
    )
    yield f.alert(
        t,
        100100,
        host,
        data={"srcip": ADMIN_HOST, "dstuser": "labadmin"},
        full_log=line,
        location="/var/log/auth.log",
        decoder="sshd",
    )
    t += f.jitter(8)
    line = _syslog(
        t, host, "sshd[1188]", f"Accepted password for labadmin from {ADMIN_HOST} port 50199 ssh2"
    )
    yield f.alert(
        t,
        5715,
        host,
        data={"srcip": ADMIN_HOST, "dstuser": "labadmin"},
        full_log=line,
        location="/var/log/auth.log",
        decoder="sshd",
    )


Scenario = Callable[[AlertFactory, datetime], Iterator[dict[str, Any]]]

SCENARIOS: dict[str, tuple[Scenario, timedelta]] = {
    # name: (generator, offset from START)
    "benign": (benign_activity, timedelta(0)),
    "web-attack": (web_attack, timedelta(minutes=10)),
    "ssh-compromise": (ssh_compromise, timedelta(minutes=40)),
    "windows-spray": (windows_password_spray, timedelta(minutes=46)),
    "windows-persistence": (windows_persistence, timedelta(hours=2, minutes=10)),
}


def generate(
    detections: Path, scenarios: list[str] | None = None, seed: int = 7, start: datetime = START
) -> list[dict[str, Any]]:
    """Alerts for the chosen scenarios (default: all), merged and sorted by time."""
    names = scenarios or list(SCENARIOS)
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown:
        raise ValueError(f"unknown scenario(s) {unknown}; choose from {list(SCENARIOS)}")
    factory = AlertFactory(detections, seed)
    alerts = [doc for n in names for doc in SCENARIOS[n][0](factory, start + SCENARIOS[n][1])]
    return sorted(alerts, key=lambda d: (d["timestamp"], d["id"]))
