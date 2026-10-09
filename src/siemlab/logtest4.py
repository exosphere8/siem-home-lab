"""Run Wazuh 4.x logtest cases against a manager, to prove the rules match what they should.

Each case sends one or more log lines through the manager's real decoders and rules, in one
logtest session (so frequency rules see the earlier lines), and compares the rule the *last*
line ended on with the expected rule ID and level. The cases live in
``detections/logtest/wazuh4.yml``.

Windows Event Channel cases (``log_format: eventchannel``) cannot use logtest: it always
decodes input as a plain log line, never with the Event Channel decoder. Those cases, and any
case with ``mode: queue``, are sent to the manager's analysis queue instead, the way agent
events arrive, and the alert of the last event is read back from ``alerts.json`` (matched on
the Windows ``EventRecordID``, or on the full log line). Queue cases share the manager's real
state, so give each one its own source address.

Run it on the manager, as root (the logtest socket belongs to root:wazuh)::

    sudo siemlab wazuh4 logtest

This module uses only the standard library and runs on Python 3.10+, so it also works as a
standalone script on the manager's own Python (3.10 in Wazuh 4.14). That is how CI tests the
rules against the official ``wazuh/wazuh-manager`` image::

    /var/ossec/framework/python/bin/python3 logtest4.py --cases cases.json
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import socket
import struct
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_SOCKET = "/var/ossec/queue/sockets/logtest"
DEFAULT_QUEUE = "/var/ossec/queue/sockets/queue"
DEFAULT_ALERTS = "/var/ossec/logs/alerts/alerts.json"

Call = Callable[[str, dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class Case:
    name: str
    location: str
    log_format: str
    events: tuple[str, ...]
    rule: str
    level: int | None = None
    mode: str = "logtest"  # or "queue"


@dataclass(frozen=True)
class Result:
    case: Case
    rule: str | None
    level: int | None
    error: str | None = None
    trail: tuple[str, ...] = ()  # the rule each event ended on, for diagnosis

    @property
    def passed(self) -> bool:
        if self.error is not None or self.rule != self.case.rule:
            return False
        if self.case.rule in self.trail[:-1]:
            return False  # a counting rule fired before the last event: its count is wrong
        return self.case.level is None or self.level == self.case.level


def parse_cases(doc: Any) -> list[Case]:
    """Cases from ``{"cases": [...]}``; raises ValueError on a malformed case."""
    raw = doc.get("cases") if isinstance(doc, dict) else None
    if not isinstance(raw, list) or not raw:
        raise ValueError("expected a non-empty 'cases' list")
    cases = []
    for n, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"case {n} is not a mapping")
        events = item.get("events")
        expect = item.get("expect")
        if not isinstance(events, list) or not events or not isinstance(expect, dict):
            raise ValueError(f"case {n}: needs a non-empty 'events' list and an 'expect' mapping")
        if "rule" not in expect:
            raise ValueError(f"case {n}: 'expect' needs a 'rule'")
        level = expect.get("level")
        mode = str(item.get("mode", "logtest"))
        if mode not in ("logtest", "queue"):
            raise ValueError(f"case {n}: mode must be logtest or queue")
        if str(item.get("log_format", "")) == "eventchannel":
            mode = "queue"  # logtest cannot apply the Event Channel decoder
        cases.append(
            Case(
                name=str(item.get("name") or f"case {n}"),
                location=str(item.get("location", "")),
                log_format=str(item.get("log_format", "syslog")),
                events=tuple(str(e) for e in events),
                rule=str(expect["rule"]),
                level=int(level) if level is not None else None,
                mode=mode,
            )
        )
    return cases


def load_cases(path: Path) -> list[Case]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return parse_cases(json.loads(text))
    import yaml  # PyYAML ships with siemlab and with the Wazuh manager's Python

    return parse_cases(yaml.safe_load(text))


def _recv(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("the logtest socket closed the connection")
        data += chunk
    return data


def socket_call(path: str) -> Call:
    """A call function speaking the Wazuh socket protocol (4-byte little-endian length + JSON)."""

    def call(command: str, parameters: dict[str, Any]) -> dict[str, Any]:
        message = {
            "version": 1,
            "origin": {"name": "siemlab", "module": "siemlab"},
            "command": command,
            "parameters": parameters,
        }
        payload = json.dumps(message).encode()
        family = getattr(socket, "AF_UNIX", None)
        if family is None:
            raise OSError("the logtest socket needs a Unix system: run this on the manager")
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.connect(path)
            sock.sendall(struct.pack("<I", len(payload)) + payload)
            (size,) = struct.unpack("<I", _recv(sock, 4))
            reply: dict[str, Any] = json.loads(_recv(sock, size))
            return reply

    return call


def run_case(call: Call, case: Case) -> Result:
    token = None
    reply: dict[str, Any] = {}
    trail: list[str] = []
    try:
        for event in case.events:
            params: dict[str, Any] = {
                "event": event,
                "log_format": case.log_format,
                "location": case.location,
            }
            if token:
                params["token"] = token
            reply = call("log_processing", params)
            if reply.get("error", 0) != 0:
                return Result(
                    case,
                    None,
                    None,
                    f"logtest error {reply.get('error')}: {reply.get('message', '')}",
                )
            token = (reply.get("data") or {}).get("token") or token
            matched = ((reply.get("data") or {}).get("output") or {}).get("rule") or {}
            trail.append(str(matched.get("id", "-")))
    finally:
        if token:
            with contextlib.suppress(OSError):  # the session also expires on its own
                call("remove_session", {"token": token})
    rule = ((reply.get("data") or {}).get("output") or {}).get("rule") or {}
    if not rule:
        return Result(case, None, None, trail=tuple(trail))
    level = rule.get("level")
    return Result(
        case, str(rule.get("id")), int(level) if level is not None else None, trail=tuple(trail)
    )


def _record_id(event: str) -> str | None:
    match = re.search(r"<EventRecordID>(\d+)</EventRecordID>", event)
    return match.group(1) if match else None


def _alert_matches(alert: dict[str, Any], case: Case, record_id: str | None) -> bool:
    if record_id is not None:
        system = ((alert.get("data") or {}).get("win") or {}).get("system") or {}
        return str(system.get("eventRecordID")) == record_id
    return str(alert.get("full_log", "")) == case.events[-1]


def run_queue_case(
    case: Case, queue: str = DEFAULT_QUEUE, alerts: str = DEFAULT_ALERTS, timeout: float = 15
) -> Result:
    """Send Event Channel events to the analysis queue and read their alerts back."""
    family = getattr(socket, "AF_UNIX", None)
    if family is None:
        raise OSError("the event queue needs a Unix system: run this on the manager")
    eventchannel = case.log_format == "eventchannel"
    wanted = _record_id(case.events[-1]) if eventchannel else None
    if eventchannel and wanted is None:
        return Result(case, None, None, "the last event needs an <EventRecordID>")
    prefix = "f" if eventchannel else "1"
    start = Path(alerts).stat().st_size if Path(alerts).exists() else 0
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        for event in case.events:
            sock.sendto(f"{prefix}:{case.location}:{event}".encode(), queue)
            time.sleep(0.2)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with open(alerts, "rb") as f:
            f.seek(start)
            lines = f.read().decode("utf-8", "replace").splitlines()
        trail = []
        for line in lines:
            try:
                alert = json.loads(line)
            except ValueError:
                continue
            rule = alert.get("rule") or {}
            trail.append(str(rule.get("id")))
            if _alert_matches(alert, case, wanted):
                level = rule.get("level")
                return Result(
                    case,
                    str(rule.get("id")),
                    int(level) if level is not None else None,
                    trail=tuple(trail),
                )
        time.sleep(0.5)
    return Result(case, None, None, trail=tuple(trail))


def run_all(
    call: Call,
    cases: list[Case],
    queue: str = DEFAULT_QUEUE,
    alerts: str = DEFAULT_ALERTS,
) -> list[Result]:
    return [
        run_queue_case(case, queue, alerts) if case.mode == "queue" else run_case(call, case)
        for case in cases
    ]


def describe(result: Result) -> str:
    want = result.case.rule + (f" (level {result.case.level})" if result.case.level else "")
    got = (result.rule or "no rule") + (f" (level {result.level})" if result.level else "")
    status = "PASS" if result.passed else "FAIL"
    line = f"{status} {result.case.name}: expected {want}, got {got}"
    if result.error:
        line += f" [{result.error}]"
    if not result.passed and result.trail:
        line += f" (rules per event: {' '.join(result.trail)})"
    return line


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Wazuh 4.x logtest cases.")
    parser.add_argument("--cases", type=Path, required=True, help="cases file (.yml or .json)")
    parser.add_argument("--socket", default=DEFAULT_SOCKET, help="logtest socket path")
    parser.add_argument("--queue", default=DEFAULT_QUEUE, help="analysis queue socket path")
    parser.add_argument("--alerts", default=DEFAULT_ALERTS, help="alerts.json path")
    args = parser.parse_args(argv)
    results = run_all(socket_call(args.socket), load_cases(args.cases), args.queue, args.alerts)
    for result in results:
        print(describe(result))
    failed = sum(not r.passed for r in results)
    print(f"{len(results) - failed}/{len(results)} case(s) passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
