"""Load the Wazuh 5 content pack into the Wazuh indexer through the Content Manager API.

The sequence follows Wazuh's rule-testing workflow
(wazuh-indexer-plugins, docs/ref/modules/content-manager/rule-testing.md):

1. create each integration in the **draft** space, then its rules;
2. promote draft to **test**;
3. run every ``logtest.yml`` case against its integration in the test space, and compare the
   rule titles that matched with the ones expected;
4. only if every case passed, and only when asked, promote test to **custom** (production).

Detectors are not created here: Wazuh creates them from the dashboard (Security Analytics >
Detectors), where the index pattern of the events is chosen. See
docs/setup-guides/05-upgrading-wazuh.md.
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .wazuh5 import LogtestCase, Pack

API = "/_plugins/_content_manager"


class DeployError(RuntimeError):
    """The API refused a step; nothing after it was attempted."""


@dataclass(frozen=True)
class LogtestResult:
    case: LogtestCase
    matched: tuple[str, ...]
    error: str | None = None

    @property
    def passed(self) -> bool:
        return self.error is None and set(self.matched) == set(self.case.expect)


@dataclass
class DeployResult:
    integration_ids: dict[str, str] = field(default_factory=dict)
    rule_ids: dict[str, str] = field(default_factory=dict)
    logtests: list[LogtestResult] = field(default_factory=list)
    promoted_to_custom: bool = False

    @property
    def failed(self) -> list[LogtestResult]:
        return [r for r in self.logtests if not r.passed]


class ContentManager:
    """A minimal client for the Content Manager API (JSON in, JSON out)."""

    def __init__(
        self,
        url: str,
        user: str,
        password: str,
        *,
        ca_file: Path | None = None,
        insecure: bool = False,
        timeout: float = 60,
    ) -> None:
        self.url = url.rstrip("/")
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self._auth = f"Basic {token}"
        self.timeout = timeout
        self._context: ssl.SSLContext | None = None
        if self.url.startswith("https://"):
            if insecure:
                self._context = ssl.create_default_context()
                self._context.check_hostname = False
                self._context.verify_mode = ssl.CERT_NONE
            else:
                self._context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)

    def request(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("Authorization", self._auth)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._context) as resp:
                return resp.status, _json(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, _json(exc.read())


def _json(raw: bytes) -> Any:
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return raw.decode("utf-8", "replace")


def _message(body: Any) -> str:
    if isinstance(body, dict):
        return str(body.get("message", body))
    return str(body)


def _expect(code: int, body: Any, ok: int, what: str) -> Any:
    if code != ok:
        raise DeployError(f"{what}: HTTP {code}: {_message(body)}")
    return body


def _promote(cm: ContentManager, space: str) -> None:
    code, preview = cm.request("GET", f"{API}/promote?space={space}")
    _expect(code, preview, 200, f"preview promotion from {space}")
    changes = preview.get("changes") if isinstance(preview, dict) else None
    if not isinstance(changes, dict):
        raise DeployError(f"preview promotion from {space}: no 'changes' in the response")
    code, body = cm.request("POST", f"{API}/promote", {"space": space, "changes": changes})
    _expect(code, body, 200, f"promote from {space}")


def _logtest(cm: ContentManager, integration_id: str, case: LogtestCase) -> LogtestResult:
    code, body = cm.request(
        "POST",
        f"{API}/logtest",
        {
            "integration": integration_id,
            "space": "test",
            "queue": 1,
            "location": case.location,
            "event": case.event,
            "trace_level": "NONE",
        },
    )
    message = body.get("message") if isinstance(body, dict) else None
    if code != 200 or not isinstance(message, dict):
        return LogtestResult(case, (), f"HTTP {code}: {_message(body)}")
    normalization = message.get("normalization") or {}
    detection = message.get("detection") or {}
    if normalization.get("status") == "error":
        return LogtestResult(case, (), f"normalization: {normalization.get('error')}")
    if detection.get("status") != "success":
        return LogtestResult(
            case, (), f"detection {detection.get('status')}: {detection.get('reason', '')}"
        )
    titles = tuple(str(m.get("rule", {}).get("title", "")) for m in detection.get("matches") or ())
    return LogtestResult(case, titles)


def deploy(
    pack: Pack,
    cm: ContentManager,
    *,
    promote_custom: bool = False,
    say: Callable[[str], None] = print,
) -> DeployResult:
    """Create, promote and test the pack. Raises DeployError when the API refuses a step."""
    result = DeployResult()
    for integ in pack.integrations:
        code, body = cm.request("POST", f"{API}/integrations", {"resource": integ.doc})
        if code == 409:
            raise DeployError(
                f"integration {integ.title!r} already exists in the draft space. Delete it "
                "in the dashboard, or reset the whole draft space, then deploy again."
            )
        integ_id = str(_expect(code, body, 201, f"create integration {integ.title}")["message"])
        result.integration_ids[integ.title] = integ_id
        say(f"created integration {integ.title} ({integ_id})")
        for rule in (r for r in pack.rules if r.integration == integ.title):
            code, body = cm.request(
                "POST", f"{API}/rules", {"integration": integ_id, "resource": rule.doc}
            )
            rule_id = str(_expect(code, body, 201, f"create rule {rule.title!r}")["message"])
            result.rule_ids[rule.title] = rule_id
        say(f"  {sum(r.integration == integ.title for r in pack.rules)} rule(s)")

    _promote(cm, "draft")
    say("promoted draft -> test")

    for case in pack.logtests:
        outcome = _logtest(cm, result.integration_ids[case.integration], case)
        result.logtests.append(outcome)
        say(f"  {'PASS' if outcome.passed else 'FAIL'} {case.integration}: {case.event[:70]}")

    if promote_custom and not result.failed:
        _promote(cm, "test")
        result.promoted_to_custom = True
        say("promoted test -> custom")
    return result
