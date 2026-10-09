"""Load the Wazuh 5 content pack into the Wazuh indexer.

:func:`deploy` follows Wazuh's rule-testing workflow
(wazuh-indexer-plugins, docs/ref/modules/content-manager/rule-testing.md):

1. create each integration in the **draft** space, then its rules;
2. promote draft to **test**;
3. run every ``logtest.yml`` case against its integration in the test space, and compare the
   rule titles that matched with the ones expected;
4. only if every case passed, and only when asked, promote test to **custom** (production).

:func:`deploy_monitors` creates or updates the pack's alerting monitors, which count findings
in real time (brute force, content discovery) because Wazuh 5 rules cannot count. It matches
existing monitors by name, so running it again updates them instead of adding copies.

Detectors are not created here: Wazuh creates them from the dashboard (Security Analytics >
Detectors), where the index pattern of the events is chosen. See
docs/setup-guides/05-upgrading-wazuh.md.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .indexer import IndexerClient, IndexerError, message
from .wazuh5 import LogtestCase, Pack

API = "/_plugins/_content_manager"
ALERTING = "/_plugins/_alerting/monitors"


class DeployError(IndexerError):
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


def _expect(code: int, body: Any, ok: int, what: str) -> Any:
    if code != ok:
        raise DeployError(f"{what}: HTTP {code}: {message(body)}")
    return body


def _promote(client: IndexerClient, space: str) -> None:
    code, preview = client.request("GET", f"{API}/promote?space={space}")
    _expect(code, preview, 200, f"preview promotion from {space}")
    changes = preview.get("changes") if isinstance(preview, dict) else None
    if not isinstance(changes, dict):
        raise DeployError(f"preview promotion from {space}: no 'changes' in the response")
    code, body = client.request("POST", f"{API}/promote", {"space": space, "changes": changes})
    _expect(code, body, 200, f"promote from {space}")


def _logtest(client: IndexerClient, integration_id: str, case: LogtestCase) -> LogtestResult:
    code, body = client.request(
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
    reply = body.get("message") if isinstance(body, dict) else None
    if code != 200 or not isinstance(reply, dict):
        return LogtestResult(case, (), f"HTTP {code}: {message(body)}")
    normalization = reply.get("normalization") or {}
    detection = reply.get("detection") or {}
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
    client: IndexerClient,
    *,
    promote_custom: bool = False,
    say: Callable[[str], None] = print,
) -> DeployResult:
    """Create, promote and test the pack. Raises DeployError when the API refuses a step."""
    result = DeployResult()
    for integ in pack.integrations:
        code, body = client.request("POST", f"{API}/integrations", {"resource": integ.doc})
        if code == 409:
            raise DeployError(
                f"integration {integ.title!r} already exists in the draft space. Delete it "
                "in the dashboard, or reset the whole draft space, then deploy again."
            )
        integ_id = str(_expect(code, body, 201, f"create integration {integ.title}")["message"])
        result.integration_ids[integ.title] = integ_id
        say(f"created integration {integ.title} ({integ_id})")
        for rule in (r for r in pack.rules if r.integration == integ.title):
            code, body = client.request(
                "POST", f"{API}/rules", {"integration": integ_id, "resource": rule.doc}
            )
            rule_id = str(_expect(code, body, 201, f"create rule {rule.title!r}")["message"])
            result.rule_ids[rule.title] = rule_id
        say(f"  {sum(r.integration == integ.title for r in pack.rules)} rule(s)")

    _promote(client, "draft")
    say("promoted draft -> test")

    for case in pack.logtests:
        outcome = _logtest(client, result.integration_ids[case.integration], case)
        result.logtests.append(outcome)
        say(f"  {'PASS' if outcome.passed else 'FAIL'} {case.integration}: {case.event[:70]}")

    if promote_custom and not result.failed:
        _promote(client, "test")
        result.promoted_to_custom = True
        say("promoted test -> custom")
    return result


def _existing_monitor(client: IndexerClient, name: str) -> str | None:
    """The ID of the monitor with exactly this name, if there is one."""
    reply = client.expect(
        "POST",
        f"{ALERTING}/_search",
        {"size": 10, "query": {"match_phrase": {"monitor.name": name}}},
        200,
        f"search monitors named {name!r}",
    )
    hits = reply.get("hits", {}).get("hits", []) if isinstance(reply, dict) else []
    for hit in hits:
        source = hit.get("_source") or {}
        if (source.get("monitor") or source).get("name") == name:
            return str(hit["_id"])
    return None


def deploy_monitors(
    pack: Pack, client: IndexerClient, *, say: Callable[[str], None] = print
) -> dict[str, str]:
    """Create or update every monitor of the pack. Returns name -> monitor ID."""
    ids: dict[str, str] = {}
    for monitor in pack.monitors:
        existing = _existing_monitor(client, monitor.name)
        if existing:
            client.expect(
                "PUT", f"{ALERTING}/{existing}", monitor.doc, 200, f"update {monitor.name!r}"
            )
            ids[monitor.name] = existing
            say(f"updated monitor {monitor.name}")
        else:
            reply = client.expect(
                "POST", ALERTING, monitor.doc, {200, 201}, f"create {monitor.name!r}"
            )
            ids[monitor.name] = str(reply.get("_id", "")) if isinstance(reply, dict) else ""
            say(f"created monitor {monitor.name}")
    return ids
