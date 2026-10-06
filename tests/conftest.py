from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from siemlab.alerts import Alert

REPO = Path(__file__).resolve().parents[1]
DETECTIONS = REPO / "detections"
T0 = datetime(2026, 10, 5, 12, 0, 0, tzinfo=UTC)


def make_alert(
    second: float,
    rule_id: str = "100100",
    *,
    level: int = 5,
    groups: tuple[str, ...] = (),
    techniques: tuple[str, ...] = (),
    agent: str = "ubuntu-endpoint",
    src_ip: str | None = "10.10.10.50",
    user: str | None = "root",
    description: str = "test alert",
) -> Alert:
    return Alert(
        timestamp=T0 + timedelta(seconds=second),
        rule_id=rule_id,
        level=level,
        description=description,
        groups=groups,
        techniques=techniques,
        agent=agent,
        src_ip=src_ip,
        user=user,
    )


def failure(second: float, **kw: Any) -> Alert:
    kw.setdefault("groups", ("sshd", "authentication_failed"))
    kw.setdefault("techniques", ("T1110.001",))
    return make_alert(second, **kw)


def success(second: float, **kw: Any) -> Alert:
    kw.setdefault("groups", ("sshd", "authentication_success"))
    kw.setdefault("rule_id", "5715")
    kw.setdefault("level", 3)
    return make_alert(second, **kw)


@pytest.fixture
def detections() -> Path:
    return DETECTIONS
