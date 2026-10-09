"""Export Wazuh 5 findings from the indexer as JSON lines for ``siemlab correlate``.

Findings live in ``wazuh-findings-v5-*``, not in a file. :func:`export_findings` pages
through them oldest first with the scroll API (a plain search stops at 10,000 hits), writes
each finding's ``_source`` on its own line, and always releases the scroll context.

The output is live security data: keep it out of version control (``exports/`` is ignored).
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Iterator
from typing import Any, TextIO

from .alerts import iter_json_lines
from .indexer import IndexerClient

FINDINGS = "wazuh-findings-v5-*"
_SINCE = re.compile(r"^\d+[mhdw]$")
_KEEP_ALIVE = "2m"


def _query(since: str | None) -> dict[str, Any]:
    if since is None:
        return {"match_all": {}}
    if not _SINCE.match(since):
        raise ValueError(f"--since {since!r}: use a number and m, h, d or w, for example 24h")
    return {"range": {"@timestamp": {"gte": f"now-{since}"}}}


def iter_findings(
    client: IndexerClient, *, since: str | None = None, index: str = FINDINGS, page: int = 1000
) -> Iterator[dict[str, Any]]:
    """Every finding's ``_source``, oldest first."""
    body = {"size": page, "sort": [{"@timestamp": "asc"}], "query": _query(since)}
    reply = client.expect(
        "POST", f"/{index}/_search?scroll={_KEEP_ALIVE}", body, 200, f"search {index}"
    )
    scroll_id = reply.get("_scroll_id") if isinstance(reply, dict) else None
    try:
        while True:
            hits = reply.get("hits", {}).get("hits", []) if isinstance(reply, dict) else []
            if not hits:
                return
            for hit in hits:
                source = hit.get("_source")
                if isinstance(source, dict):
                    yield source
            if not scroll_id:
                return
            reply = client.expect(
                "POST",
                "/_search/scroll",
                {"scroll": _KEEP_ALIVE, "scroll_id": scroll_id},
                200,
                "continue the scroll",
            )
            scroll_id = reply.get("_scroll_id", scroll_id) if isinstance(reply, dict) else None
    finally:
        if scroll_id:
            # Best effort: the scroll context also expires on its own.
            with contextlib.suppress(OSError):
                client.request("DELETE", "/_search/scroll", {"scroll_id": [scroll_id]})


def export_findings(client: IndexerClient, out: TextIO, **kw: Any) -> int:
    """Write findings as JSON lines to ``out``; returns how many were written."""
    count = 0
    for line in iter_json_lines(iter_findings(client, **kw)):
        out.write(line + "\n")
        count += 1
    return count
