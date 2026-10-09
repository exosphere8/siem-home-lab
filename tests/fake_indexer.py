"""A fake Wazuh indexer: just enough of the Content Manager, Alerting and search APIs."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

CONTENT = "/_plugins/_content_manager"
ALERTING = "/_plugins/_alerting/monitors"


class FakeIndexer(BaseHTTPRequestHandler):
    """Requests are recorded in ``server.state["calls"]``; behaviour is driven by the state."""

    def log_message(self, *args: Any) -> None:  # keep test output quiet
        pass

    @property
    def state(self) -> dict[str, Any]:
        return self.server.state  # type: ignore[attr-defined, no-any-return]

    def _reply(self, code: int, body: Any) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> Any:
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length)) if length else None

    def _handle(self, method: str) -> None:
        body = self._body()
        self.state["calls"].append((method, self.path))
        assert self.headers["Authorization"].startswith("Basic ")
        path = urlsplit(self.path).path
        handler = getattr(self, f"_{method.lower()}", None)
        reply = handler(path, body) if handler else None
        if reply is None:
            reply = (404, {"message": "no such endpoint"})
        self._reply(*reply)

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._handle("PUT")

    def do_DELETE(self) -> None:
        self._handle("DELETE")

    # -- routes ----------------------------------------------------------------------------

    def _get(self, path: str, body: Any) -> tuple[int, Any] | None:
        if path == f"{CONTENT}/promote":
            return 200, {"changes": {"integrations": [], "rules": [], "policy": []}}
        return None

    def _post(self, path: str, body: Any) -> tuple[int, Any] | None:
        s = self.state
        if path == f"{CONTENT}/integrations":
            title = body["resource"]["metadata"]["title"]
            if title in s["existing"]:
                return 409, {"message": "exists", "status": 409}
            return 201, {"message": f"id-{title}", "status": 201}
        if path == f"{CONTENT}/rules":
            return 201, {"message": "rule-id", "status": 201}
        if path == f"{CONTENT}/promote":
            s["promoted"].append(body["space"])
            return 200, {"message": "Promotion completed successfully"}
        if path == f"{CONTENT}/logtest":
            return 200, {"status": 200, "message": s["logtest"](body)}
        if path == f"{ALERTING}/_search":
            name = body["query"]["match_phrase"]["monitor.name"]
            hits = [
                {"_id": mid, "_source": {"monitor": doc}}
                for mid, doc in s["monitors"].items()
                if doc["name"] == name
            ]
            return 200, {"hits": {"hits": hits}}
        if path == ALERTING:
            mid = f"mon-{len(s['monitors']) + 1}"
            s["monitors"][mid] = body
            return 201, {"_id": mid, "monitor": body}
        if path.endswith("/_search") and "scroll=" in self.path:
            if s.get("search_error"):
                return 500, {"error": "search failed"}
            return self._page(0)
        if path == "/_search/scroll":
            if s.get("scroll_error"):
                return 500, {"error": "scroll failed"}
            return self._page(int(body["scroll_id"]))
        return None

    def _put(self, path: str, body: Any) -> tuple[int, Any] | None:
        mid = path.removeprefix(f"{ALERTING}/")
        if path.startswith(f"{ALERTING}/") and mid in self.state["monitors"]:
            self.state["monitors"][mid] = body
            self.state["updated"].append(mid)
            return 200, {"_id": mid}
        return None

    def _delete(self, path: str, body: Any) -> tuple[int, Any] | None:
        if path == "/_search/scroll":
            self.state["cleared"].append(body["scroll_id"])
            return 200, {"succeeded": True}
        return None

    def _page(self, n: int) -> tuple[int, Any]:
        pages = self.state["pages"]
        hits = pages[n] if n < len(pages) else []
        return 200, {"_scroll_id": str(n + 1), "hits": {"hits": [{"_source": h} for h in hits]}}


@contextmanager
def running(**state: Any) -> Iterator[tuple[str, dict[str, Any]]]:
    """Run a fake indexer; yields its URL and its mutable state."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeIndexer)
    full: dict[str, Any] = {
        "calls": [],
        "promoted": [],
        "existing": set(),
        "monitors": {},
        "updated": [],
        "pages": [],
        "cleared": [],
        "logtest": lambda body: {"detection": {"status": "success", "matches": []}},
    }
    full.update(state)
    server.state = full  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", full
    finally:
        server.shutdown()
        server.server_close()
