"""A minimal HTTPS client for the Wazuh indexer's REST APIs (JSON in, JSON out).

Used for the Content Manager API (``siemlab wazuh5 deploy``), the Alerting API
(``siemlab wazuh5 monitors``) and search (``siemlab wazuh5 export``). Only the standard
library: no credentials are stored, logged or written anywhere. The password comes from the
caller, which reads it from ``WAZUH_INDEXER_PASSWORD`` or a prompt, never from arguments.
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class IndexerError(RuntimeError):
    """The indexer refused a request; nothing after it was attempted."""


class IndexerClient:
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

    def __repr__(self) -> str:  # never show the credentials
        return f"IndexerClient({self.url!r})"

    def request(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("Authorization", self._auth)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._context) as resp:
                return resp.status, parse_json(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, parse_json(exc.read())

    def expect(self, method: str, path: str, body: Any, ok: int | set[int], what: str) -> Any:
        """Send a request and return the body; raise IndexerError on another status."""
        code, reply = self.request(method, path, body)
        allowed = {ok} if isinstance(ok, int) else ok
        if code not in allowed:
            raise IndexerError(f"{what}: HTTP {code}: {message(reply)}")
        return reply


def parse_json(raw: bytes) -> Any:
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return raw.decode("utf-8", "replace")


def message(body: Any) -> str:
    if isinstance(body, dict):
        return str(body.get("message") or body.get("error") or body)
    return str(body)
