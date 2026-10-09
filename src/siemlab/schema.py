"""The Wazuh Common Schema (WCS) field list, downloaded on demand.

Wazuh 5 rejects a rule that names a field outside the WCS, so :mod:`siemlab.wazuh5` checks
every detection field against the official list. That list is published in
`wazuh/wazuh-indexer-plugins <https://github.com/wazuh/wazuh-indexer-plugins>`_, which is
licensed under the AGPL-3.0, so siemlab does not ship a copy: ``siemlab wazuh5 fetch-schema``
downloads it once, checks it against a pinned SHA-256, and caches it as one field name per
line (``noindex`` marks a field that is stored but not indexed, which a detector may not be
able to match on).

Lookup order: ``$SIEMLAB_WCS_FIELDS`` (a converted file), then the cache in
``$SIEMLAB_CACHE_DIR``, ``%LOCALAPPDATA%\\siemlab`` on Windows, or ``$XDG_CACHE_HOME/siemlab``
(``~/.cache/siemlab``) elsewhere.
"""

from __future__ import annotations

import csv
import hashlib
import io
import os
import sys
import urllib.request
from pathlib import Path

WCS_TAG = "5.0.0"
WCS_URL = (
    f"https://raw.githubusercontent.com/wazuh/wazuh-indexer-plugins/{WCS_TAG}"
    "/wcs/stateless/events/main/docs/fields.csv"
)
# SHA-256 of fields.csv at tag 5.0.0, checked on 2026-10-07 and 2026-10-09.
WCS_SHA256 = "86275f938419f0b0ca178ecb43a9b2d40379856887339626a6c6618f94e7b150"
_REQUIRED_COLUMNS = {"Field", "Indexed"}


class SchemaError(RuntimeError):
    """The schema could not be downloaded, verified or parsed."""


def cache_dir() -> Path:
    if os.environ.get("SIEMLAB_CACHE_DIR"):
        return Path(os.environ["SIEMLAB_CACHE_DIR"])
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "siemlab"
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "siemlab"


def schema_path() -> Path:
    """Where the converted field list is read from (and written to by :func:`fetch`)."""
    override = os.environ.get("SIEMLAB_WCS_FIELDS")
    return Path(override) if override else cache_dir() / f"wcs-events-{WCS_TAG}.txt"


def convert(csv_text: str) -> str:
    """fields.csv -> one ``field`` or ``field noindex`` per line, sorted."""
    reader = csv.DictReader(io.StringIO(csv_text))
    if not set(reader.fieldnames or ()) >= _REQUIRED_COLUMNS:
        raise SchemaError(f"not a WCS fields.csv: columns {reader.fieldnames}")
    lines = []
    for row in reader:
        name = (row.get("Field") or "").strip()
        if name:
            lines.append(name + ("" if row.get("Indexed") == "true" else " noindex"))
    if not lines:
        raise SchemaError("the WCS field list is empty")
    header = f"# Wazuh Common Schema event fields, wazuh-indexer-plugins {WCS_TAG}"
    return "\n".join([header, *sorted(set(lines))]) + "\n"


def _read(source: str) -> bytes:
    if source.startswith(("https://", "http://")):
        with urllib.request.urlopen(source, timeout=60) as resp:
            data: bytes = resp.read()
            return data
    return Path(source).read_bytes()


def fetch(source: str = WCS_URL, sha256: str | None = WCS_SHA256) -> Path:
    """Download (or read) fields.csv, verify it, and cache the converted list.

    ``sha256=None`` skips the check, for a newer schema or a file you already trust.
    """
    try:
        raw = _read(source)
    except OSError as exc:
        raise SchemaError(f"could not read {source}: {exc}") from exc
    digest = hashlib.sha256(raw).hexdigest()
    if sha256 is not None and digest != sha256:
        raise SchemaError(
            f"{source} has SHA-256 {digest}, expected {sha256}. If Wazuh changed the file on "
            "purpose, review it and run again with --no-verify."
        )
    text = convert(raw.decode("utf-8-sig"))
    path = schema_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path


def load() -> dict[str, bool] | None:
    """Field -> indexed, or None when the list has not been fetched."""
    path = schema_path()
    if not path.is_file():
        return None
    fields: dict[str, bool] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            name, _, flag = line.partition(" ")
            fields[name] = flag != "noindex"
    return fields
