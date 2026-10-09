"""The lab kit: detections, lab scripts, configs, runbooks and synthetic samples.

An installed ``siemlab`` carries the kit inside the package (``siemlab/_kit``, copied there
at build time by ``setup.py``), so every command works outside a clone of the repository.
In a source checkout the kit is the checkout itself. ``siemlab init DIR`` copies the kit
into a directory of your own to edit, version and deploy.
"""

from __future__ import annotations

import shutil
from pathlib import Path

# Copied into the package at build time, and by `siemlab init`.
KIT_DIRS = ("detections", "scripts", "configs", "docs", "sample-data")
KIT_FILES = ("README.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "CHANGELOG.md")


def root() -> Path | None:
    """The bundled kit, or the source checkout siemlab runs from, or None."""
    here = Path(__file__).resolve().parent
    packaged = here / "_kit"
    if (packaged / "detections").is_dir():
        return packaged
    checkout = here.parents[1]  # src/siemlab -> repository root
    if (checkout / "detections").is_dir() and (checkout / "pyproject.toml").is_file():
        return checkout
    return None


def detections_dir() -> Path:
    """``./detections`` when there is one (an initialised kit), else the bundled detections."""
    local = Path("detections")
    if local.is_dir():
        return local
    kit = root()
    return kit / "detections" if kit else local


def sample(name: str) -> Path:
    kit = root()
    if kit is None:
        raise FileNotFoundError("the lab kit is not installed with this siemlab")
    path = kit / "sample-data" / "sanitized" / name
    if not path.is_file():
        raise FileNotFoundError(f"sample {name} not found in {path.parent}")
    return path


def init(dest: Path, *, force: bool = False) -> list[str]:
    """Copy the kit into ``dest``. Refuses a non-empty directory unless ``force``."""
    kit = root()
    if kit is None:
        raise FileNotFoundError("the lab kit is not installed with this siemlab")
    if dest.exists() and any(dest.iterdir()) and not force:
        raise FileExistsError(f"{dest} is not empty: choose another directory or use --force")
    dest.mkdir(parents=True, exist_ok=True)
    copied = []
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    for name in KIT_DIRS:
        if (kit / name).is_dir():
            shutil.copytree(kit / name, dest / name, dirs_exist_ok=True, ignore=ignore)
            copied.append(f"{name}/")
    for name in KIT_FILES:
        if (kit / name).is_file():
            shutil.copy2(kit / name, dest / name)
            copied.append(name)
    return copied
