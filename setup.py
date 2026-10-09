"""Build hook: bundle the lab kit into the package.

All project metadata lives in pyproject.toml. This file only extends ``build_py`` so that the
wheel carries the detections, lab scripts, configs, runbooks and synthetic samples under
``siemlab/_kit`` (see src/siemlab/kit.py). The sdist includes them through MANIFEST.in.
"""

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

ROOT = Path(__file__).resolve().parent
KIT_DIRS = ("detections", "scripts", "configs", "docs", "sample-data")
KIT_FILES = (
    "README.md",
    "LICENSE",
    "COMMERCIAL-LICENSE.md",
    "THIRD_PARTY_NOTICES.md",
    "CHANGELOG.md",
)


class BuildPyWithKit(build_py):
    def run(self) -> None:
        super().run()
        kit = Path(self.build_lib) / "siemlab" / "_kit"
        ignore = shutil.ignore_patterns("__pycache__", "*.pyc", ".gitkeep")
        for name in KIT_DIRS:
            if (ROOT / name).is_dir():
                shutil.copytree(ROOT / name, kit / name, dirs_exist_ok=True, ignore=ignore)
        for name in KIT_FILES:
            if (ROOT / name).is_file():
                kit.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, kit / name)


setup(cmdclass={"build_py": BuildPyWithKit})
