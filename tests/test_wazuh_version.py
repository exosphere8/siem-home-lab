"""The lab is pinned to one Wazuh version: the setup guides must all install that version."""

from __future__ import annotations

import re

import pytest

from conftest import REPO

PINNED = (REPO / "configs" / "wazuh-version").read_text(encoding="utf-8").strip()
INSTALL_GUIDES = ("02-wazuh-server.md", "03-linux-agent.md", "04-windows-agent.md")


def test_pinned_version_is_a_4x_release():
    assert re.fullmatch(r"4\.\d+\.\d+", PINNED), PINNED


@pytest.mark.parametrize("guide", INSTALL_GUIDES)
def test_install_guides_use_the_pinned_version(guide):
    text = (REPO / "docs" / "setup-guides" / guide).read_text(encoding="utf-8")
    versions = set(re.findall(r"\b4\.\d+\.\d+\b", text))
    assert versions == {PINNED}, f"{guide} mentions {sorted(versions)}, pinned is {PINNED}"


def test_installer_series_matches_the_pinned_version():
    text = (REPO / "docs" / "setup-guides" / "02-wazuh-server.md").read_text(encoding="utf-8")
    series = PINNED.rsplit(".", 1)[0]
    assert f"packages.wazuh.com/{series}/wazuh-install.sh" in text


def test_deploy_script_reads_the_pinned_version():
    script = (REPO / "scripts" / "deploy" / "deploy-rules.sh").read_text(encoding="utf-8")
    assert "configs/wazuh-version" in script
