"""The MITRE ATT&CK techniques this lab detects: id -> (name, primary tactic).

Kept deliberately small and explicit. The validator warns when a detection references a
technique missing from this table, so the coverage matrix never shows an unnamed ID.
"""

from __future__ import annotations

TACTIC_ORDER = (
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Impact",
)

# Wazuh 5 rules name the tactic by ID as well as by name.
TACTIC_IDS = {
    "Reconnaissance": "TA0043",
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Impact": "TA0040",
}

TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1595.002": ("Active Scanning: Vulnerability Scanning", "Reconnaissance"),
    "T1595.003": ("Active Scanning: Wordlist Scanning", "Reconnaissance"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "Persistence"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "Persistence"),
    "T1505.003": ("Server Software Component: Web Shell", "Persistence"),
    "T1547.001": (
        "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "Persistence",
    ),
    "T1548.003": (
        "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "Privilege Escalation",
    ),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", "Defense Evasion"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement"),
}

# Parents of the sub-techniques above. Wazuh 5 lists a sub-technique's parent separately.
PARENT_TECHNIQUES: dict[str, str] = {
    "T1595": "Active Scanning",
    "T1136": "Create Account",
    "T1053": "Scheduled Task/Job",
    "T1543": "Create or Modify System Process",
    "T1505": "Server Software Component",
    "T1547": "Boot or Logon Autostart Execution",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1070": "Indicator Removal",
    "T1021": "Remote Services",
}


def name(technique: str) -> str:
    return TECHNIQUES.get(technique, (technique, ""))[0]


def tactic(technique: str) -> str:
    return TECHNIQUES.get(technique, ("", "Unknown"))[1]


def technique_name(technique: str) -> str | None:
    """Name of a technique or sub-technique the lab knows, parents included."""
    if technique in TECHNIQUES:
        return TECHNIQUES[technique][0]
    return PARENT_TECHNIQUES.get(technique)


def url(technique: str) -> str:
    return f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"
