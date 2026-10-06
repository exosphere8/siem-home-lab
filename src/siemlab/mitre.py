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


def name(technique: str) -> str:
    return TECHNIQUES.get(technique, (technique, ""))[0]


def tactic(technique: str) -> str:
    return TECHNIQUES.get(technique, ("", "Unknown"))[1]


def url(technique: str) -> str:
    return f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"
