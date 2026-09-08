"""
Static reference data for the UI: SIEM alert templates and Windows
EventCode descriptions.

These are INPUT templates only — the same field payloads used by the
pipeline's documented demo scenarios. Investigation results are never
mocked here; all displayed findings come from the live backend.
"""
from __future__ import annotations

from src.ui.icons import has as _has_icon
from src.ui.icons import icon as _icon


class Template:
    """An input scenario card: display metadata + the raw SIEM payload."""
    __slots__ = ("key", "title", "eventcode", "description", "tag", "ic",
                 "payload")

    def __init__(self, key: str, title: str, eventcode: str, description: str,
                 tag: str, ic: str, payload: dict):
        self.key = key
        self.title = title
        self.eventcode = eventcode
        self.description = description
        self.tag = tag            # ATT&CK reference shown on the card
        self.ic = ic              # icon name (validated below)
        self.payload = payload

    def icon_html(self, size: int = 18) -> str:
        name = self.ic if _has_icon(self.ic) else "alert-triangle"
        return _icon(name, size)


ALERT_TEMPLATES: list[Template] = [
    Template(
        key="brute_force",
        title="Brute Force Attack",
        eventcode="4625",
        description="Repeated failed authentication attempts against a "
                    "privileged account.",
        tag="T1110",
        ic="key",
        payload={
            "host": "WIN-DC01", "EventCode": "4625",
            "src_ip": "10.0.2.15", "dest_ip": "10.0.2.5",
            "user": "administrator", "Logon_Type": "3",
            "sourcetype": "WinEventLog:Security",
            "signature": "An account failed to log on — multiple failures detected",
            "severity": "medium", "count": 15,
        },
    ),
    Template(
        key="lateral_movement",
        title="Lateral Movement",
        eventcode="4624",
        description="Admin logon from the web tier to the database tier via SMB.",
        tag="T1021",
        ic="network",
        payload={
            "host": "WIN-WEB01", "EventCode": "4624",
            "src_ip": "10.0.2.5", "dest_ip": "10.0.2.20",
            "user": "administrator", "Logon_Type": "3",
            "sourcetype": "WinEventLog:Security",
            "signature": "Lateral movement via SMB — admin logon from web tier to database tier",
            "severity": "critical", "count": 1,
        },
    ),
    Template(
        key="command_execution",
        title="Command Execution",
        eventcode="4688",
        description="Encoded PowerShell process spawned on a production host.",
        tag="T1059",
        ic="terminal",
        payload={
            "host": "WIN-WEB01", "EventCode": "4688",
            "src_ip": "", "dest_ip": "",
            "user": "administrator",
            "sourcetype": "WinEventLog:Security",
            "signature": "New process: powershell.exe -enc SGVsbG8gV29ybGQ=",
            "severity": "high", "count": 1,
        },
    ),
    Template(
        key="scheduled_task",
        title="Scheduled Task Persistence",
        eventcode="4698",
        description="Potential persistence through a Windows scheduled task "
                    "under the SYSTEM account.",
        tag="T1053",
        ic="clock",
        payload={
            "host": "WIN-FIN02", "EventCode": "4698",
            "src_ip": "", "dest_ip": "",
            "user": "SYSTEM",
            "sourcetype": "WinEventLog:Security",
            "signature": "Scheduled task created: \\Microsoft\\Windows\\Update\\SystemMaintenance",
            "severity": "critical", "count": 1,
        },
    ),
    Template(
        key="benign_logoff",
        title="Benign Logoff",
        eventcode="4634",
        description="Routine user logoff — should close as benign.",
        tag="—",
        ic="check-circle",
        payload={
            "host": "WIN-WEB01", "EventCode": "4634",
            "src_ip": "", "dest_ip": "",
            "user": "jsmith",
            "sourcetype": "WinEventLog:Security",
            "signature": "An account was logged off",
            "severity": "low", "count": 1,
        },
    ),
]

# Backwards-compatible dict view {display name -> payload}
ALERT_TEMPLATES_DICT: dict[str, dict] = {
    f"{t.title} ({t.tag} · {t.eventcode})": t.payload for t in ALERT_TEMPLATES
}

# Static Microsoft documentation reference for common Windows Security
# EventCodes shown in tables/headers. Purely descriptive metadata.
EVENTCODE_DESCRIPTIONS: dict[str, str] = {
    "4624": "Successful logon",
    "4625": "Failed logon",
    "4634": "Logoff",
    "4648": "Logon with explicit credentials",
    "4663": "Object access attempt",
    "4672": "Special privileges assigned to new logon",
    "4688": "New process created",
    "4697": "Service installed",
    "4698": "Scheduled task created",
    "4699": "Scheduled task deleted",
    "4720": "User account created",
    "4776": "Credential validation",
}

# Pipeline phase labels used by the timeline view (mirrors src/state.py Phase)
PIPELINE_NODE_LABELS = {
    "ingest":          "Alert received",
    "classify":        "Classification",
    "investigate":     "Evidence analysis",
    "hil_classify":    "Classification review",
    "rca_generator":   "Root cause analysis",
    "propose_actions": "Recommended actions",
    "hil_action":      "Action approval",
    "deploy":          "Disposition",
}
