"""
Signals — deterministic feature extraction from a raw SIEM alert.

The false-positive filter turns each alert into a small set of signals
that the rule-based classifier can reason over WITHOUT any LLM or tool
calls. This keeps the filter fast enough to triage thousands of alerts
in a single batch.

Signals are grouped into three layers:
  - Static fields   : severity, EventCode, user, Logon_Type, count
  - Signature text  : benign / false-positive / malicious keyword patterns
  - Structural cues : known-benign event codes, admin account, failure volume
"""
import re
from dataclasses import dataclass

# Event codes that are almost always routine, non-malicious activity.
# Following the rule-based baseline (src/eval/baseline_rule_based.py).
BENIGN_EVENT_CODES = {"4634", "4647", "4800", "4801"}

# Accounts that frequently appear in false positives (service accounts
# doing scheduled logons), but also make an alert MORE suspicious when
# combined with privileged operations.
SERVICE_ACCOUNT_PATTERNS = (
    "svc_", "sqlagent", "backup", "mssql$", "spooler", "tsvc", "cifs$",
)

ADMIN_ACCOUNTS = {"administrator", "domain admin", "ad\\administrator", "sa", "root"}

# Signatures that strongly indicate routine/benign activity.
BENIGN_SIGNATURES = [
    "logged off",
    "logged out",
    "unlocked",
    "screen saver",
    "successfully logged off",
    "user initiated logoff",
    "closed resource",
    "system time changed",
    "print job completed",
    "scheduled to start",
    "security audit",
    "informational",
]

# Signatures of classic SOC noise — activity that fires detection rules but
# is almost never a real incident (scans, patching, maintenance, tests).
FALSE_POSITIVE_SIGNATURES = [
    "vulnerability scan",
    "vulnerability scanner",
    "nessus scan",
    "qualys",
    "openvas",
    "port scan",
    "network scan",
    "windows update",
    "defender update",
    "antivirus signature",
    "av definition update",
    "backup",
    "maintenance window",
    "test alert",
    "false positive",
    "drill",
    "containment test",
]

# Signatures that strongly indicate a genuine threat regardless of severity.
MALICIOUS_SIGNATURES = [
    "failed to log on",
    "failed login",
    "password spray",
    "brute force",
    "credential dumping",
    "mimikatz",
    "lsass",
    "lateral movement",
    "scheduled task",
    "powershell -enc",
    "-encodedcommand",
    "encoded command",
    "web shell",
    "cmd.exe redirection",
    "ransomware",
    "cobalt strike",
    "beacon",
    "log cleared",
    "security log was cleared",
    "isolation",
    "privilege escalation",
    "exploit",
    "dropper",
    "wscript",
    "cscript",
    "persistence",
]

_COMPILED = {
    "benign": [(re.compile(p, re.IGNORECASE), p) for p in BENIGN_SIGNATURES],
    "false_positive": [(re.compile(p, re.IGNORECASE), p) for p in FALSE_POSITIVE_SIGNATURES],
    "malicious": [(re.compile(p, re.IGNORECASE), p) for p in MALICIOUS_SIGNATURES],
}


def _match_signature(text: str, category: str):
    for pattern, phrase in _COMPILED[category]:
        if pattern.search(text):
            return phrase
    return None


@dataclass
class AlertSignals:
    """Structured view of one alert for the rule classifier."""

    severity: str
    event_code: str
    base_score: float
    eventcode_boost: float
    count: int
    logon_type: str
    user: str
    is_admin: bool
    is_service_account: bool
    benign_signature: str | None = None
    false_positive_signature: str | None = None
    malicious_signature: str | None = None
    has_benign_code: bool = False
    high_failure_volume: bool = False

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "event_code": self.event_code,
            "base_score": self.base_score,
            "eventcode_boost": self.eventcode_boost,
            "count": self.count,
            "logon_type": self.logon_type,
            "user": self.user,
            "is_admin": self.is_admin,
            "is_service_account": self.is_service_account,
            "benign_signature": self.benign_signature,
            "false_positive_signature": self.false_positive_signature,
            "malicious_signature": self.malicious_signature,
            "has_benign_code": self.has_benign_code,
            "high_failure_volume": self.high_failure_volume,
        }


def _as_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 1


def extract_signals(alert: dict, base_score: float, eventcode_boost: float) -> AlertSignals:
    """
    Extract deterministic signals from a raw alert.

    Args:
        alert: Raw SIEM alert dictionary.
        base_score: Severity-derived base score (from classifier).
        eventcode_boost: EventCode boost (from classifier).

    Returns:
        AlertSignals with all matched patterns and structural cues.
    """
    severity = str(alert.get("severity", "medium")).lower()
    event_code = str(alert.get("EventCode", ""))
    count = _as_int(alert.get("count", 1))

    user = str(alert.get("user", "")).lower()
    user = user.replace("nt authority\\", "").replace("domain\\", "").strip("$!")
    is_admin = user in ADMIN_ACCOUNTS or "administrator" in user
    is_service_account = any(s in user for s in SERVICE_ACCOUNT_PATTERNS)

    signature = str(alert.get("signature", ""))
    benign_match = _match_signature(signature, "benign")
    fp_match = _match_signature(signature, "false_positive")
    malicious_match = _match_signature(signature, "malicious")

    logon_type = str(alert.get("Logon_Type", ""))
    failure_codes = {"4625", "4624", "4776"}
    high_failure_volume = (
        count >= 10 and event_code in failure_codes and benign_match is None
    )

    return AlertSignals(
        severity=severity,
        event_code=event_code,
        base_score=base_score,
        eventcode_boost=eventcode_boost,
        count=count,
        logon_type=logon_type,
        user=user,
        is_admin=is_admin,
        is_service_account=is_service_account,
        benign_signature=benign_match,
        false_positive_signature=fp_match,
        malicious_signature=malicious_match,
        has_benign_code=event_code in BENIGN_EVENT_CODES,
        high_failure_volume=high_failure_volume,
    )