from datetime import datetime, timezone
from src.state import SOCAgentState, Phase

# Base scores from alert severity field
SEVERITY_SCORES = {
    "low": 10,
    "medium": 40,
    "high": 70,
    "critical": 90,
}

# Additional score boost for specific high-risk Windows Event Codes
EVENTCODE_BOOSTS = {
    "4625": 20,   # Failed logon — brute force indicator
    "4624": 10,   # Successful logon — context, moderate boost
    "4688": 25,   # New process created — execution indicator
    "4698": 30,   # Scheduled task created — persistence indicator
    "4672": 15,   # Special privileges assigned — privilege escalation
    "4776": 20,   # Credential validation — lateral movement context
}

BENIGN_THRESHOLD = 30.0  # below this → benign path


def classify_node(state: SOCAgentState) -> SOCAgentState:
    state["phase"] = Phase.CLASSIFYING
    alert = state["alert_raw"]

    severity = alert.get("severity", "medium").lower()
    base_score = SEVERITY_SCORES.get(severity, 40)

    event_code = str(alert.get("EventCode", ""))
    boost = EVENTCODE_BOOSTS.get(event_code, 0)

    triage_score = min(base_score + boost, 100.0)
    state["triage_score"] = triage_score
    state["severity"] = severity

    route = "malicious" if triage_score >= BENIGN_THRESHOLD else "benign"

    state["event_log"].append({
        "node": "classify",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detail": f"triage_score={triage_score} severity={severity} "
                  f"EventCode={event_code} route={route}",
    })
    return state
