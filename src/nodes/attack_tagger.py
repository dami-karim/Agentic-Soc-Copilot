from datetime import datetime, timezone
from src.state import SOCAgentState, Phase
from src.tools.attack_corpus_tool import AttackStixTool

_attack_tool = AttackStixTool()

# Maps Windows Event Codes to ATT&CK search terms for the corpus tool
EVENTCODE_SEARCH_TERMS = {
    "4625": "brute force logon failed authentication",
    "4624": "valid accounts successful logon",
    "4688": "process execution command line",
    "4698": "scheduled task persistence",
    "4672": "privilege escalation special privileges",
    "4776": "credential access authentication",
}


def build_rationale(technique: dict, alert: dict, iocs: list) -> str:
    """
    Builds a human-readable rationale string explaining
    why this technique was tagged for this alert.
    """
    host = alert.get("host", "unknown")
    user = alert.get("user", "unknown")
    event_code = alert.get("EventCode", "unknown")
    src_ip = alert.get("src_ip", "unknown")

    ioc_values = [i["value"] for i in iocs[:3]]

    return (
        f"{technique['technique_id']} ({technique['technique_name']}) — "
        f"EventCode {event_code} on host {host} "
        f"involving account '{user}' from {src_ip}. "
        f"IoCs: {', '.join(ioc_values)}. "
        f"ATT&CK match score: {technique['score']}."
    )


def attack_tagger_node(state: SOCAgentState) -> SOCAgentState:
    state["phase"] = Phase.TAGGING
    alert = state["alert_raw"]
    event_code = str(alert.get("EventCode", ""))

    # Get the search term for this event code
    # Fall back to signature text if no specific mapping
    search_term = EVENTCODE_SEARCH_TERMS.get(
        event_code,
        alert.get("signature", "security event")
    )

    # Query the ATT&CK corpus for candidate techniques
    candidates = _attack_tool.query_techniques(search_term, top_k=5)

    # Build the final tagged techniques with rationale
    techniques = []
    for candidate in candidates:
        techniques.append({
            "technique_id": candidate["technique_id"],
            "technique_name": candidate["technique_name"],
            "confidence": min(candidate["score"] / 3.0, 1.0),
            "rationale": build_rationale(candidate, alert, state["ioc_list"]),
        })

    state["attack_techniques"] = techniques

    state["event_log"].append({
        "node": "attack_tagger",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detail": f"Tagged {len(techniques)} techniques: "
                  f"{[t['technique_id'] for t in techniques]}",
    })
    return state
