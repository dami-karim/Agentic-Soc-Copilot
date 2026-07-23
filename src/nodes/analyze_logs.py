from datetime import datetime, timezone
from src.state import SOCAgentState, Phase
from src.tools.opensearch_tool import OpenSearchLogTool
from src.tools.qdrant_tool import QdrantIncidentTool

# Initialize tools once at module level
# This avoids reconnecting on every node call
_log_tool = OpenSearchLogTool()
_incident_tool = QdrantIncidentTool()


def extract_iocs(alert: dict) -> list[dict]:
    """
    First-pass IoC extraction from alert fields.
    Returns structured IoC objects with type, value, confidence, source.
    """
    iocs = []

    if alert.get("src_ip"):
        iocs.append({
            "type": "ip",
            "value": alert["src_ip"],
            "confidence": 0.8,
            "source": "alert_field"
        })

    if alert.get("user"):
        iocs.append({
            "type": "account",
            "value": alert["user"],
            "confidence": 0.8,
            "source": "alert_field"
        })

    if alert.get("host"):
        iocs.append({
            "type": "host",
            "value": alert["host"],
            "confidence": 0.9,
            "source": "alert_field"
        })

    if alert.get("dest_ip"):
        iocs.append({
            "type": "ip",
            "value": alert["dest_ip"],
            "confidence": 0.6,
            "source": "alert_field"
        })

    return iocs


def analyze_logs_node(state: SOCAgentState) -> SOCAgentState:
    state["phase"] = Phase.ANALYZING
    alert = state["alert_raw"]

    # Step 1 — extract IoCs from the raw alert
    iocs = extract_iocs(alert)
    state["ioc_list"] = iocs

    # Step 2 — enrich each IoC with related log events from OpenSearch
    # This is the RAM-ablation-justified enrichment step
    enrichment = {}
    for ioc in iocs:
        query = f"{ioc['value']}"
        related_logs = _log_tool.search(
            query=query,
            time_range=("now-30d", "now")
        )
        enrichment[ioc["value"]] = related_logs

    # Step 3 — retrieve similar past incidents from Qdrant
    # Gives the LLM grounded precedent to reason from
    alert_description = (
        f"EventCode {alert.get('EventCode', '')} "
        f"on host {alert.get('host', '')} "
        f"from {alert.get('src_ip', '')} "
        f"user {alert.get('user', '')}"
    )
    similar = _incident_tool.similar_incidents(alert_description, top_k=3)
    enrichment["similar_past_incidents"] = similar

    state["enrichment"] = enrichment

    state["event_log"].append({
        "node": "analyze_logs",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detail": f"Extracted {len(iocs)} IoCs, "
                  f"enriched from OpenSearch, "
                  f"retrieved {len(similar)} similar past incidents",
    })
    return state
