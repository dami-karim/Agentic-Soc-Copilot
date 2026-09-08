import os
os.environ["CUDA_VISIBLE_DEVICES"] = ""
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"

from datetime import datetime, timezone
from src.state import SOCAgentState, Phase
from src.tools.opensearch_tool import OpenSearchLogTool
from src.tools.qdrant_tool import QdrantIncidentTool
from src.guardrails.guardrail_wrapper import check_tool_argument

_log_tool = OpenSearchLogTool()
_incident_tool = QdrantIncidentTool()


def extract_iocs(alert: dict) -> list[dict]:
    iocs = []
    if alert.get("src_ip"):
        iocs.append({"type": "ip", "value": alert["src_ip"], "confidence": 0.8, "source": "alert_field"})
    if alert.get("user"):
        iocs.append({"type": "account", "value": alert["user"], "confidence": 0.8, "source": "alert_field"})
    if alert.get("host"):
        iocs.append({"type": "host", "value": alert["host"], "confidence": 0.9, "source": "alert_field"})
    if alert.get("dest_ip"):
        iocs.append({"type": "ip", "value": alert["dest_ip"], "confidence": 0.6, "source": "alert_field"})
    return iocs


def analyze_logs_node(state: SOCAgentState) -> SOCAgentState:
    state["phase"] = Phase.ANALYZING
    alert = state["alert_raw"]

    iocs = extract_iocs(alert)
    state["ioc_list"] = iocs

    enrichment = {}
    for ioc in iocs:
        # GUARDRAIL: validate IoC value before passing to OpenSearch
        state, is_safe = check_tool_argument(
            state=state,
            tool_name="OpenSearchLogTool",
            argument_name="query",
            argument_value=ioc["value"],
            node_name="analyze_logs"
        )
        if not is_safe:
            # Log the block and skip this IoC
            enrichment[ioc["value"]] = [{"error": "Blocked by guardrail", "value": ioc["value"]}]
            continue

        query = f"{ioc['value']}"
        related_logs = _log_tool.search(query=query, time_range=("now-30d", "now"))
        enrichment[ioc["value"]] = related_logs

    alert_description = (
        f"EventCode {alert.get('EventCode', '')} "
        f"on host {alert.get('host', '')} "
        f"from {alert.get('src_ip', '')} "
        f"user {alert.get('user', '')}"
    )

    # GUARDRAIL: validate query before Qdrant call
    state, is_safe = check_tool_argument(
        state=state,
        tool_name="QdrantIncidentTool",
        argument_name="query_text",
        argument_value=alert_description,
        node_name="analyze_logs"
    )
    if is_safe:
        similar = _incident_tool.similar_incidents(alert_description, top_k=3)
        enrichment["similar_past_incidents"] = similar
    else:
        enrichment["similar_past_incidents"] = []

    state["enrichment"] = enrichment

    guardrail_count = len([f for f in state["guardrail_flags"] if f["node"] == "analyze_logs"])
    state["event_log"].append({
        "node": "analyze_logs",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detail": (
            f"Extracted {len(iocs)} IoCs, enriched from OpenSearch, "
            f"retrieved {len(enrichment.get('similar_past_incidents', []))} similar incidents. "
            f"Guardrail flags: {guardrail_count}"
        ),
    })
    return state