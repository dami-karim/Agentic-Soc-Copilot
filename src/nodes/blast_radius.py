"""
Blast Radius Node — Neo4j asset graph traversal.

This node answers the question every Tier-1 analyst asks after
confirming a true positive: "This host is compromised — what else
is at risk?"

It queries Neo4j with a variable-depth Cypher path traversal,
starting from the compromised host or identity identified in the
alert, and returns all assets reachable within max_hops steps.

This is the project's primary architectural contribution over LanG
(arXiv:2604.05440), which uses a flat relational UICR store and
explicitly cannot answer "what can the attacker reach next" during
an active investigation.

Literature reference:
  OCR-APT (arXiv:2510.15188) — "graph representation is what makes
  causal root-cause reasoning tractable."
"""
from datetime import datetime, timezone
from src.state import SOCAgentState, Phase
from src.tools.neo4j_tool import Neo4jGraphTool

# Initialize once at module level — avoids reconnecting on every call
_graph_tool = Neo4jGraphTool()

# How many hops to traverse. 3 is the default from architecture/decisions.md
MAX_HOPS = 3


def get_start_node(alert: dict, ioc_list: list) -> str | None:
    """
    Identifies the best starting node for the blast-radius query.

    Priority order:
      1. Host field from the alert (most direct — the target machine)
      2. A "host" type IoC from the ioc_list
      3. An "account" type IoC (identity-based blast radius)
      4. None if nothing found

    Why this priority: the host is the directly attacked asset.
    Starting from there gives the most actionable blast radius —
    "what can an attacker on WIN-DC01 reach" is more useful than
    "what can the source IP reach" since we don't own the source IP.
    """
    # First choice: host field directly from the raw alert
    if alert.get("host"):
        return alert["host"]

    # Second choice: host-type IoC extracted during analyze_logs
    for ioc in ioc_list:
        if ioc.get("type") == "host":
            return ioc["value"]

    # Third choice: account-type IoC for identity-based traversal
    for ioc in ioc_list:
        if ioc.get("type") == "account":
            return ioc["value"]

    return None


def blast_radius_node(state: SOCAgentState) -> SOCAgentState:
    """
    Queries Neo4j for all assets reachable from the compromised node.

    Writes to:
      state["blast_radius"] — the full traversal result
      state["event_log"]    — one timestamped entry
    """
    state["phase"] = Phase.BLAST_RADIUS_QUERY

    start_node = get_start_node(state["alert_raw"], state["ioc_list"])

    if not start_node:
        # No identifiable start node — log and continue
        state["blast_radius"] = {
            "start_node": None,
            "max_hops": MAX_HOPS,
            "reachable_assets": [],
            "reachable_count": 0,
            "error": "No identifiable host or account in alert"
        }
        state["event_log"].append({
            "node": "blast_radius",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail": "No identifiable start node in alert — blast radius skipped",
        })
        return state

    # Execute the Neo4j blast-radius query
    try:
        result = _graph_tool.blast_radius(
            start_node_id=start_node,
            max_hops=MAX_HOPS
        )
        state["blast_radius"] = result

        reachable = result.get("reachable_count", 0)
        assets = [a["id"] for a in result.get("reachable_assets", [])[:5]]

        state["event_log"].append({
            "node": "blast_radius",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail": (
                f"Blast radius from '{start_node}' "
                f"(max {MAX_HOPS} hops): "
                f"{reachable} reachable assets. "
                f"Sample: {assets}"
            ),
        })

    except Exception as e:
        # Neo4j might be down or the node might not exist in the graph
        state["blast_radius"] = {
            "start_node": start_node,
            "max_hops": MAX_HOPS,
            "reachable_assets": [],
            "reachable_count": 0,
            "error": str(e)
        }
        state["event_log"].append({
            "node": "blast_radius",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail": f"Blast radius query failed for '{start_node}': {str(e)[:100]}",
        })

    return state
