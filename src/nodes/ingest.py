import uuid
from datetime import datetime, timezone
from src.state import SOCAgentState, Phase, new_state


def make_initial_input(alert_raw: dict) -> SOCAgentState:
    """
    Factory called before invoking the graph.
    Creates the initial state from a raw SIEM alert.
    """
    workflow_id = str(uuid.uuid4())
    alert_id = alert_raw.get("alert_id", str(uuid.uuid4()))
    return new_state(
        alert_raw=alert_raw,
        workflow_id=workflow_id,
        alert_id=alert_id,
    )


def ingest_node(state: SOCAgentState) -> SOCAgentState:
    """
    Entry node. Sets phase to INGESTING and logs the start event.
    Does not modify alert_raw — preserves original evidence.
    """
    state["phase"] = Phase.INGESTING
    state["event_log"].append({
        "node": "ingest",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detail": f"Alert {state['alert_id']} received from host "
                  f"{state['alert_raw'].get('host', 'unknown')} "
                  f"EventCode={state['alert_raw'].get('EventCode', 'unknown')}",
    })
    return state
