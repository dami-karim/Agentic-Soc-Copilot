from datetime import datetime, timezone
from src.state import SOCAgentState, Phase, FinalStatus


def deploy_node(state: SOCAgentState) -> SOCAgentState:
    """
    Terminal node. Sets final status based on triage score.
    Does NOT execute any real actions in Week 3.
    """
    if state["triage_score"] < 30.0:
        state["final_status"] = FinalStatus.COMPLETED_BENIGN
        detail = f"Alert classified as BENIGN (score={state['triage_score']}). No action taken."
    else:
        state["final_status"] = FinalStatus.COMPLETED
        techniques = [t["technique_id"] for t in state["attack_techniques"]]
        detail = (
            f"Investigation COMPLETE (score={state['triage_score']}). "
            f"ATT&CK tags: {techniques}. "
            f"Awaiting analyst review — no destructive action executed."
        )

    state["phase"] = Phase.COMPLETED

    state["event_log"].append({
        "node": "deploy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detail": detail,
    })
    return state
