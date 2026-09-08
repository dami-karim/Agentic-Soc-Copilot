"""
HIL Checkpoint — Human-In-the-Loop gate for high-impact actions.

Uses LangGraph's interrupt() to pause execution and wait for
analyst approval before continuing.

Following Microsoft's disruption-layer / reasoning-layer pattern:
  "The agent proposes, the human decides, the agent executes
  only what was approved."

And LanG's two-gate pattern (arXiv:2604.05440):
  Gate 1: after classify (before investigation) — for borderline alerts
  Gate 2: after propose_actions (before deploy) — for high-risk actions

High-impact actions that require approval:
  - isolate_host
  - reset_credentials
  - block_network_path
  - remove_persistence
  - disable_account

Low-impact actions that auto-approve:
  - audit_account_usage
  - generate_report
  - collect_forensics

The actual graph-integrated checkpoint functions are in graph.py:
  - hil_classify_checkpoint() — Gate 1, uses interrupt()
  - hil_action_checkpoint() — Gate 2, uses interrupt()

This file provides the shared requires_hil() logic and HIGH_IMPACT_ACTIONS
set that both the graph nodes and the standalone function use.
"""
from datetime import datetime, timezone
from src.state import SOCAgentState, Phase, FinalStatus

# Actions that require analyst approval before execution
HIGH_IMPACT_ACTIONS = {
    "isolate_host",
    "reset_credentials",
    "block_network_path",
    "remove_persistence",
    "disable_account",
}

# Actions that are auto-approved (read-only or low risk)
AUTO_APPROVE_ACTIONS = {
    "audit_account_usage",
    "generate_report",
    "collect_forensics",
}


def requires_hil(action: dict) -> bool:
    """
    Determines if an action requires HIL approval.

    High-impact actions always require approval.
    Medium-impact actions require approval if confidence >= 0.8.
    Low-impact actions are auto-approved.
    """
    action_type = action.get("action_type", "")
    risk_level = action.get("risk_level", "low")
    confidence = action.get("confidence", 0.0)

    if action_type in AUTO_APPROVE_ACTIONS:
        return False
    if action_type in HIGH_IMPACT_ACTIONS:
        return True
    if risk_level == "high":
        return True
    if risk_level == "medium" and confidence >= 0.8:
        return True
    return False


def hil_checkpoint_node(state: SOCAgentState) -> str | None:
    """
    Standalone HIL checkpoint node — pauses execution for analyst approval.

    This is a utility function. The actively used HIL checkpoints are:
      - hil_classify_checkpoint() in graph.py (Gate 1 — borderline alerts)
      - hil_action_checkpoint() in graph.py (Gate 2 — high-risk actions)

    This standalone version uses interrupt() and is kept for backward
    compatibility and for use outside the main graph (e.g. batch processing).
    """
    from langgraph.types import interrupt

    state["phase"] = Phase.AWAITING_ACTION_REVIEW

    proposed = state["proposed_actions"]
    if not proposed:
        state["event_log"].append({
            "node": "hil_checkpoint",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail": "No proposed actions — HIL gate skipped",
        })
        return None

    approved_actions = []
    rejected_actions = []

    high_risk = [a for a in proposed if requires_hil(a)]
    low_risk = [a for a in proposed if not requires_hil(a)]

    if high_risk:
        # Pause for analyst approval via interrupt()
        analyst_decision = interrupt({
            "gate_name": "HIL_Action_Approval",
            "message": f"High-risk actions require analyst approval ({len(high_risk)} action(s)).",
            "high_risk_actions": high_risk,
            "confidence": state.get("rca_report", {}).get("overall_confidence", 0),
        })

        for i, action in enumerate(high_risk):
            decision = analyst_decision.get(f"action_{i}", "rejected")
            action_key = f"{action['action_type']}:{action['target']}"
            notes = analyst_decision.get(f"action_{i}_notes", "")

            if decision == "approved":
                approved_actions.append(action)
            else:
                rejected_actions.append(action)

            state["human_decisions"].append({
                "gate_name": "HIL_Action_Approval",
                "action_type": action["action_type"],
                "target": action["target"],
                "risk_level": action["risk_level"],
                "decision": decision,
                "analyst_note": notes,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    # Merge: low-risk actions are auto-approved, high-risk need explicit approval
    state["proposed_actions"] = low_risk + approved_actions

    state["event_log"].append({
        "node": "hil_checkpoint",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detail": (
            f"HIL gate complete: "
            f"{len(approved_actions)} high-risk approved, "
            f"{len(rejected_actions)} high-risk rejected, "
            f"{len(low_risk)} low-risk auto-approved. "
            f"Audit trail written to human_decisions."
        ),
    })

    return None
