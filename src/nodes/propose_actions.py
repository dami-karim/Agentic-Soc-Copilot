"""
Propose Actions Node — Generates containment action proposals for analyst review.

This node runs AFTER the RCA generator. It takes the structured RCA report
and produces a list of specific, actionable containment proposals that an
analyst can approve or reject via a human-in-the-loop gate.

In Week 3, these are ONLY proposals — nothing is executed automatically.
The HIL gate (Week 6) will enforce mandatory analyst approval before any
destructive action is taken, following Microsoft's disruption-layer pattern.
"""
from datetime import datetime, timezone
from src.state import SOCAgentState, Phase


# Maps ATT&CK technique IDs to specific, actionable containment proposals.
# Each proposal has:
#   - action_type: category of the action (isolate, reset, block, remove, monitor)
#   - target: what the action acts on
#   - justification: why this action is recommended, referencing the technique
#   - risk_level: how destructive the action is (low/medium/high)
#     → high-risk actions trigger the HIL gate in Week 6
TECHNIQUE_ACTIONS = {
    "T1110": {
        "action_type": "reset_credentials",
        "target": "compromised_account",
        "justification": "Brute force / password spray detected — credentials may be compromised.",
        "risk_level": "medium",
    },
    "T1078": {
        "action_type": "revoke_sessions",
        "target": "compromised_account",
        "justification": "Valid account misuse detected — active sessions should be terminated.",
        "risk_level": "medium",
    },
    "T1059": {
        "action_type": "isolate_host",
        "target": "affected_host",
        "justification": "Command-line / script execution detected — host may be compromised.",
        "risk_level": "high",
    },
    "T1053": {
        "action_type": "remove_persistence",
        "target": "scheduled_tasks",
        "justification": "Scheduled task created — likely persistence mechanism.",
        "risk_level": "medium",
    },
    "T1021": {
        "action_type": "block_network_path",
        "target": "lateral_movement_path",
        "justification": "Lateral movement detected — block SMB/RDP between affected segments.",
        "risk_level": "high",
    },
    "T1003": {
        "action_type": "isolate_host",
        "target": "affected_host",
        "justification": "Credential dumping detected — host must be isolated immediately.",
        "risk_level": "high",
    },
    "T1046": {
        "action_type": "block_network_path",
        "target": "external_connection",
        "justification": "Network service scan detected — block suspicious outbound connections.",
        "risk_level": "medium",
    },
    "T1566": {
        "action_type": "block_network_path",
        "target": "email_attachment",
        "justification": "Phishing email delivered — block sender domain and quarantine attachment.",
        "risk_level": "medium",
    },
}

# Default actions that are ALWAYS recommended regardless of technique
DEFAULT_ACTIONS = [
    {
        "action_type": "full_edr_scan",
        "target": "affected_host",
        "justification": "Standard procedure after any confirmed or suspected compromise.",
        "risk_level": "low",
    },
    {
        "action_type": "update_detection_rules",
        "target": "siem",
        "justification": "Ensure detection rules cover the observed attack pattern.",
        "risk_level": "low",
    },
]


def extract_technique_prefix(tech_id: str) -> str:
    """
    Extract the base technique prefix from a technique ID.

    Examples:
        "T1110" → "T1110"
        "T1110.001" → "T1110"
        "T1059.001" → "T1059"
        "T???? " → "T????"

    The prefix is used to look up the corresponding containment action
    in the TECHNIQUE_ACTIONS dictionary.
    """
    # Remove any sub-technique suffix (e.g. ".001")
    base = tech_id.split(".")[0]
    return base


def build_action_proposals(techniques: list[dict], blast_radius: dict,
                           alert: dict) -> list[dict]:
    """
    Build a list of specific, actionable containment proposals from
    the ATT&CK techniques and blast-radius information.

    Each proposal includes:
      - action_type: what to do
      - target: what to do it to
      - justification: why (references the specific technique)
      - risk_level: low/medium/high (determines if HIL gate is needed)
      - technique_id: which technique triggered this proposal
      - blast_radius_context: affected assets if applicable
    """
    proposals = []
    seen_actions = set()

    # Map each ATT&CK technique to a specific containment action
    for technique in techniques:
        tech_id = technique.get("technique_id", "T????")
        prefix = extract_technique_prefix(tech_id)

        if prefix in TECHNIQUE_ACTIONS:
            action = TECHNIQUE_ACTIONS[prefix].copy()
            action["technique_id"] = tech_id
            action["technique_name"] = technique.get("technique_name", "Unknown")

            # Add blast-radius context if available
            reachable = blast_radius.get("reachable_assets", [])
            if reachable:
                action["blast_radius_context"] = (
                    f"Attacker can reach {len(reachable)} additional "
                    f"assets from compromised host within "
                    f"{blast_radius.get('max_hops', 3)} hops."
                )

            # Deduplicate — don't propose the same action twice
            action_key = f"{action['action_type']}:{action['target']}"
            if action_key not in seen_actions:
                proposals.append(action)
                seen_actions.add(action_key)

    # Always add the default low-risk actions
    for default in DEFAULT_ACTIONS:
        action_key = f"{default['action_type']}:{default['target']}"
        if action_key not in seen_actions:
            proposals.append(default.copy())
            seen_actions.add(action_key)

    return proposals


def propose_actions_node(state: SOCAgentState) -> SOCAgentState:
    """
    Main action-proposal node.

    Reads from state:
      - alert_raw (for context)
      - attack_techniques (from the ReAct investigation)
      - blast_radius (from the ReAct investigation)
      - rca_report (from the RCA generator)

    Writes to state:
      - proposed_actions (list of action proposals)
      - phase → Phase.PROPOSING_ACTIONS
      - event_log (appends proposal event)
    """
    state["phase"] = Phase.PROPOSING_ACTIONS

    techniques = state["attack_techniques"]
    blast_radius = state.get("blast_radius", {})
    alert = state["alert_raw"]

    # Build the proposals
    proposals = build_action_proposals(techniques, blast_radius, alert)
    state["proposed_actions"] = proposals

    # Count high-risk actions (these will require HIL gate in Week 6)
    high_risk = [p for p in proposals if p.get("risk_level") == "high"]

    state["event_log"].append({
        "node": "propose_actions",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detail": (
            f"Proposed {len(proposals)} actions "
            f"({len(high_risk)} high-risk requiring analyst approval): "
            f"{[p['action_type'] for p in proposals]}"
        ),
    })
    return state


# ──────────────────────────────────────────────────────────────────────────────
# WHAT WAS DONE HERE — Teaching Notes
# ──────────────────────────────────────────────────────────────────────────────
#
# WHY A SEPARATE "PROPOSE ACTIONS" NODE?
# ──────────────────────────────────────
# The document defines a specific pipeline phase called "Proposing Actions"
# (see state_schema.md: Phase.PROPOSING_ACTIONS). This is SEPARATE from the
# RCA generator because:
#
#   1. The RCA says "what happened and why" (diagnosis)
#   2. The actions say "what to do about it" (response)
#
# In a real SOC, these are often done by different people:
#   - A Tier-1 analyst does the triage and writes the RCA
#   - A Tier-2 analyst or incident commander decides the response
#
# By separating them, we can later add a human-in-the-loop gate BETWEEN
# the RCA and the actions, which is exactly what LanG's architecture does
# (Human Review gate between "Propose Rules" and "Deploy").
#
# HOW THE ACTION MAPPING WORKS:
# ────────────────────────────
# The TECHNIQUE_ACTIONS dictionary maps ATT&CK technique prefixes to
# specific containment actions. For example:
#
#   T1110 (Brute Force) → reset_credentials on compromised_account
#   T1059 (Command Execution) → isolate_host the affected_host
#   T1021 (Lateral Movement) → block_network_path between segments
#
# When the investigation tags technique T1110.001 (Password Spraying),
# we:
#   1. Extract the prefix: "T1110.001" → "T1110"
#   2. Look up TECHNIQUE_ACTIONS["T1110"]
#   3. Create a proposal with action_type="reset_credentials"
#
# The sub-technique suffix (.001) is stripped because the containment
# action is the same for all variants of brute force.
#
# WHAT "RISK_LEVEL" MEANS:
# ────────────────────────
# Each action has a risk_level: low, medium, or high.
#   - low:    Won't disrupt operations (EDR scan, rule update)
#   - medium: May disrupt a user's session (credential reset, session revoke)
#   - high:   Will disrupt network connectivity or host availability
#              (host isolation, network path blocking)
#
# In Week 6 (guardrails + HIL), the rule is:
#   - low-risk actions → can be auto-executed (no analyst approval needed)
#   - medium/high-risk actions → MUST go through HIL gate first
#
# This follows Microsoft's "disruption layer vs reasoning layer" split:
#   - Disruption layer = deterministic, policy-bound, auto-executes
#   - Reasoning layer = agentic, requires human approval for destructive ops
#
# WHY BLAST RADIUS IS INCLUDED:
# ────────────────────────────
# The blast_radius from Neo4j tells us how many other assets the attacker
# can reach. This context is included in the proposal justification so the
# analyst understands the urgency. For example:
#   "Attacker can reach 5 additional assets from compromised host within
#    3 hops" → this makes host isolation MORE urgent than if the attacker
#    is contained to a single machine.
#
# WHY WE ALWAYS ADD DEFAULT ACTIONS:
# ──────────────────────────────────
# Even if no specific technique is matched, we always recommend:
#   1. Full EDR scan (standard procedure after any compromise)
#   2. Update detection rules (ensure future alerts catch this pattern)
#
# These are "defense in depth" recommendations that apply to ANY incident,
# regardless of the specific ATT&CK technique.
#
# ──────────────────────────────────────────────────────────────────────────────
