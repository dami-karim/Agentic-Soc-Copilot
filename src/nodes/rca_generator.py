"""
RCA Generator Node — Produces a structured Root-Cause Analysis report.

This node runs AFTER the ReAct investigation loop has completed.
It takes all the evidence the agent gathered (IoCs, ATT&CK techniques,
enrichment data, blast radius) and assembles it into a structured RCA
report following the OCR-APT pattern: extract → narrate → merge.

The RCA is deterministic (no LLM call) — it synthesizes the investigation
findings into a fixed schema. This keeps Week 3 fast and testable.
"""
from datetime import datetime, timezone
from src.state import SOCAgentState, Phase


# Maps ATT&CK tactic prefixes to containment action templates.
# When a technique like T1110.001 (Password Spraying) is tagged,
# we look up T1110 → "Credential Access" → the corresponding actions.
TACTIC_CONTAINMENT = {
    "T11": "Reset compromised credentials and enforce MFA on affected accounts.",
    "T10": "Isolate the affected host from the network and run a full EDR scan.",
    "T107": "Revoke and rotate any stolen or exposed credentials.",
    "T102": "Block lateral movement paths (SMB/RDP) at the network level.",
    "T105": "Remove malicious scheduled tasks/processes and audit persistence mechanisms.",
    "T103": "Monitor for further discovery activity and restrict account privileges.",
    "T104": "Review and restrict network firewall rules for the affected segment.",
    "T156": "Audit and restrict permissions on sensitive data stores.",
}


def compute_overall_confidence(techniques: list[dict]) -> float:
    """
    Compute a single overall confidence score for the RCA from
    individual ATT&CK technique confidences.

    Strategy: weighted average weighted by the technique's relevance score.
    Higher-scored techniques (more relevant to the alert) contribute more
    to the overall confidence. Falls back to a simple average if all scores
    are zero.
    """
    if not techniques:
        return 0.0

    total_weight = sum(t.get("confidence", 0.5) for t in techniques)
    if total_weight == 0:
        return 0.0

    weighted_sum = sum(
        t.get("confidence", 0.5) * t.get("confidence", 0.5)
        for t in techniques
    )
    return round(weighted_sum / total_weight, 2)


def build_timeline(event_log: list[dict]) -> list[dict]:
    """
    Extract the investigation timeline from the event log.
    Each entry becomes a {timestamp, node, action} record that shows
    the step-by-step progression of the investigation.
    """
    timeline = []
    for entry in event_log:
        timeline.append({
            "timestamp": entry.get("timestamp", ""),
            "node": entry.get("node", "unknown"),
            "action": entry.get("detail", ""),
        })
    return timeline


def identify_root_cause(alert: dict, techniques: list[dict],
                        iocs: list[dict]) -> str:
    """
    Build a human-readable root-cause summary from the investigation
    findings.

    This is the "narrative" part of the RCA, following OCR-APT's
    decomposed report-generation pattern: each finding is narrated
    individually, then merged into a single coherent story.
    """
    host = alert.get("host", "unknown host")
    user = alert.get("user", "unknown user")
    event_code = alert.get("EventCode", "unknown")
    src_ip = alert.get("src_ip", "unknown")
    severity = alert.get("severity", "unknown")

    # Identify the primary technique (highest confidence)
    primary_technique = techniques[0] if techniques else None
    primary_name = primary_technique["technique_name"] if primary_technique else "Unknown"
    primary_id = primary_technique["technique_id"] if primary_technique else "T????"

    # Build IoC summary
    ioc_summary = ", ".join(
        f"{ioc['type']}:{ioc['value']}" for ioc in iocs[:5]
    ) if iocs else "none identified"

    # Build the narrative
    summary = (
        f"Alert EventCode {event_code} on {host} involving account "
        f"'{user}' from source IP {src_ip} (severity: {severity}). "
        f"Investigation identified primary technique: {primary_id} "
        f"({primary_name}). "
        f"IoCs found: [{ioc_summary}]. "
        f"Overall confidence: {compute_overall_confidence(techniques):.0%}."
    )
    return summary


def identify_containment_actions(techniques: list[dict]) -> list[str]:
    """
    Map ATT&CK techniques to specific containment actions.

    Each technique is matched to its parent tactic prefix (e.g. T1110 → T11
    → "Credential Access") and the corresponding containment template is
    returned. Deduplicates so the same action isn't listed twice.
    """
    actions = []
    seen = set()

    for technique in techniques:
        tech_id = technique.get("technique_id", "T????")
        # Match the technique ID prefix to a tactic category
        for prefix, action in TACTIC_CONTAINMENT.items():
            if tech_id.startswith(prefix) and action not in seen:
                actions.append(action)
                seen.add(action)
                break

    # Always include a general recommendation
    general = "Conduct full incident review and update detection rules as needed."
    if general not in seen:
        actions.append(general)

    return actions


def rca_generator_node(state: SOCAgentState) -> SOCAgentState:
    """
    Main RCA generation node.

    Reads from state:
      - alert_raw, triage_score, severity
      - ioc_list (populated by the ReAct investigation)
      - attack_techniques (populated by the ReAct investigation)
      - enrichment (populated by the ReAct investigation)
      - blast_radius (populated by the ReAct investigation)
      - event_log (for timeline)

    Writes to state:
      - rca_report (structured RCA dict)
      - phase → Phase.COMPLETED
      - event_log (appends RCA generation event)
    """
    # NOTE: We do NOT set phase to COMPLETED here.
    # That happens in deploy_node (the terminal node).
    # The RCA generator just produces the report; deploy is what wraps up.
    state["phase"] = Phase.PROPOSING_ACTIONS

    alert = state["alert_raw"]
    techniques = state["attack_techniques"]
    iocs = state["ioc_list"]

    # Build the structured RCA report
    state["rca_report"] = {
        "alert_id": state["alert_id"],
        "workflow_id": state["workflow_id"],
        "summary": identify_root_cause(alert, techniques, iocs),
        "triage_score": state["triage_score"],
        "severity": state["severity"],
        "attack_techniques": [
            {
                "technique_id": t["technique_id"],
                "technique_name": t["technique_name"],
                "confidence": t.get("confidence", 0.0),
                "rationale": t.get("rationale", ""),
            }
            for t in techniques
        ],
        "ioc_summary": [
            {
                "type": ioc["type"],
                "value": ioc["value"],
                "confidence": ioc["confidence"],
                "source": ioc["source"],
            }
            for ioc in iocs
        ],
        "enrichment": state.get("enrichment", {}),
        "blast_radius": state.get("blast_radius", {}),
        "overall_confidence": compute_overall_confidence(techniques),
        "containment_actions": identify_containment_actions(techniques),
        "timeline": build_timeline(state["event_log"]),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    state["event_log"].append({
        "node": "rca_generator",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detail": (
            f"RCA generated: {len(techniques)} techniques, "
            f"{len(iocs)} IoCs, "
            f"confidence={state['rca_report']['overall_confidence']:.0%}, "
            f"{len(state['rca_report']['containment_actions'])} containment actions"
        ),
    })
    return state


# ──────────────────────────────────────────────────────────────────────────────
# WHAT WAS DONE HERE — Teaching Notes
# ──────────────────────────────────────────────────────────────────────────────
#
# WHY AN RCA GENERATOR NODE?
# ──────────────────────────
# The document's Week 3 deliverable requires: "end-to-end triage on simple
# alerts with ATT&CK tagging." But the FULL deliverable (visible in the state
# schema and Week 5 spec) is a STRUCTURED root-cause analysis with:
#   - A human-readable summary of what happened
#   - ATT&CK technique breakdown with confidence scores
#   - IoC list with context
#   - Investigation timeline
#   - Overall confidence score
#   - Recommended containment actions
#
# This node produces that structured RCA from the evidence the ReAct
# investigation gathered. It runs AFTER the investigation loop, not inside it.
#
# WHY DETERMINISTIC (NO LLM)?
# ────────────────────────────
# For Week 3, we keep this deterministic — it's a function that takes
# the investigation results and assembles them into a fixed schema.
# This has three advantages:
#   1. Fast — no additional LLM inference needed
#   2. Testable — the same inputs always produce the same output
#   3. Reliable — no hallucinated RCA content
#
# In Week 5 (per the document), this could be upgraded to use an LLM
# for narrative generation following OCR-APT's pattern: extract → narrate
# per-finding → merge → final LLM enrichment pass.
#
# HOW THE CONTAINMENT ACTIONS WORK:
# ─────────────────────────────────
# The TACTIC_CONTAINMENT dictionary maps ATT&CK technique ID prefixes
# to containment action templates:
#   - T11xx → Credential Access → "Reset credentials, enforce MFA"
#   - T10xx (most) → Execution/Lateral Movement → "Isolate host, EDR scan"
#   - T105x → Persistence → "Remove scheduled tasks, audit persistence"
#
# When a technique like T1110.001 (Password Spraying) is tagged, the
# function matches T1110 → prefix "T11" → Credential Access action.
# Deduplication ensures the same action isn't listed twice even if
# multiple techniques map to the same tactic.
#
# HOW CONFIDENCE IS COMPUTED:
# ───────────────────────────
# The overall confidence is a weighted average of individual technique
# confidences, weighted by the technique's own confidence. This means
# high-confidence technique tags contribute more to the overall score
# than low-confidence ones. This is a simple but effective heuristic —
# in Week 7's evaluation, this score can be calibrated against ground
# truth to check whether it's well-calibrated.
#
# HOW THE SUMMARY IS BUILT:
# ─────────────────────────
# Following OCR-APT's decomposed pattern:
#   1. Identify the PRIMARY technique (highest confidence)
#   2. List all IoCs found
#   3. Combine into a single narrative sentence
# This is a mechanical, deterministic version of what OCR-APT's LLM
# does in its "per-subgraph narration" stage.
#
# ──────────────────────────────────────────────────────────────────────────────
