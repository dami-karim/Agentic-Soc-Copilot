"""
Main LangGraph Pipeline — The top-level state machine for alert triage.

This is the "orchestrator" that connects all the nodes into a single
executable pipeline. It defines:
  - The node registry (which functions are available)
  - The edge topology (which nodes connect to which)
  - The conditional routing (benign → early exit, malicious → full pipeline)
  - The entry point

Week 6 UPDATED TOPOLOGY (guardrails + HIL checkpoints integrated):
   ingest → classify → [conditional]
                         ├── score < (threshold - margin) → deploy (COMPLETED_BENIGN)
                         ├── score in borderline range → hil_classify → [interrupt] → investigate OR deploy (ABORTED)
                         └── score >= threshold → investigate (ReAct loop with guardrails)
                                                        → rca_generator
                                                        → propose_actions
                                                        → [conditional: high-risk?] → hil_action → [interrupt] → deploy (COMPLETED)

The "investigate" node is a compiled ReAct sub-graph that dynamically
calls tools (search_logs, query_blast_radius, search_similar_incidents,
search_attack_techniques) with guardrail validation on each tool argument.
The "extract_results" translation is handled inside investigate_node itself.
"""
from langgraph.graph import StateGraph, END
from langgraph.types import interrupt, Command
from src.state import SOCAgentState, Phase, FinalStatus
from src.nodes.ingest import ingest_node
from src.nodes.classify import classify_node, BENIGN_THRESHOLD
from src.nodes.deploy import deploy_node
from src.nodes.rca_generator import rca_generator_node
from src.nodes.propose_actions import propose_actions_node
from src.guardrails.hil_checkpoint import requires_hil
from src.react_graph import build_investigation_agent, parse_investigation_output
from src.guardrails.guardrail_wrapper import check_content
from src.tools.langchain_tools import get_guardrail_log
from datetime import datetime, timezone

# Borderline threshold: alerts within this range of the benign threshold
# trigger the first HIL gate. E.g. if BENIGN_THRESHOLD=30 and BORDERLINE_MARGIN=10,
# alerts scoring 20-29 go through the classification review gate.
BORDERLINE_MARGIN = 5.0


# ──────────────────────────────────────────────────────────────────────────────
# REACT INVESTIGATION AGENT — built once at module load time
# ──────────────────────────────────────────────────────────────────────────────
# We build the investigation agent ONCE when graph.py is imported, not on
# every invocation. The agent is a compiled LangGraph StateGraph that we
# invoke inside the investigate_node.
#
# Why module level? Because building the agent involves:
#   1. Loading the ChatOllama model connection
#   2. Registering the 4 tools (now with guardrail validation)
#   3. Compiling the LangGraph state machine
# Doing this on every alert would add ~2-3 seconds of overhead per investigation.
_investigation_agent = build_investigation_agent()


def route_after_classify(state: SOCAgentState) -> str:
    """
    Conditional edge after classify_node.

    Three routes:
    - score < (BENIGN_THRESHOLD - BORDERLINE_MARGIN) → "deploy" (clearly benign, no HIL)
    - score in borderline range → "hil_classify" (analyst review before investigation)
    - score >= BENIGN_THRESHOLD → "investigate" (full ReAct investigation, read-only so no HIL gate needed)
    """
    score = state["triage_score"]
    borderline_low = BENIGN_THRESHOLD - BORDERLINE_MARGIN

    if score < borderline_low:
        return "deploy"
    elif score < BENIGN_THRESHOLD:
        return "hil_classify"
    else:
        return "investigate"


def route_after_propose_actions(state: SOCAgentState) -> str:
    """
    After proposing actions, check if any are high-risk.
    If so, route to the HIL checkpoint. Otherwise, go straight to deploy.
    """
    proposals = state.get("proposed_actions", [])
    high_risk = [a for a in proposals if requires_hil(a)]
    if high_risk:
        return "hil_action"
    return "deploy"


def investigate_node(state: SOCAgentState) -> SOCAgentState:
    """
    Invokes the ReAct investigation agent on the current alert.

    This node:
      1. Builds a human-readable alert description from state["alert_raw"]
      2. Invokes the ReAct agent (which dynamically calls tools with guardrail validation)
      3. Parses the agent's output to extract structured findings
      4. Post-validates the LLM output via guardrails before writing to state
      5. Collects any guardrail flags from tool calls and writes them to state

    The ReAct agent uses its own internal MessagesState, so this node
    acts as the BRIDGE between the agent's state and the main graph's state.
    """
    state["phase"] = Phase.ANALYZING

    alert = state["alert_raw"]

    # Build the investigation prompt — the human message the agent receives
    investigation_prompt = (
        f"INVESTIGATE THIS ALERT:\n"
        f"Host: {alert.get('host', 'unknown')}\n"
        f"EventCode: {alert.get('EventCode', 'unknown')}\n"
        f"Source IP: {alert.get('src_ip', 'unknown')}\n"
        f"Destination IP: {alert.get('dest_ip', 'unknown')}\n"
        f"User: {alert.get('user', 'unknown')}\n"
        f"Signature: {alert.get('signature', 'unknown')}\n"
        f"Severity: {alert.get('severity', 'unknown')}\n"
        f"Logon Type: {alert.get('Logon_Type', 'unknown')}\n"
        f"\nBegin your investigation. Search logs, identify techniques, "
        f"check blast radius, and find similar past incidents."
    )

    # Invoke the ReAct agent
    try:
        agent_result = _investigation_agent.invoke({
            "messages": [{"role": "user", "content": investigation_prompt}]
        })
    except Exception as e:
        # If the ReAct agent fails (e.g. Ollama not running), fall back
        # to an empty investigation — the pipeline continues with empty data
        state["event_log"].append({
            "node": "investigate",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail": f"ReAct agent failed: {str(e)[:200]}. Continuing with empty investigation.",
        })
        return state

    # Collect guardrail flags from tool calls during the ReAct loop
    tool_guardrail_flags = get_guardrail_log()
    for flag in tool_guardrail_flags:
        state["guardrail_flags"].append(flag)

    # Parse the agent's output messages to extract structured findings
    messages = agent_result.get("messages", [])
    findings = parse_investigation_output(messages)

    # GUARDRAIL: Post-validate the LLM's final output (summary text)
    summary_text = findings.get("summary_text", "")
    if summary_text:
        output_result = check_content(summary_text, node_name="investigate:llm_output")
        if output_result.level != "pass":
            state["guardrail_flags"].append({
                "node": "investigate",
                "check_type": "output",
                "level": output_result.level,
                "reason": output_result.reason,
                "pattern_matched": output_result.pattern_matched,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            if not output_result.passed:
                # If the LLM output is blocked, use a safe fallback summary
                summary_text = (
                    f"Investigation output was blocked by guardrails. "
                    f"Raw alert: EventCode={alert.get('EventCode', 'unknown')} "
                    f"host={alert.get('host', 'unknown')}."
                )
                findings["summary_text"] = summary_text

    # Write findings back into SOCAgentState
    # IoCs — merge agent-extracted IoCs with any we already have
    agent_iocs = findings.get("ioc_list", [])
    if agent_iocs:
        state["ioc_list"] = agent_iocs

    # ATT&CK techniques — use agent's findings if available
    agent_techniques = findings.get("attack_techniques", [])
    if agent_techniques:
        state["attack_techniques"] = agent_techniques

    # Enrichment — merge with existing enrichment data
    state["enrichment"].update(findings.get("enrichment", {}))

    # Blast radius — use agent's findings if available
    agent_blast = findings.get("blast_radius", {})
    if agent_blast and agent_blast.get("reachable_assets"):
        state["blast_radius"] = agent_blast

    # Count guardrail flags from this investigation
    guardrail_count = len([
        f for f in state["guardrail_flags"]
        if f["node"] in ("investigate", "search_logs", "query_blast_radius",
                         "search_similar_incidents", "search_attack_techniques")
    ])

    # Log the investigation summary
    summary = findings.get("summary_text", "No summary produced")
    state["event_log"].append({
        "node": "investigate",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detail": (
            f"ReAct investigation complete: "
            f"{len(state['ioc_list'])} IoCs, "
            f"{len(state['attack_techniques'])} techniques, "
            f"blast_radius={'yes' if state['blast_radius'] else 'no'}. "
            f"Guardrail flags: {guardrail_count}. "
            f"Summary: {summary[:200]}"
        ),
    })

    return state


def hil_classify_checkpoint(state: SOCAgentState) -> str | Command:
    """
    HIL Gate 1 — Classification review for borderline alerts.

    Pauses execution and asks the analyst to confirm whether to proceed
    with full investigation or treat as benign.

    Uses LangGraph's interrupt() to pause the graph and return control
    to the caller, who resumes with a Command(resume=...).
    """
    state["phase"] = Phase.AWAITING_CLASSIFICATION_REVIEW

    score = state["triage_score"]
    alert = state["alert_raw"]

    analyst_decision = interrupt({
        "gate_name": "HIL_1_Classification_Review",
        "message": (
            f"Borderline alert: triage_score={score} "
            f"(threshold={BENIGN_THRESHOLD}, borderline_range="
            f"{BENIGN_THRESHOLD - BORDERLINE_MARGIN:.0f}-{BENIGN_THRESHOLD:.0f}). "
            f"EventCode={alert.get('EventCode', 'unknown')} "
            f"host={alert.get('host', 'unknown')} "
            f"severity={state.get('severity', 'unknown')}"
        ),
        "score": score,
        "triage_score": score,
        "benign_threshold": BENIGN_THRESHOLD,
        "alert": {
            "host": alert.get("host", "unknown"),
            "EventCode": alert.get("EventCode", "unknown"),
            "src_ip": alert.get("src_ip", "unknown"),
            "user": alert.get("user", "unknown"),
            "severity": alert.get("severity", "unknown"),
        },
    })

    # Record the analyst's decision in the audit trail
    state["human_decisions"].append({
        "gate_name": "HIL_1_Classification_Review",
        "decision": analyst_decision.get("decision", "unknown"),
        "analyst_id": analyst_decision.get("analyst_id", "interactive"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "notes": analyst_decision.get("notes", ""),
    })

    if analyst_decision.get("decision") == "approved":
        state["event_log"].append({
            "node": "hil_classify",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail": "Borderline alert APPROVED by analyst — proceeding to investigation.",
        })
        return Command(resume=analyst_decision, goto="investigate")
    else:
        state["final_status"] = FinalStatus.ABORTED
        state["event_log"].append({
            "node": "hil_classify",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail": "Borderline alert REJECTED by analyst — terminated as benign.",
        })
        return Command(resume=analyst_decision, goto="deploy")


def hil_action_checkpoint(state: SOCAgentState) -> str | Command:
    """
    HIL Gate 2 — Action approval for high-risk containment actions.

    Pauses execution and presents high-risk actions to the analyst for approval.
    Uses LangGraph's interrupt() for proper graph pausing.
    """
    state["phase"] = Phase.AWAITING_ACTION_REVIEW

    proposed = state["proposed_actions"]
    if not proposed:
        state["event_log"].append({
            "node": "hil_action",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail": "No proposed actions — HIL gate skipped",
        })
        return state

    high_risk_actions = [a for a in proposed if requires_hil(a)]
    if not high_risk_actions:
        state["event_log"].append({
            "node": "hil_action",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail": "No high-risk actions — HIL gate skipped",
        })
        return state

    # Pause for analyst approval via interrupt()
    analyst_decisions = interrupt({
        "gate_name": "HIL_2_Action_Approval",
        "message": f"High-risk actions require analyst approval ({len(high_risk_actions)} action(s)).",
        "high_risk_actions": high_risk_actions,
        "confidence": state.get("rca_report", {}).get("overall_confidence", 0),
    })

    approved_actions = []
    rejected_actions = []

    # Process the analyst's decisions
    for action in high_risk_actions:
        action_key = f"{action['action_type']}:{action['target']}"
        decision_entry = next(
            (d for d in analyst_decisions.get("decisions", [])
             if d.get("action_key") == action_key),
            None
        )

        if decision_entry and decision_entry.get("decision") == "approved":
            approved_actions.append(action)
        else:
            rejected_actions.append(action)

        # Record in audit trail
        state["human_decisions"].append({
            "gate_name": "HIL_2_Action_Approval",
            "action_type": action["action_type"],
            "target": action["target"],
            "risk_level": action["risk_level"],
            "decision": decision_entry.get("decision", "rejected") if decision_entry else "rejected",
            "analyst_note": decision_entry.get("notes", "") if decision_entry else "",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    # Also keep auto-approved (low-risk) actions
    low_risk_actions = [a for a in proposed if not requires_hil(a)]

    # Update proposed_actions to only include approved + auto-approved
    state["proposed_actions"] = low_risk_actions + approved_actions

    state["event_log"].append({
        "node": "hil_action",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detail": (
            f"HIL gate complete: "
            f"{len(approved_actions)} high-risk approved, "
            f"{len(rejected_actions)} high-risk rejected, "
            f"{len(low_risk_actions)} low-risk auto-approved. "
            f"Audit trail written to human_decisions."
        ),
    })

    return Command(resume=analyst_decisions, goto="deploy")


def build_graph(with_hil: bool = True):
    """
    Assembles the Week 6 LangGraph pipeline with guardrails and HIL checkpoints.

    Topology (with HIL gates):
        ingest → classify → [conditional]
            clearly benign (< threshold - margin) → deploy (COMPLETED_BENIGN)
            borderline → hil_classify → interrupt → investigate OR deploy (ABORTED)
            suspicious (>= threshold) → investigate → rca_generator → propose_actions → [conditional]
                no high-risk → deploy
                high-risk → hil_action → interrupt → deploy

    Topology (without HIL gates, for testing):
        ingest → classify → [conditional]
            benign → deploy (COMPLETED_BENIGN)
            malicious → investigate → rca_generator → propose_actions → deploy (COMPLETED)

    Args:
        with_hil: If True, include HIL checkpoint nodes in the graph.
                  Set to False for automated testing (no interrupt pauses).
    """
    graph = StateGraph(SOCAgentState)

    # Register all nodes
    graph.add_node("ingest", ingest_node)
    graph.add_node("classify", classify_node)
    graph.add_node("investigate", investigate_node)
    graph.add_node("rca_generator", rca_generator_node)
    graph.add_node("propose_actions", propose_actions_node)
    graph.add_node("deploy", deploy_node)

    if with_hil:
        graph.add_node("hil_classify", hil_classify_checkpoint)
        graph.add_node("hil_action", hil_action_checkpoint)

    # Set the entry point
    graph.set_entry_point("ingest")

    # Fixed edge: ingest always goes to classify
    graph.add_edge("ingest", "classify")

    # Conditional edge after classify — the routing decision
    graph.add_conditional_edges(
        "classify",
        route_after_classify,
        {
            "deploy": "deploy",
            "hil_classify": "hil_classify" if with_hil else "investigate",
            "investigate": "investigate",
        }
    )

    # Fixed edges for the malicious investigation path
    graph.add_edge("investigate", "rca_generator")
    graph.add_edge("rca_generator", "propose_actions")

    if with_hil:
        # Conditional edge after propose_actions — check for high-risk actions
        graph.add_conditional_edges(
            "propose_actions",
            route_after_propose_actions,
            {
                "hil_action": "hil_action",
                "deploy": "deploy",
            }
        )
        # After HIL action gate, always go to deploy
        graph.add_edge("hil_action", "deploy")
        # After HIL classify gate, the node returns a Command with goto
    else:
        # Without HIL, propose_actions goes directly to deploy
        graph.add_edge("propose_actions", "deploy")

    # Terminal edge
    graph.add_edge("deploy", END)

    return graph.compile()


# ──────────────────────────────────────────────────────────────────────────────
# SMOKE TEST — Run this file directly to test the full pipeline
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    from src.nodes.ingest import make_initial_input

    app = build_graph(with_hil=False)

    # Test alert — brute force pattern (same as before)
    test_alert = {
        "host": "WIN-DC01",
        "EventCode": "4625",
        "src_ip": "10.0.2.15",
        "dest_ip": "10.0.2.5",
        "user": "administrator",
        "Logon_Type": "3",
        "sourcetype": "WinEventLog:Security",
        "signature": "An account failed to log on",
        "severity": "medium",
    }

    print("=" * 60)
    print("AGENTIC SOC CO-PILOT — Week 6 Pipeline (HIL disabled for smoke test)")
    print("=" * 60)
    print(f"Alert: EventCode={test_alert['EventCode']} "
          f"host={test_alert['host']} user={test_alert['user']}")
    print()

    initial_state = make_initial_input(test_alert)
    result = app.invoke(initial_state)

    print(f"Final status:    {result['final_status']}")
    print(f"Triage score:    {result['triage_score']}")
    print(f"Severity:        {result['severity']}")
    print(f"IoCs found:      {len(result['ioc_list'])}")
    print(f"ATT&CK tags:     {[t['technique_id'] for t in result['attack_techniques']]}")
    print(f"Blast radius:    {bool(result['blast_radius'])}")
    print(f"Proposed actions: {len(result['proposed_actions'])}")
    print(f"Guardrail flags:  {len(result['guardrail_flags'])}")
    print(f"HIL decisions:    {len(result['human_decisions'])}")
    print()

    # Print the structured RCA report
    if result["rca_report"]:
        print("─" * 60)
        print("ROOT-CAUSE ANALYSIS REPORT")
        print("─" * 60)
        rca = result["rca_report"]
        print(f"Summary: {rca.get('summary', 'N/A')}")
        print(f"Overall confidence: {rca.get('overall_confidence', 0):.0%}")
        print(f"Containment actions: {rca.get('containment_actions', [])}")
        print()

    # Print proposed actions
    if result["proposed_actions"]:
        print("─" * 60)
        print("PROPOSED CONTAINMENT ACTIONS")
        print("─" * 60)
        for action in result["proposed_actions"]:
            risk = action.get("risk_level", "unknown")
            print(f"  [{risk.upper()}] {action['action_type']}: "
                  f"{action.get('justification', '')}")
        print()

    # Print investigation event log
    print("─" * 60)
    print("INVESTIGATION EVENT LOG")
    print("─" * 60)
    for event in result["event_log"]:
        print(f"  [{event['node']}] {event['detail'][:120]}")
    print()

    # Print guardrail flags
    if result["guardrail_flags"]:
        print("─" * 60)
        print("GUARDRAIL FLAGS")
        print("─" * 60)
        for flag in result["guardrail_flags"]:
            print(f"  [{flag.get('level', 'unknown')}] {flag.get('node', '?')}: {flag.get('reason', '?')}")
        print()
