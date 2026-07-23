"""
Main LangGraph Pipeline — The top-level state machine for alert triage.

This is the "orchestrator" that connects all the nodes into a single
executable pipeline. It defines:
  - The node registry (which functions are available)
  - The edge topology (which nodes connect to which)
  - The conditional routing (benign → early exit, malicious → full pipeline)
  - The entry point

NEW TOPOLOGY (Week 3 — ReAct upgrade):
  ingest → classify → [conditional]
    ├─ benign (< 30) → deploy (COMPLETED_BENIGN)
    └─ malicious (≥ 30) → investigate (ReAct loop)
                           → extract_results (state bridge)
                           → rca_generator (structured RCA)
                           → propose_actions (containment proposals)
                           → deploy (COMPLETED)

The "investigate" node is a compiled ReAct sub-graph that dynamically
calls tools (log search, blast radius, similar incidents, ATT&CK mapping).
The "extract_results" node translates the ReAct agent's output back into
the main SOCAgentState.
"""
from langgraph.graph import StateGraph, END
from src.state import SOCAgentState, Phase
from src.nodes.ingest import ingest_node
from src.nodes.classify import classify_node
from src.nodes.deploy import deploy_node
from src.nodes.rca_generator import rca_generator_node
from src.nodes.propose_actions import propose_actions_node
from src.react_graph import build_investigation_agent, parse_investigation_output
from datetime import datetime, timezone

BENIGN_THRESHOLD = 30.0


def route_after_classify(state: SOCAgentState) -> str:
    """
    Conditional edge after classify_node.
    Routes benign alerts directly to deploy (terminate early).
    Routes suspicious alerts through the full ReAct investigation pipeline.
    """
    if state["triage_score"] < BENIGN_THRESHOLD:
        return "deploy"
    return "investigate"


# ──────────────────────────────────────────────────────────────────────────────
# REACT INVESTIGATION AGENT — built once at module load time
# ──────────────────────────────────────────────────────────────────────────────
# We build the investigation agent ONCE when graph.py is imported, not on
# every invocation. The agent is a compiled LangGraph StateGraph that we
# invoke inside the investigate_node.
#
# Why module level? Because building the agent involves:
#   1. Loading the ChatOllama model connection
#   2. Registering the 4 tools
#   3. Compiling the LangGraph state machine
# Doing this on every alert would add ~2-3 seconds of overhead per investigation.
_investigation_agent = build_investigation_agent()


def investigate_node(state: SOCAgentState) -> SOCAgentState:
    """
    Invokes the ReAct investigation agent on the current alert.

    This node:
      1. Builds a human-readable alert description from state["alert_raw"]
      2. Invokes the ReAct agent (which dynamically calls tools)
      3. Parses the agent's output to extract structured findings
      4. Writes the findings back into SOCAgentState

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
    # The agent returns a dict with "messages" (the full conversation)
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

    # Parse the agent's output messages to extract structured findings
    messages = agent_result.get("messages", [])
    findings = parse_investigation_output(messages)

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
            f"Summary: {summary[:200]}"
        ),
    })

    return state


def build_graph():
    """
    Assembles the Week 3 LangGraph pipeline with ReAct investigation.

    Topology:
        ingest → classify → [conditional]
            benign  → deploy (COMPLETED_BENIGN)
            malicious → investigate → rca_generator → propose_actions → deploy (COMPLETED)

    The "investigate" node wraps a compiled ReAct sub-graph that
    dynamically calls tools. The "extract_results" translation is
    handled inside investigate_node itself (see above).
    """
    graph = StateGraph(SOCAgentState)

    # Register all nodes
    graph.add_node("ingest", ingest_node)
    graph.add_node("classify", classify_node)
    graph.add_node("investigate", investigate_node)
    graph.add_node("rca_generator", rca_generator_node)
    graph.add_node("propose_actions", propose_actions_node)
    graph.add_node("deploy", deploy_node)

    # Set the entry point
    graph.set_entry_point("ingest")

    # Fixed edge: ingest always goes to classify
    graph.add_edge("ingest", "classify")

    # Conditional edge after classify — the routing decision
    graph.add_conditional_edges(
        "classify",
        route_after_classify,
        {
            "deploy": "deploy",              # Benign → early exit
            "investigate": "investigate",    # Suspicious → full pipeline
        }
    )

    # Fixed edges for the malicious investigation path
    graph.add_edge("investigate", "rca_generator")
    graph.add_edge("rca_generator", "propose_actions")
    graph.add_edge("propose_actions", "deploy")

    # Terminal edge
    graph.add_edge("deploy", END)

    return graph.compile()


# ──────────────────────────────────────────────────────────────────────────────
# SMOKE TEST — Run this file directly to test the full pipeline
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    from src.nodes.ingest import make_initial_input

    app = build_graph()

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
    print("AGENTIC SOC CO-PILOT — Week 3 ReAct Pipeline")
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


# ──────────────────────────────────────────────────────────────────────────────
# WHAT WAS DONE HERE — Teaching Notes
# ──────────────────────────────────────────────────────────────────────────────
#
# THIS FILE WAS COMPLETELY REWRITTEN for Week 3's ReAct upgrade.
# Here's what changed and why:
#
# ──────────────────────────────────────────────────────────────────────────────
# BEFORE (original graph.py):
# ────────────────────────────
#   ingest → classify → [conditional]
#       benign → deploy
#       malicious → analyze_logs → attack_tagger → deploy
#
#   This was a FIXED pipeline — every alert went through the same steps
#   in the same order. No LLM reasoning, no dynamic tool selection.
#
# ──────────────────────────────────────────────────────────────────────────────
# AFTER (new graph.py):
# ──────────────────────
#   ingest → classify → [conditional]
#       benign → deploy
#       malicious → investigate (ReAct) → rca_generator → propose_actions → deploy
#
#   The "investigate" node wraps a ReAct agent that dynamically decides
#   which tools to call. The RCA generator and propose_actions nodes
#   produce structured output from the investigation findings.
#
# ──────────────────────────────────────────────────────────────────────────────
# NEW NODES:
# ───────────
# 1. investigate_node — wraps the ReAct agent from react_graph.py
#    - Builds an alert description prompt
#    - Invokes the ReAct agent (which calls tools dynamically)
#    - Parses the agent's output to extract IoCs, techniques, etc.
#    - Writes findings back into SOCAgentState
#
# 2. rca_generator_node — from rca_generator.py
#    - Takes all investigation findings
#    - Produces a structured RCA report with:
#      - summary (human-readable narrative)
#      - attack_techniques (with confidence scores)
#      - ioc_summary (with context)
#      - overall_confidence (weighted average)
#      - containment_actions (mapped from ATT&CK techniques)
#      - timeline (from event_log)
#
# 3. propose_actions_node — from propose_actions_node.py
#    - Takes the ATT&CK techniques and blast radius
#    - Produces specific containment proposals:
#      - reset_credentials, isolate_host, block_network_path, etc.
#    - Each proposal has a risk_level (low/medium/high)
#    - high-risk actions will require HIL gate in Week 6
#
# ──────────────────────────────────────────────────────────────────────────────
# HOW THE STATE BRIDGE WORKS:
# ───────────────────────────
# The ReAct agent uses its own MessagesState (key = "messages").
# The main graph uses SOCAgentState (key = all the custom fields).
#
# The investigate_node bridges these two:
#   1. Extracts alert data from SOCAgentState
#   2. Builds a prompt and invokes the ReAct agent
#   3. Parses the agent's messages to extract structured findings
#   4. Writes findings back into SOCAgentState fields:
#      - ioc_list ← from log search results
#      - attack_techniques ← from ATT&CK corpus results
#      - enrichment ← from all tool results
#      - blast_radius ← from Neo4j query results
#
# This pattern (sub-graph with state translation) is the standard way
# to integrate LangGraph's prebuilt agents into custom pipelines.
#
# ──────────────────────────────────────────────────────────────────────────────
# WHY THE BENIGN THRESHOLD IS STILL 30.0:
# ────────────────────────────────────────
# The classify node hasn't changed — it still uses the same rule-based
# scoring (severity + EventCode boost). Alerts below 30 are routed
# directly to deploy (benign path), skipping the expensive ReAct loop.
#
# This is intentional for Week 3: the ReAct agent uses an LLM which
# costs compute time. We don't want to waste LLM calls on obviously
# benign alerts. In Week 4+, the classify node could be upgraded to
# use an LLM for more nuanced severity assessment.
#
# ──────────────────────────────────────────────────────────────────────────────
# WHY THE OLD analyze_logs.py AND attack_tagger.py STILL EXIST:
# ─────────────────────────────────────────────────────────────
# They're NOT deleted — they still contain useful functions:
#   - analyze_logs.py: extract_iocs() — could be used as a fallback
#   - attack_tagger.py: build_rationale() — still used for formatting
#
# But they're no longer called from the main graph. The ReAct agent
# replaces their functionality with dynamic tool calls. They remain
# as reference code and potential fallback implementations.
#
# ──────────────────────────────────────────────────────────────────────────────
# HOW TO RUN THE SMOKE TEST:
# ──────────────────────────
# 1. Make sure Ollama is running: docker compose up ollama
# 2. Make sure the model is pulled: docker exec soc-ollama ollama pull llama3.2:3b
# 3. Run: python -m src.graph
#
# The test will:
#   - Ingest a brute-force test alert
#   - Classify it as suspicious (score=60 ≥ threshold 30)
#   - Run the ReAct investigation agent
#   - Generate an RCA report
#   - Propose containment actions
#   - Print the full results
#
# If Ollama is not running, the investigate_node catches the exception
# and continues with empty investigation data — you'll still see the
# pipeline structure work, just without LLM-generated findings.
#
# ──────────────────────────────────────────────────────────────────────────────
