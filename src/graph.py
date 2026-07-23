from langgraph.graph import StateGraph, END
from src.state import SOCAgentState
from src.nodes.ingest import ingest_node
from src.nodes.classify import classify_node
from src.nodes.analyze_logs import analyze_logs_node
from src.nodes.attack_tagger import attack_tagger_node
from src.nodes.deploy import deploy_node

BENIGN_THRESHOLD = 30.0


def route_after_classify(state: SOCAgentState) -> str:
    """
    Conditional edge after classify_node.
    Routes benign alerts directly to deploy (terminate early).
    Routes suspicious alerts through the full investigation pipeline.
    """
    if state["triage_score"] < BENIGN_THRESHOLD:
        return "deploy"
    return "analyze_logs"


def build_graph():
    """
    Assembles the Week 3 LangGraph pipeline.
    
    Topology:
    ingest → classify → [conditional]
        benign  → deploy (COMPLETED_BENIGN)
        malicious → analyze_logs → attack_tagger → deploy (COMPLETED)
    """
    graph = StateGraph(SOCAgentState)

    # Register all nodes
    graph.add_node("ingest", ingest_node)
    graph.add_node("classify", classify_node)
    graph.add_node("analyze_logs", analyze_logs_node)
    graph.add_node("attack_tagger", attack_tagger_node)
    graph.add_node("deploy", deploy_node)

    # Set the entry point
    graph.set_entry_point("ingest")

    # Fixed edges
    graph.add_edge("ingest", "classify")

    # Conditional edge — the routing decision
    graph.add_conditional_edges(
        "classify",
        route_after_classify,
        {
            "deploy": "deploy",
            "analyze_logs": "analyze_logs",
        }
    )

    # Fixed edges for the malicious path
    graph.add_edge("analyze_logs", "attack_tagger")
    graph.add_edge("attack_tagger", "deploy")

    # Terminal edge
    graph.add_edge("deploy", END)

    return graph.compile()


# Allow running this file directly for a quick smoke test
if __name__ == "__main__":
    import json
    from src.nodes.ingest import make_initial_input

    app = build_graph()

    # Test alert — brute force pattern
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

    print("Running end-to-end triage on test alert...")
    print(f"Alert: EventCode={test_alert['EventCode']} host={test_alert['host']}")
    print()

    initial_state = make_initial_input(test_alert)
    result = app.invoke(initial_state)

    print(f"Final status:    {result['final_status']}")
    print(f"Triage score:    {result['triage_score']}")
    print(f"Severity:        {result['severity']}")
    print(f"IoCs found:      {len(result['ioc_list'])}")
    print(f"ATT&CK tags:     {[t['technique_id'] for t in result['attack_techniques']]}")
    print()
    print("Event log:")
    for event in result["event_log"]:
        print(f"  [{event['node']}] {event['detail']}")
    print()
    print("ATT&CK techniques detail:")
    for t in result["attack_techniques"]:
        print(f"  {t['technique_id']} — {t['technique_name']} (confidence={t['confidence']:.2f})")
        print(f"  Rationale: {t['rationale']}")
        print()
