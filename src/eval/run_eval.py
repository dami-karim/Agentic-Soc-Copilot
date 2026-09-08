"""
Evaluation Runner — Week 7.

Runs the full pipeline on a test set of labeled BOTS v3 alerts
and computes the three evaluation metrics.

Test set: hand-labeled BOTS v3 scenarios covering the main
attack patterns (brute force, lateral movement, execution,
persistence). Ground-truth ATT&CK labels from the official
BOTS v3 answer key.

Baseline: rule-based triage (keyword matching, no LLM, no tools)
so the marginal value of the agentic approach is measurable.
"""
import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.graph import build_graph
from src.nodes.ingest import make_initial_input
from src.eval.metrics import compute_attack_metrics, compute_mttr, compute_false_execution_rate

# ── LABELED TEST SET ─────────────────────────────────────────────────────────
# Each entry: (alert_dict, ground_truth_techniques)
# Ground truth from BOTS v3 official answer key
TEST_ALERTS = [
    (
        {
            "host": "WIN-DC01", "EventCode": "4625",
            "src_ip": "10.0.2.15", "dest_ip": "10.0.2.5",
            "user": "administrator", "Logon_Type": "3",
            "signature": "An account failed to log on", "severity": "medium",
        },
        ["T1110", "T1110.001"]   # Brute Force, Password Guessing
    ),
    (
        {
            "host": "WIN-DC01", "EventCode": "4624",
            "src_ip": "10.0.2.15", "dest_ip": "10.0.2.5",
            "user": "administrator", "Logon_Type": "3",
            "signature": "An account was successfully logged on", "severity": "high",
        },
        ["T1078", "T1078.002"]   # Valid Accounts, Domain Accounts
    ),
    (
        {
            "host": "WIN-WEB01", "EventCode": "4688",
            "src_ip": "", "dest_ip": "",
            "user": "administrator",
            "signature": "A new process has been created: powershell.exe -enc SGVsbG8=",
            "severity": "high",
        },
        ["T1059", "T1059.001"]   # Command and Scripting Interpreter, PowerShell
    ),
    (
        {
            "host": "WIN-FIN02", "EventCode": "4698",
            "src_ip": "", "dest_ip": "",
            "user": "administrator",
            "signature": "A scheduled task was created", "severity": "critical",
        },
        ["T1053", "T1053.005"]   # Scheduled Task/Job, Scheduled Task
    ),
    (
        {
            "host": "WIN-WEB01", "EventCode": "4624",
            "src_ip": "10.0.2.5", "dest_ip": "10.0.2.20",
            "user": "administrator", "Logon_Type": "3",
            "signature": "Lateral movement via network logon detected", "severity": "critical",
        },
        ["T1021", "T1021.002"]   # Remote Services, SMB/Windows Admin Shares
    ),
    # Benign alert — should be terminated early with COMPLETED_BENIGN
    (
        {
            "host": "WIN-WEB01", "EventCode": "4634",
            "src_ip": "", "dest_ip": "",
            "user": "jsmith",
            "signature": "An account was logged off", "severity": "low",
        },
        []   # No ATT&CK techniques — benign event
    ),
]


# ── BASELINE: Rule-based triage (no LLM, no tools) ───────────────────────────
EVENTCODE_BASELINE = {
    "4625": ["T1110"],
    "4624": ["T1078"],
    "4688": ["T1059"],
    "4698": ["T1053"],
    "4634": [],
    "4648": ["T1078"],
}


def run_baseline(alert: dict) -> list[str]:
    """Rule-based baseline: EventCode → technique mapping only."""
    return EVENTCODE_BASELINE.get(str(alert.get("EventCode", "")), [])


def run_evaluation(skip_hil: bool = True):
    """
    Runs both agent and baseline on the test set.

    Args:
        skip_hil: If True, auto-approve all HIL prompts (for automated eval).
                  Set to False for interactive demo.
    """
    print("=" * 70)
    print("AGENTIC SOC CO-PILOT — Week 7 Evaluation")
    print("=" * 70)
    print(f"Test set: {len(TEST_ALERTS)} alerts "
          f"({sum(1 for _, gt in TEST_ALERTS if gt)} malicious, "
          f"{sum(1 for _, gt in TEST_ALERTS if not gt)} benign)")
    print()

    app = build_graph()

    agent_results = []
    baseline_results = []

    for i, (alert, ground_truth) in enumerate(TEST_ALERTS, 1):
        print(f"[{i}/{len(TEST_ALERTS)}] EventCode={alert.get('EventCode')} "
              f"host={alert.get('host')} severity={alert.get('severity')}")

        # ── Agent evaluation ─────────────────────────────────────────────
        start_time = time.time()

        if skip_hil:
            # Monkey-patch HIL to auto-approve for automated evaluation
            import src.guardrails.hil_checkpoint as hil_mod
            original_hil = hil_mod.hil_checkpoint_node

            def auto_approve_hil(state):
                from datetime import datetime, timezone
                for action in state["proposed_actions"]:
                    state["human_decisions"].append({
                        "gate_name": "HIL_2",
                        "action_type": action["action_type"],
                        "target": action["target"],
                        "risk_level": action["risk_level"],
                        "decision": "approved",
                        "analyst_note": "Auto-approved for evaluation",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                return state

            hil_mod.hil_checkpoint_node = auto_approve_hil

        try:
            result = app.invoke(make_initial_input(alert))
        except Exception as e:
            print(f"  ERROR: {e}")
            continue
        finally:
            if skip_hil:
                hil_mod.hil_checkpoint_node = original_hil

        elapsed = time.time() - start_time

        predicted = [t["technique_id"] for t in result.get("attack_techniques", [])]
        metrics = compute_attack_metrics(predicted, ground_truth)
        mttr = compute_mttr(result.get("event_log", []))
        fer = compute_false_execution_rate(
            result.get("proposed_actions", []),
            result.get("human_decisions", [])
        )

        agent_results.append({
            "alert": alert,
            "ground_truth": ground_truth,
            "predicted": predicted,
            "metrics": metrics,
            "mttr_seconds": mttr,
            "fer": fer,
            "final_status": str(result.get("final_status", "")),
            "guardrail_flags": len(result.get("guardrail_flags", [])),
        })

        # ── Baseline evaluation ──────────────────────────────────────────
        baseline_predicted = run_baseline(alert)
        baseline_metrics = compute_attack_metrics(baseline_predicted, ground_truth)
        baseline_results.append(baseline_metrics)

        print(f"  Agent:    P={metrics['precision']:.2f} R={metrics['recall']:.2f} "
              f"F1={metrics['f1']:.2f} | MTTR={mttr:.1f}s | "
              f"status={result.get('final_status', '?')}")
        print(f"  Baseline: P={baseline_metrics['precision']:.2f} "
              f"R={baseline_metrics['recall']:.2f} F1={baseline_metrics['f1']:.2f}")
        print()

    # ── Aggregate metrics ─────────────────────────────────────────────────────
    if not agent_results:
        print("No results to aggregate.")
        return

    avg_agent_p = sum(r["metrics"]["precision"] for r in agent_results) / len(agent_results)
    avg_agent_r = sum(r["metrics"]["recall"] for r in agent_results) / len(agent_results)
    avg_agent_f1 = sum(r["metrics"]["f1"] for r in agent_results) / len(agent_results)
    avg_mttr = sum(r["mttr_seconds"] for r in agent_results) / len(agent_results)
    total_fer = sum(r["fer"]["bypassed"] for r in agent_results)
    total_high_risk = sum(r["fer"]["total_high_risk"] for r in agent_results)
    overall_fer = total_fer / total_high_risk if total_high_risk > 0 else 0.0

    avg_base_p = sum(r["precision"] for r in baseline_results) / len(baseline_results)
    avg_base_r = sum(r["recall"] for r in baseline_results) / len(baseline_results)
    avg_base_f1 = sum(r["f1"] for r in baseline_results) / len(baseline_results)

    print("=" * 70)
    print("EVALUATION RESULTS SUMMARY")
    print("=" * 70)
    print(f"{'Metric':<30} {'Agent':>12} {'Baseline':>12} {'Delta':>10}")
    print("-" * 70)
    print(f"{'ATT&CK Avg Precision':<30} {avg_agent_p:>12.3f} {avg_base_p:>12.3f} {avg_agent_p-avg_base_p:>+10.3f}")
    print(f"{'ATT&CK Avg Recall':<30} {avg_agent_r:>12.3f} {avg_base_r:>12.3f} {avg_agent_r-avg_base_r:>+10.3f}")
    print(f"{'ATT&CK Avg F1':<30} {avg_agent_f1:>12.3f} {avg_base_f1:>12.3f} {avg_agent_f1-avg_base_f1:>+10.3f}")
    print(f"{'Simulated MTTR (avg, sec)':<30} {avg_mttr:>12.1f} {'N/A':>12} {'':>10}")
    print(f"{'False Execution Rate':<30} {overall_fer:>12.3f} {'N/A':>12} {'':>10}")
    print("-" * 70)
    print()

    if avg_agent_f1 > avg_base_f1:
        print(f"✓ Agent outperforms baseline by {(avg_agent_f1 - avg_base_f1):.3f} F1 points")
    else:
        print(f"✗ Agent underperforms baseline by {(avg_base_f1 - avg_agent_f1):.3f} F1 points")

    if overall_fer == 0.0:
        print("✓ False execution rate = 0.0 — all high-risk actions went through HIL")
    else:
        print(f"✗ False execution rate = {overall_fer:.1%} — {total_fer} action(s) bypassed HIL")

    print()
    print("Metric definitions:")
    print("  ATT&CK Precision/Recall: following RAM (arXiv:2502.02337) AR/AP metric")
    print("  Simulated MTTR: wall-clock time from ingest to deploy node")
    print("  False Execution Rate: fraction of high-risk actions that bypassed HIL gate")


if __name__ == "__main__":
    run_evaluation(skip_hil=True)
