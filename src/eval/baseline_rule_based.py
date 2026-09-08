"""
Rule-based baseline for comparison in Week 7 evaluation.

No LLM, no tools — just EventCode → triage decision mapping.
Used to measure the marginal value of the agentic approach.
"""
from src.eval.metrics import compute_attack_metrics

EVENTCODE_TO_TECHNIQUES = {
    "4625": ["T1110"],
    "4624": ["T1078"],
    "4688": ["T1059"],
    "4698": ["T1053"],
    "4648": ["T1078"],
    "4672": ["T1548"],
    "4776": ["T1110"],
    "7045": ["T1543"],
}

BENIGN_CODES = {"4634", "4647", "4800", "4801"}


def baseline_triage(alert: dict) -> dict:
    event_code = str(alert.get("EventCode", ""))
    severity = alert.get("severity", "low")

    if event_code in BENIGN_CODES or severity == "low":
        return {
            "final_status": "COMPLETED_BENIGN",
            "triage_score": 5.0,
            "attack_techniques": [],
            "proposed_actions": [],
        }

    techniques = EVENTCODE_TO_TECHNIQUES.get(event_code, [])
    return {
        "final_status": "COMPLETED",
        "triage_score": 60.0,
        "attack_techniques": [{"technique_id": t} for t in techniques],
        "proposed_actions": [],
    }


if __name__ == "__main__":
    from src.eval.run_eval import TEST_ALERTS
    print("Rule-based baseline results:")
    precisions, recalls, f1s = [], [], []
    for alert, ground_truth in TEST_ALERTS:
        result = baseline_triage(alert)
        predicted = [t["technique_id"] for t in result["attack_techniques"]]
        m = compute_attack_metrics(predicted, ground_truth)
        precisions.append(m["precision"])
        recalls.append(m["recall"])
        f1s.append(m["f1"])
        print(f"  EventCode={alert.get('EventCode')} "
              f"P={m['precision']:.2f} R={m['recall']:.2f} F1={m['f1']:.2f}")

    print(f"\nAverage: P={sum(precisions)/len(precisions):.3f} "
          f"R={sum(recalls)/len(recalls):.3f} "
          f"F1={sum(f1s)/len(f1s):.3f}")
