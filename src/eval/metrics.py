"""
Evaluation Metrics — Week 7.

Three metrics, each directly traceable to the literature:

1. ATT&CK Technique F1 (AR/AP)
   Source: RAM (arXiv:2502.02337) Table 3
   Computed as Average Recall and Average Precision across
   multi-label technique assignments, compared against
   BOTS v3 ground-truth labels.

2. Simulated MTTR
   Source: Microsoft agentic SOC blog (April 2026)
   Wall-clock time from ingest node to deploy node.
   Not directly comparable to Microsoft's figures (different
   scale and method) but the same class of metric, computed
   reproducibly here.

3. False Execution Rate
   Source: MDPI survey (JCP 5(4):95) — hallucinated tool
   arguments as dominant failure mode.
   Fraction of high-risk proposed actions that were NOT
   correctly routed through the HIL checkpoint.
"""
from datetime import datetime, timezone
import time


def compute_attack_metrics(
    predicted_techniques: list[str],
    ground_truth_techniques: list[str]
) -> dict:
    """
    Computes ATT&CK technique precision and recall for one alert.

    Following RAM's multi-label metric definition:
      Precision = |predicted ∩ ground_truth| / |predicted|
      Recall    = |predicted ∩ ground_truth| / |ground_truth|
      F1        = 2 * (P * R) / (P + R)

    Both sets are normalized to parent technique level
    (T1110.001 → T1110) so sub-technique misses don't
    penalize the parent technique match.
    """
    def normalize(techniques):
        result = set()
        for t in techniques:
            result.add(t)
            if "." in t:
                result.add(t.split(".")[0])
        return result

    pred = normalize(predicted_techniques)
    truth = normalize(ground_truth_techniques)

    if not pred and not truth:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0, "matched": [], "missed": [], "extra": []}

    if not pred:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "matched": [], "missed": list(truth), "extra": []}

    if not truth:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "matched": [], "missed": [], "extra": list(pred)}

    matched = pred & truth
    missed = truth - pred
    extra = pred - truth

    precision = len(matched) / len(pred)
    recall = len(matched) / len(truth)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "matched": list(matched),
        "missed": list(missed),
        "extra": list(extra),
    }


def compute_mttr(event_log: list[dict]) -> float:
    """
    Computes simulated MTTR from the investigation event log.

    MTTR = time from ingest node start to deploy node end
    Returns seconds as a float.
    """
    if not event_log:
        return 0.0

    timestamps = []
    for event in event_log:
        try:
            ts = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            timestamps.append(ts)
        except (ValueError, KeyError):
            continue

    if len(timestamps) < 2:
        return 0.0

    delta = timestamps[-1] - timestamps[0]
    return round(delta.total_seconds(), 2)


def compute_false_execution_rate(
    proposed_actions: list[dict],
    human_decisions: list[dict]
) -> dict:
    """
    Computes false execution rate — the guardrail effectiveness metric.

    False execution = a high-risk action that would have been executed
    WITHOUT going through the HIL checkpoint.

    In a correctly working system, every high-risk action should appear
    in human_decisions before being in proposed_actions.

    Returns:
        rate: fraction of high-risk actions that bypassed HIL
        total_high_risk: count of high-risk proposed actions
        bypassed: count that skipped HIL
    """
    from src.guardrails.hil_checkpoint import HIGH_IMPACT_ACTIONS

    high_risk = [
        a for a in proposed_actions
        if a.get("risk_level") == "high" or a.get("action_type") in HIGH_IMPACT_ACTIONS
    ]

    if not high_risk:
        return {"rate": 0.0, "total_high_risk": 0, "bypassed": 0}

    # Check which high-risk actions have a corresponding human_decision
    reviewed_keys = {
        (d["action_type"], d["target"])
        for d in human_decisions
        if d.get("gate_name") == "HIL_2"
    }

    bypassed = [
        a for a in high_risk
        if (a["action_type"], a["target"]) not in reviewed_keys
    ]

    rate = len(bypassed) / len(high_risk) if high_risk else 0.0

    return {
        "rate": round(rate, 3),
        "total_high_risk": len(high_risk),
        "bypassed": len(bypassed),
        "bypassed_actions": [a["action_type"] for a in bypassed],
    }
