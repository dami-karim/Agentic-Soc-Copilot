"""
Batch runner — triage a large set of alerts (e.g. 1000) in one pass.

Each alert gets a rule-based FP/TP/REVIEW verdict in pure Python (no LLM, no
DB), so a 1000-alert batch completes in well under a second. Optionally the
REVIEW bucket can be sent to the local LLM adjudicator for resolution.

If ground-truth labels are supplied, a binary classification summary is
computed so the filter's false-positive-reduction behaviour can be measured.
"""
import json

from src.fp_filter.adjudicator import adjudicate_alert
from src.fp_filter.classifier import (
    FALSE_POSITIVE,
    REVIEW,
    TRUE_POSITIVE,
    classify_alert,
)

VERDICTS = {FALSE_POSITIVE, TRUE_POSITIVE, REVIEW}


# ── Ground-truth parsing ───────────────────────────────────────────────────────

def _label_polarity(entry) -> str | None:
    """Convert one ground-truth entry to 'malicious' or 'benign'."""
    if isinstance(entry, bool):
        return "malicious" if entry else "benign"
    if isinstance(entry, dict):
        fp = entry.get("is_false_positive")
        if isinstance(fp, bool):
            return "benign" if fp else "malicious"
    if isinstance(entry, str):
        low = entry.strip().lower()
        if low in ("false_positive", "fp", "benign", "noise", "false positive"):
            return "benign"
        if low in ("true_positive", "tp", "malicious", "threat", "true positive"):
            return "malicious"
    return None


# ── Input loading ──────────────────────────────────────────────────────────────

def load_alerts(path: str) -> list[dict]:
    """
    Load alerts from a JSON file.

    Supported formats:
      - JSON array of alert objects
      - JSON object {"alerts": [...]}
      - JSONL (one alert object per line)
    """
    with open(path, "r", encoding="utf-8") as fh:
        content = fh.read().strip()

    if content.startswith("["):
        data = json.loads(content)
        return [a for a in data if isinstance(a, dict)]

    lines = [ln for ln in content.splitlines() if ln.strip()]
    if len(lines) > 1 or not content.startswith("{"):
        alerts = []
        for ln in lines:
            if not ln.strip():
                continue
            parsed = json.loads(ln)
            if isinstance(parsed, dict):
                alerts.append(parsed)
        if alerts:
            return alerts

    data = json.loads(content)
    if isinstance(data, dict) and isinstance(data.get("alerts"), list):
        return [a for a in data["alerts"] if isinstance(a, dict)]
    raise ValueError("Unsupported alerts format — expected JSON array, JSONL, or {'alerts': [...]}")


def _default_alert_id(alert: dict, index: int) -> str:
    return str(alert.get("alert_id") or alert.get("id") or f"alert-{index+1:04d}")


# ── Binary classification metrics ──────────────────────────────────────────────

def binary_metrics(labels: list[str], predictions: list[str]) -> dict:
    """
    Compute binary classification metrics over aligned verdicts.

    'positive' = TRUE_POSITIVE (a real, actionable threat).
    Alerts left in REVIEW are counted separately and excluded from the
    precision/recall/F1 denominators (they are undecided, not wrong).

    Returns:
        Counts (tp/fp/tn/fn/review) plus precision, recall, f1, accuracy,
        false positive rate, and fp_reduction (share of benign alerts that
        were correctly suppressed).
    """
    if len(labels) != len(predictions):
        raise ValueError("Ground-truth labels and predictions must be aligned")

    tp = fp = tn = fn = review = 0
    for label, pred in zip(labels, predictions):
        if pred == REVIEW:
            review += 1
            continue
        if label == "malicious" and pred == TRUE_POSITIVE:
            tp += 1
        elif label == "benign" and pred == TRUE_POSITIVE:
            fp += 1
        elif label == "benign" and pred == FALSE_POSITIVE:
            tn += 1
        elif label == "malicious" and pred == FALSE_POSITIVE:
            fn += 1

    definitive = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / definitive if definitive else 0.0
    benign_total = tn + fp
    fp_reduction = tn / benign_total if benign_total else 0.0
    malicious_total = tp + fn
    missed_threats = fn / malicious_total if malicious_total else 0.0

    return {
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "review": review,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "accuracy": round(accuracy, 3),
        "false_positive_rate": round(fp / (fp + tn) if (fp + tn) else 0.0, 3),
        "fp_reduction": round(fp_reduction, 3),
        "missed_threat_rate": round(missed_threats, 3),
    }


# ── Batch processing ───────────────────────────────────────────────────────────

def run_batch(
    alerts: list[dict],
    ground_truth: list | None = None,
    use_llm: bool = False,
    verbose: bool = True,
) -> dict:
    """
    Classify every alert in the batch and aggregate a report.

    Args:
        alerts: List of raw SIEM alert dictionaries.
        ground_truth: Optional aligned labels (bool, {'is_false_positive': bool},
            or str 'fp'/'tp'). len must equal len(alerts).
        use_llm: Resolve REVIEW alerts via the local LLM adjudicator.
        verbose: Print progress/result summary to stdout.

    Returns:
        dict report: totals, verdict distribution, filter rate, per-alert rows,
        and (if ground_truth given) accuracy metrics.
    """
    if ground_truth is not None and len(ground_truth) != len(alerts):
        raise ValueError("ground_truth length must match alerts length")

    rows = []
    review_count = 0
    for index, alert in enumerate(alerts):
        result = classify_alert(alert)

        if result.verdict == REVIEW and use_llm:
            decision = adjudicate_alert(alert, result.score, result.signals)
            if decision:
                result.verdict = decision["verdict"]
                result.confidence = decision["confidence"]
                result.method = "llm"
                result.review_note = decision.get("rationale", "")

        if result.verdict == REVIEW:
            review_count += 1

        rows.append(result.to_dict(index=index, alert_id=_default_alert_id(alert, index)))

    verdict_counts = {v: 0 for v in VERDICTS}
    for row in rows:
        verdict_counts[row["verdict"]] += 1

    total = len(rows)
    report = {
        "total": total,
        "verdicts": verdict_counts,
        "false_positive_rate": round(verdict_counts[FALSE_POSITIVE] / total, 3) if total else 0.0,
        "true_positive_rate": round(verdict_counts[TRUE_POSITIVE] / total, 3) if total else 0.0,
        "review_rate": round(verdict_counts[REVIEW] / total, 3) if total else 0.0,
        "filtered_rate": round(verdict_counts[FALSE_POSITIVE] / total, 3) if total else 0.0,
        "use_llm_adjudication": use_llm,
        "per_alert": rows,
    }

    if ground_truth is not None:
        labels = [_label_polarity(e) for e in ground_truth]
        valid = all(l is not None for l in labels) if labels else False
        if not valid:
            report["metrics"] = {"error": "Could not parse ground-truth labels"}
        else:
            predictions = [r["verdict"] for r in rows]
            report["metrics"] = binary_metrics(labels, predictions)

    if verbose:
        _print_summary(report)

    return report


def _print_summary(report: dict) -> None:
    counts = report["verdicts"]
    total = report["total"]
    print("=" * 60)
    print("FALSE-POSITIVE FILTER — BATCH SUMMARY")
    print("=" * 60)
    if report.get("use_llm_adjudication"):
        print("LLM adjudication:       enabled (REVIEW alerts resolved by local model)")
    print(f"Alerts processed:        {total}")
    print(f"False positives kept:    {counts[FALSE_POSITIVE]}  ({report['false_positive_rate']:.1%})")
    print(f"True positives flagged:  {counts[TRUE_POSITIVE]}  ({report['true_positive_rate']:.1%})")
    print(f"Review (borderline):     {counts[REVIEW]}  ({report['review_rate']:.1%})")
    if report.get("metrics") and "precision" in report["metrics"]:
        m = report["metrics"]
        print("-" * 60)
        print("GROUND-TRUTH METRICS (positive = true positive)")
        print(f"  Precision:            {m['precision']:.3f}")
        print(f"  Recall:               {m['recall']:.3f}")
        print(f"  F1:                   {m['f1']:.3f}")
        print(f"  Accuracy:             {m['accuracy']:.3f}")
        print(f"  FPs (pred TP, benign):{m['false_positives']}")
        print(f"  FNs (pred FP, threat):{m['false_negatives']}")
        print(f"  FP reduction:         {m['fp_reduction']:.1%} of benign alerts suppressed")
    print("=" * 60)