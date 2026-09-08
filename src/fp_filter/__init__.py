"""
False-Positive Filter — batch alert triage at scale.

Reduces alert fatigue by classifying each alert in a batch as a TRUE POSITIVE,
FALSE POSITIVE, or REVIEW BEFORE the expensive ReAct investigation runs.

Only alerts classified as TRUE POSITIVE (or REVIEW, after human adjudication)
flow into the full investigation pipeline — a large batch of noise is
filtered out in milliseconds without LLM or database round-trips.

Components:
  - signals.py     : deterministic signal extraction from a raw SIEM alert
  - classifier.py  : rule-based triage scoring + FP/TP/REVIEW verdict
  - adjudicator.py : optional local-LLM adjudication for borderline (REVIEW) alerts
  - batch.py       : process hundreds of alerts, produce a report + metrics
  - cli.py         : command line entry point (`python -m src.fp_filter`)
"""
from src.fp_filter.batch import binary_metrics, load_alerts, run_batch
from src.fp_filter.classifier import (
    FPFilterResult,
    classify_alert,
    compute_triage_score,
)
from src.fp_filter.signals import extract_signals

__all__ = [
    "FPFilterResult",
    "binary_metrics",
    "classify_alert",
    "compute_triage_score",
    "extract_signals",
    "load_alerts",
    "run_batch",
]