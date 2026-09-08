"""
Batch False-Positive Filter — classify thousands of alerts from the dashboard.

Lets the analyst:
  1. Upload a JSON/JSONL file of alerts (any size)
  2. Or instantly generate a 10,000-alert sample dataset
  3. Run the rule-based FP filter (fast, no LLM)
  4. See a scoreboard: FP / TP / REVIEW counts + rates
  5. Preview the per-alert detail table
  6. Download the full report as JSON
  7. (Optionally) resolve REVIEW alerts via the local LLM
"""
from __future__ import annotations

import json

import streamlit as st

from src.ui import components as C
from src.ui.icons import icon

# ── helpers ──────────────────────────────────────────────────────────────────────

def _alerts_from_file(uploaded) -> list[dict] | None:
    if uploaded is None:
        return None
    raw = uploaded.getvalue().decode("utf-8")
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]

    # Try JSON array first
    if raw.lstrip().startswith("["):
        try:
            data = json.loads(raw)
            return [a for a in data if isinstance(a, dict)]
        except json.JSONDecodeError:
            pass

    # JSONL
    alerts = []
    for ln in lines:
        try:
            parsed = json.loads(ln)
            if isinstance(parsed, dict):
                alerts.append(parsed)
        except json.JSONDecodeError:
            continue
    return alerts or None


def _generate_sample(n: int, fp_ratio: float, seed: int) -> list[dict]:
    import random

    from lab.generate_fp_filter_dataset import (
        _fp_patterns,
        _tp_patterns,
    )
    random.seed(seed)
    fp = _fp_patterns()
    tp = _tp_patterns()
    alerts = []
    for _ in range(n):
        make, _ = (random.choice(fp) if random.random() < fp_ratio
                   else random.choice(tp))
        alerts.append(make())
    return alerts


# ── main view ─────────────────────────────────────────────────────────────────────

def render() -> None:
    st.markdown('<div class="sec-label"><span class="t">'
                f'{icon("filter", 18)} Batch False-Positive Filter</span></div>',
                unsafe_allow_html=True)

    # ── Source selector ────────────────────────────────────────────────────────
    src = st.radio("Alert source", ["Upload file", "Generate sample"],
                    horizontal=True, key="fp_src")

    alerts = None
    ground_truth = None
    n = 10_000

    if src == "Upload file":
        uploaded = st.file_uploader(
            "Drop a JSON or JSONL file of SIEM alerts",
            type=["json", "jsonl"],
            key="fp_upload",
            help="One alert object per JSONL line, or a JSON array.",
        )
        alerts = _alerts_from_file(uploaded)

        gt_file = st.file_uploader(
            "Optional: ground-truth labels file (JSONL)",
            type=["json", "jsonl"],
            key="fp_gt",
            help="One entry per alert: {'is_false_positive': bool} or "
                 "bool where True=malicious.",
            label_visibility="collapsed",
        )
        if gt_file:
            raw = gt_file.getvalue().decode("utf-8")
            try:
                ground_truth = json.loads(raw)
            except json.JSONDecodeError:
                ground_truth = [json.loads(ln) for ln in raw.splitlines()
                                if ln.strip()]

    else:
        c1, c2, c3 = st.columns([2, 1, 1])
        with c1:
            n = st.number_input("Number of alerts", min_value=100,
                                max_value=200_000, value=10_000, step=1_000,
                                key="fp_n")
        with c2:
            fp_ratio = st.slider("Share that are noise", 0.50, 0.99, 0.85,
                                 key="fp_ratio")
        with c3:
            seed = st.number_input("Seed", min_value=0, max_value=99999,
                                   value=42, key="fp_seed")
        alerts = _generate_sample(n, fp_ratio, seed)
        # Ground truth is embedded inside the generator; re-generate to capture it
        import random
        random.seed(seed)
        from lab.generate_fp_filter_dataset import _fp_patterns, _tp_patterns
        fp_p = _fp_patterns()
        tp_p = _tp_patterns()
        ground_truth = []
        for _ in range(n):
            _, label = (random.choice(fp_p) if random.random() < fp_ratio
                        else random.choice(tp_p))
            ground_truth.append({"is_false_positive": label})

    if not alerts:
        C.callout("No alerts loaded. Upload a file or use <b>Generate sample</b>.",
                  kind="info", ic="info")
        return

    # ── Run button ─────────────────────────────────────────────────────────────
    use_llm = st.checkbox(
        "Resolve REVIEW alerts via local LLM",
        value=False,
        key="fp_llm",
        help="Needs Ollama running. Off = rule-based only (fast).",
    )

    if st.button(f"Classify {len(alerts):,} alerts", key="fp_run",
                 type="primary", use_container_width=True):
        with st.status(f"Classifying {len(alerts):,} alerts…",
                       expanded=False) as status:
            import time

            from src.fp_filter.batch import run_batch
            start = time.time()
            report = run_batch(alerts, ground_truth=ground_truth,
                               use_llm=use_llm, verbose=False)
            elapsed = time.time() - start
            report["duration_seconds"] = round(elapsed, 3)
            st.session_state["fp_report"] = report
            status.update(label=f"Done — {elapsed:.3f}s", state="complete")

    report = st.session_state.get("fp_report")
    if not report:
        C.callout(f"Loaded <b>{len(alerts):,}</b> alerts — press <b>Classify</b> to begin."
                  , kind="info", ic="zap")
        return

    # ── Scoreboard ─────────────────────────────────────────────────────────────
    counts = report["verdicts"]
    total = report["total"]
    dur = report.get("duration_seconds", 0)

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.metric("Total", f"{total:,}")
    with c2:
        st.metric("True positives", f"{counts['true_positive']:,}",
                   delta=f"{report['true_positive_rate']:.1%} of alerts",
                   delta_color="off")
    with c3:
        st.metric("False positives (noise)", f"{counts['false_positive']:,}",
                   delta=f"{report['false_positive_rate']:.1%} filtered out",
                   delta_color="off")
    with c4:
        st.metric("Review", f"{counts['review']:,}",
                   delta=f"{report['review_rate']:.1%}",
                   delta_color="off")
    with c5:
        st.metric("Duration", f"{dur*1000:.0f} ms")

    # ── Ground truth metrics (if available) ────────────────────────────────────
    metrics = report.get("metrics")
    if metrics and "precision" in metrics:
        st.markdown('<div class="sec-label"><span class="t">'
                    'Accuracy vs ground truth</span></div>',
                    unsafe_allow_html=True)
        rows = [
            ("Precision", f"{metrics['precision']:.1%}"),
            ("Recall", f"{metrics['recall']:.1%}"),
            ("F1", f"{metrics['f1']:.1%}"),
            ("Accuracy", f"{metrics['accuracy']:.1%}"),
            ("FP reduction (benign suppressed)",
             f"{metrics['fp_reduction']:.1%}"),
            ("Missed threats",
             f"{metrics['false_negatives']} ({metrics['missed_threat_rate']:.1%})"),
        ]
        st.markdown(f'<div class="soc-card">{C.kv_table(rows)}</div>',
                    unsafe_allow_html=True)

    # ── Per-alert detail table ─────────────────────────────────────────────────
    st.markdown('<div class="sec-label"><span class="t">Per-alert results</span></div>',
                unsafe_allow_html=True)
    rows = report.get("per_alert", [])
    # Flatten signals for the table
    table_data = []
    for row in rows[:5000]:  # cap table to 5k rows for browser performance
        sig = row.get("signals", {})
        table_data.append({
            "idx": row["index"],
            "verdict": row["verdict"],
            "score": row["score"],
            "confidence": row["confidence"],
            "method": row["method"],
            "EventCode": sig.get("event_code", ""),
            "severity": sig.get("severity", ""),
            "user": sig.get("user", ""),
            "count": sig.get("count", ""),
            "reasons": "; ".join(row.get("reasons", [])[:2]),
        })
    st.dataframe(table_data, use_container_width=True,
                 height=min(350, 37 * len(table_data) + 37))

    # ── Download report ────────────────────────────────────────────────────────
    blob = json.dumps(report, indent=2, default=str)
    st.download_button(
        "Download full report (JSON)",
        data=blob,
        file_name="fp_filter_report.json",
        mime="application/json",
        key="fp_download",
    )