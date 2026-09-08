"""
Investigation Timeline — the pipeline execution trace as a modern,
expandable timeline with subtle colored dots.

Every entry renders from the real SOCAgentState.event_log; summaries are
parsed deterministically from node-produced state data. Nothing invented.
"""
from __future__ import annotations

import re
from datetime import datetime

import streamlit as st

from src.ui import components as C
from src.ui.data import EVENTCODE_DESCRIPTIONS, PIPELINE_NODE_LABELS

# Node accent colors (theme-aware CSS variables)
NODE_COLOR = {
    "ingest":          "var(--primary)",
    "classify":        "var(--warn)",
    "investigate":     "var(--purple)",
    "hil_classify":    "var(--warn)",
    "rca_generator":   "var(--primary)",
    "propose_actions": "var(--primary)",
    "hil_action":      "var(--warn)",
    "deploy":          "var(--ok)",
}


def _fmt_time(iso_ts: str) -> str:
    try:
        dt = datetime.fromisoformat(str(iso_ts).replace("Z", "+00:00"))
        return dt.strftime("%H:%M:%S")
    except Exception:
        return "--:--:--"


def _headline(event: dict, result: dict) -> tuple[str, str]:
    """Return (headline html, extra text) for an event_log summary row."""
    node = str(event.get("node", "unknown"))
    detail = str(event.get("detail", ""))

    if node == "ingest":
        alert = result.get("alert_raw", {}) or {}
        return ("Alert received",
                f"{alert.get('host', '?')} · EC {alert.get('EventCode', '?')}")

    if node == "classify":
        m = re.search(r"triage_score=([\d.]+) severity=(\S+) EventCode=(\S*) route=(\S+)",
                      detail)
        if m:
            score, sev, ec, route = m.groups()
            color = "var(--crit)" if route == "malicious" else "var(--ok)"
            headline = (f"Severity {sev.upper()} · triage score "
                        f"<span style='color:{color};font-weight:600;'>"
                        f"{float(score):g}</span> · routed {route.upper()}")
            return headline, f"EC {ec}"

    if node == "investigate":
        trace = ((result.get("enrichment", {}) or {}).get("tool_trace", []))
        n_tools = len([t for t in trace if t.get("tool") != "_final_answer"])
        m = re.search(r"(\d+) IoCs, (\d+) techniques", detail)
        if m:
            n_ioc, n_tech = m.groups()
            return ("Evidence analysis finished",
                    f"{n_tools} tool calls · {n_ioc} IoCs · {n_tech} techniques")
        if "failed" in detail.lower():
            return "Agent failed — continuing with empty investigation", ""
        return ("Evidence analysis finished",
                f"{n_tools} tool calls" if n_tools else "")

    if node == "rca_generator":
        m = re.search(r"confidence=(\d+)%", detail)
        conf = f"{m.group(1)}% confidence" if m else ""
        return "Root-cause report generated", conf

    if node == "propose_actions":
        m = re.search(r"Proposed (\d+) actions \((\d+) high-risk", detail)
        if m:
            n, hr = m.groups()
            extra = f"{n} proposed · {hr} high-risk" if hr != "0" \
                else f"{n} proposed"
            return "Containment actions proposed", extra
        return "Containment actions proposed", ""

    if node == "hil_classify":
        if "APPROVED" in detail:
            return "Analyst approved investigation", ""
        if "REJECTED" in detail:
            return "Analyst rejected — terminated benign", ""
        return "Classification review gate", ""

    if node == "hil_action":
        return "Action approval completed", ""

    if node == "deploy":
        if "BENIGN" in detail:
            return "Closed as benign — no action taken", ""
        if "COMPLETE" in detail:
            return "Investigation closed — awaiting analyst review", ""
        return "Pipeline terminal state reached", ""

    # Fallback: first clause of raw detail
    return (C.esc(detail.split(".")[0][:90]) or C.esc(node)), ""


# ── Per-node structured bodies (built only from real state data) ──────────────


def _body_ingest(result: dict) -> str:
    alert = result.get("alert_raw", {}) or {}
    rows = [
        ("Workflow ID", f"<span class='mono'>{C.esc(str(result.get('workflow_id', ''))[:18])}…</span>"),
        ("Alert ID", f"<span class='mono'>{C.esc(str(result.get('alert_id', ''))[:24])}</span>"),
    ]
    for key, label in [("host", "Host"), ("EventCode", "EventCode"),
                       ("user", "Account"), ("src_ip", "Source IP"),
                       ("dest_ip", "Dest IP"), ("Logon_Type", "Logon Type"),
                       ("sourcetype", "Sourcetype"), ("severity", "Severity"),
                       ("count", "Event Count")]:
        v = alert.get(key)
        if v not in (None, "", "unknown"):
            rows.append((label, f"<span class='mono'>{C.esc(v)}</span>"))
    sig = alert.get("signature")
    if sig:
        rows.append(("Signature", C.esc(sig)))
    ec = str(alert.get("EventCode", ""))
    ec_desc = EVENTCODE_DESCRIPTIONS.get(ec)
    if ec_desc:
        rows.append(("Event meaning", C.esc(ec_desc)))
    return C.kv_table(rows)


def _body_classify(event: dict) -> str:
    detail = str(event.get("detail", ""))
    m = re.search(r"triage_score=([\d.]+) severity=(\S+) EventCode=(\S*) route=(\S+)",
                  detail)
    rows: list[tuple[str, str]] = []
    if m:
        score, sev, ec, route = m.groups()
        rc = "var(--crit)" if route == "malicious" else "var(--ok)"
        rows = [
            ("Triage Score", f"<span class='mono'>{float(score):g} / 100</span>"),
            ("Severity", C.severity_pill(sev)),
            ("Route", f"<b style='color:{rc};'>{C.esc(route.upper())}</b>"),
        ]
        try:
            from src.nodes.classify import BENIGN_THRESHOLD, BORDERLINE_MARGIN
            rows.append((
                "Routing rule",
                f"score ≥ {BENIGN_THRESHOLD:g} → investigate · "
                f"&lt; {BENIGN_THRESHOLD - BORDERLINE_MARGIN:g} → benign close"))
        except Exception:
            pass
    else:
        rows = [("Detail", C.esc(detail))]
    return C.kv_table(rows)


def _tool_oneliner(entry: dict) -> str:
    out = entry.get("output")
    if out is None:
        return "invoked — no output captured"
    text = str(out)
    if text.startswith("[") or text.startswith("{"):
        parsed = None
        try:
            import ast
            parsed = ast.literal_eval(text)
        except (ValueError, SyntaxError, TypeError):
            pass
        if isinstance(parsed, list):
            return f"{len(parsed)} result(s)"
        if isinstance(parsed, dict):
            n = parsed.get("reachable_count")
            return (f"{n} reachable assets" if n is not None
                    else f"object · {len(parsed)} keys")
    return C.esc(text.replace("\n", " ")[:90])


def _body_investigate(result: dict) -> str:
    trace = ((result.get("enrichment", {}) or {}).get("tool_trace", []))
    calls = [t for t in trace if t.get("tool") != "_final_answer"]
    parts = []
    if calls:
        lines = "".join(
            f'<div class="tl-mini">#{int(t.get("step", i + 1)):02d} '
            f'<b>{C.esc(t.get("tool", "?"))}</b>'
            f'<span class="arr">→</span>'
            f'{_tool_oneliner(t)}</div>'
            for i, t in enumerate(calls)
        )
        parts.append(f'<div class="tb-k">Tool invocations ({len(calls)})'
                     f'</div>{lines}')
    else:
        parts.append('<div class="tl-mini">No tool invocations recorded — '
                     'agent answered without calling tools.</div>')
    summary = ""
    for ev in reversed(result.get("event_log", []) or []):
        if ev.get("node") == "investigate":
            m = re.search(r"Summary: (.*)$", str(ev.get("detail", "")), re.S)
            if m:
                summary = m.group(1).strip()
            break
    if summary:
        parts.append(f'<div class="tb-k" style="margin-top:.45rem;">Summary'
                     f'</div><div class="tl-mini">{C.esc(summary)}</div>')
    return "".join(parts)


def _body_rca(result: dict) -> str:
    rca = result.get("rca_report", {}) or {}
    techs = rca.get("attack_techniques", []) or []
    ids = ", ".join(f"<span class='tech-id'>{C.esc(t.get('technique_id', '?'))}"
                    f"</span>" for t in techs) or "none"
    guidance = rca.get("containment_actions", []) or []
    rows = [
        ("Techniques mapped", ids),
        ("IoCs in report", str(len(rca.get("ioc_summary", []) or []))),
        ("Overall confidence",
         f"{float(rca.get('overall_confidence', 0) or 0):.0%}"),
        ("Containment guidance", f"{len(guidance)} playbook item(s)"),
        ("Generated at", f"<span class='mono'>"
                         f"{C.esc(str(rca.get('generated_at', ''))[:19])} UTC</span>"),
    ]
    return C.kv_table(rows)


def _body_propose_actions(result: dict) -> str:
    actions = result.get("proposed_actions", []) or []
    if not actions:
        return '<div class="tl-mini">No containment proposals produced.</div>'
    risk_color = {"high": "var(--crit)", "medium": "var(--warn)",
                  "low": "var(--ok)"}
    lines = "".join(
        f'<div class="tl-mini">'
        f'<b>{C.esc(str(a.get("action_type", "?")).replace("_", " ").title())}</b>'
        f'<span class="arr">→</span>{C.esc(a.get("target", "?"))} '
        f'<span style="color:{risk_color.get(str(a.get("risk_level", "")).lower(), "var(--txt-3)")};">'
        f'{C.esc(str(a.get("risk_level", "?")).upper())}</span></div>'
        for a in actions
    )
    return lines


def _body_deploy(result: dict) -> str:
    status = getattr(result.get("final_status"), "value",
                     result.get("final_status")) or "—"
    phase = str(result.get("phase", ""))
    if "." in phase:
        phase = phase.split(".")[-1]
    return C.kv_table([
        ("Final status", C.status_pill(status)),
        ("Phase", f"<span class='mono'>{C.esc(phase)}</span>"),
    ])


_BODY_BUILDERS = {
    "ingest":          lambda ev, res: _body_ingest(res),
    "classify":        lambda ev, res: _body_classify(ev),
    "investigate":     lambda ev, res: _body_investigate(res),
    "rca_generator":   lambda ev, res: _body_rca(res),
    "propose_actions": lambda ev, res: _body_propose_actions(res),
    "deploy":          lambda ev, res: _body_deploy(res),
}


def render(result: dict) -> None:
    event_log = result.get("event_log", []) or []
    if not event_log:
        C.empty_state("No execution events recorded",
                      "The pipeline did not record any events for this run.",
                      ic="clock")
        return

    rows = []
    for ev in event_log:  # appended chronologically by the nodes
        node = str(ev.get("node", "unknown"))
        label = PIPELINE_NODE_LABELS.get(node, node.replace("_", " ").title())
        color = NODE_COLOR.get(node, "var(--txt-3)")
        headline, extra = _headline(ev, result)
        t = _fmt_time(ev.get("timestamp", ""))
        builder = _BODY_BUILDERS.get(node)
        ts_full = C.esc(str(ev.get("timestamp", "")))
        base_rows = [("Node", f"<span class='mono'>{C.esc(node)}</span>"),
                     ("Timestamp", f"<span class='mono'>{ts_full} UTC</span>"),
                     ("Detail", C.esc(str(ev.get("detail", ""))))]
        try:
            body = builder(ev, result) if builder else C.kv_table(base_rows)
        except Exception:
            body = C.kv_table(base_rows)
        rows.append(C.timeline_event(label, color, t, headline, extra, body))

    st.markdown(f'<div class="tl">{"".join(rows)}</div>', unsafe_allow_html=True)

    st.write("")
    with st.expander("Raw execution log"):
        for ev in reversed(event_log):  # newest first for log review
            C.json_details(
                f"{_fmt_time(ev.get('timestamp', ''))} · {ev.get('node', '?')}",
                ev,
            )
