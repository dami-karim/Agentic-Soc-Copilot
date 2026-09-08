"""
Agent Execution view — structured ReAct tool-call trace.

Each invocation is rendered as a clean card: step, tool, parsed input,
parsed result summary, and a collapsible raw payload. Data comes from the
tool trace recorded by parse_investigation_output(); nothing is fabricated.
"""
from __future__ import annotations

import ast

import streamlit as st

from src.ui import components as C
from src.ui.icons import icon


def _parse_py(raw: str):
    """Safely parse str(list|dict) tool outputs; None on failure."""
    try:
        val = ast.literal_eval(raw)
        return val if isinstance(val, (list, dict)) else None
    except (ValueError, SyntaxError, TypeError):
        return None


def _arg_fields(tool: str, args: dict) -> list[tuple[str, str]]:
    if not isinstance(args, dict):
        return [("input", str(args))]
    if tool == "search_logs":
        return [("query", args.get("query", ""))]
    if tool == "query_blast_radius":
        fields = [("host_id", args.get("host_id", ""))]
        if "max_hops" in args:
            fields.append(("max_hops", str(args.get("max_hops"))))
        return fields
    if tool == "search_similar_incidents":
        return [("description", args.get("description", ""))]
    if tool == "search_attack_techniques":
        return [("keywords", args.get("keywords", ""))]
    if tool == "classify_attack_techniques":
        return [("observation", str(args))]
    return [(k, str(v)) for k, v in args.items()]


def _result_summary(tool: str, output: str | None) -> tuple[str, object]:
    """
    Produce a short technical result line + optional parsed payload.
    Returns ("summary text", payload-or-None).
    """
    if output is None:
        return "no output captured", None

    parsed = _parse_py(output)

    if tool == "search_logs":
        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            if "error" in parsed[0]:
                return f"error — {parsed[0]['error'][:80]}", parsed
            hosts = sorted({e.get("host") for e in parsed if e.get("host")})
            codes = sorted({e.get("EventCode") for e in parsed
                            if e.get("EventCode")},
                           key=lambda x: (x is None, x))
            extra = []
            if hosts:
                extra.append(f"hosts: {', '.join(str(h) for h in hosts[:3])}")
            if codes:
                extra.append(f"codes: {', '.join(str(c) for c in codes[:6])}")
            detail = " · ".join(extra)
            return (f"{len(parsed)} matching events"
                    + (f" — {detail}" if detail else "")), parsed
        return "0 matching events", parsed

    if tool == "query_blast_radius":
        if isinstance(parsed, dict):
            n = parsed.get("reachable_count", "?")
            start = parsed.get("start_node", "?")
            hops = parsed.get("max_hops", "?")
            return (f"{n} reachable assets from {start} within {hops} hops",
                    parsed)
        return output[:100], None

    if tool == "search_similar_incidents":
        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            top = parsed[0]
            score = top.get("score")
            sid = top.get("incident_id", top.get("id", "?"))
            pct = f"{float(score):.0%} similarity" if score is not None else ""
            return (f"{len(parsed)} similar incidents — top: {sid} ({pct})"
                    .rstrip(), parsed)
        return "no similar incidents found", parsed

    if tool == "search_attack_techniques":
        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            ids = [t.get("technique_id", "?") for t in parsed[:4]]
            more = "…" if len(parsed) > 4 else ""
            return (f"{len(parsed)} candidate techniques — "
                    f"{', '.join(ids)}{more}", parsed)
        return "no technique matches", parsed

    if tool == "classify_attack_techniques":
        return (output or "")[:140], parsed

    return output[:120], parsed


def _card(step: int, tool: str, args_html: list[tuple[str, str]],
          summary: str, raw_output: str | None) -> str:
    fields = "".join(
        f'<div class="tc-field"><div class="tc-fk">{C.esc(k)}</div>'
        f'<div class="tc-fv">{C.esc(v)}</div></div>'
        for k, v in args_html
    )

    result_block = f'<div class="tc-fv" style="color:var(--txt);">' \
                   f'{C.esc(summary)}</div>'

    raw = ""
    if raw_output:
        raw_text = C.esc(raw_output)
        raw = (
            '<details class="tc-inline-details" style="margin-top:.45rem;">'
            '<summary>Raw output</summary>'
            f'<pre>{raw_text}</pre></details>'
        )

    return f"""
    <div class="tool-card">
      <div class="tc-head">
        <span class="tc-step">#{step}</span>
        <span class="tc-ic" style="color:var(--primary);display:inline-flex;">
          {icon("zap", 13)}</span>
        <span class="tc-name">{C.esc(tool)}</span>
      </div>
      <div class="tc-body">
        {fields}
        <div class="tc-field"><div class="tc-fk">Result</div>{result_block}</div>
        {raw}
      </div>
    </div>"""


def render(result: dict) -> None:
    enrichment = result.get("enrichment", {}) or {}
    trace = enrichment.get("tool_trace") or []

    calls = [t for t in trace if t.get("tool") != "_final_answer"]
    finals = [t for t in trace if t.get("tool") == "_final_answer"]

    if not calls:
        C.callout("No tool trace recorded for this investigation — the agent "
                  "answered without calling tools.", kind="info")
        _render_final(finals)
        _render_flags(result)
        return

    C.section_label("Agent Tool Invocations",
                    f"{len(calls)} calls · ReAct loop")

    for entry in trace:
        tool = str(entry.get("tool", ""))
        if tool == "_final_answer":
            continue
        args_html = _arg_fields(tool, entry.get("args", {}))
        summary, _payload = _result_summary(tool, entry.get("output"))
        st.markdown(_card(int(entry.get("step", 0)), tool, args_html,
                          summary, entry.get("output")),
                    unsafe_allow_html=True)

    _render_final(finals)
    _render_flags(result)


def _render_final(finals: list) -> None:
    if not finals:
        return
    text = str(finals[-1].get("output", "") or "")
    st.markdown(f"""
    <div class="soc-card" style="margin-top:.9rem;">
      <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.5rem;">
        <span style="color:var(--purple);display:inline-flex;"
          >{icon("sparkles", 15)}</span>
        <span style="font-size:13px;font-weight:600;color:var(--txt-2);">
          Agent Assessment</span>
        <span style="font-size:11.5px;color:var(--txt-3);margin-left:.3rem;">
          final answer · unedited</span>
      </div>
      <div style="font-size:14px;line-height:1.7;color:var(--txt);
           white-space:pre-wrap;">{C.esc(text)}</div>
    </div>
    """, unsafe_allow_html=True)


def _render_flags(result: dict) -> None:
    flags = result.get("guardrail_flags", []) or []
    if not flags:
        st.markdown('<div style="display:flex;align-items:center;gap:.45rem;'
                    'font-size:12.5px;color:var(--txt-3);margin-top:.8rem;">'
                    '<span class="svc-dot" style="--dot:var(--ok);"></span>'
                    'Guardrails — no violations detected during this '
                    'investigation.</div>', unsafe_allow_html=True)
        return

    C.section_label("Guardrail Flags", f"{len(flags)} raised")
    for flag in flags:
        level = str(flag.get("level", "warn")).upper()
        node = flag.get("node", "?")
        reason = flag.get("reason", "")
        arg = flag.get("argument", "")
        loc = f"{node}" + (f" · {arg}" if arg else "")
        st.markdown(
            f'<div class="flag-row"><span class="fl">{C.esc(level)}</span>'
            f'<span>{C.esc(loc)} — {C.esc(reason)}</span></div>',
            unsafe_allow_html=True,
        )
