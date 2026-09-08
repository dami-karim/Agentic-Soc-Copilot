"""
Investigation workspace — result presentation for a completed run.

Structure:
  · Hero header  (Investigation Complete · host · EventCode · status pills)
  · Compact metric cards (Triage Score / Confidence / ATT&CK / IoCs)
  · Human-readable Investigation Summary card (composed from real state,
    never raw dicts)
  · Tabbed workspace: Timeline · Evidence · Agent Execution · Root Cause ·
    Recommended Actions

While a run is executing, renders a calm progress panel instead.
"""
from __future__ import annotations

import re

import streamlit as st

from src.ui import components as C
from src.ui.data import EVENTCODE_DESCRIPTIONS
from src.ui.icons import icon


# ── helpers ───────────────────────────────────────────────────────────────────


def _classify_route(result: dict) -> str:
    """Extract routing decision recorded by classify_node."""
    for ev in result.get("event_log", []) or []:
        if ev.get("node") == "classify":
            m = re.search(r"route=(\S+)", str(ev.get("detail", "")))
            if m:
                return m.group(1).lower()
    return ""


def _incident_id(result: dict) -> str:
    wid = str(result.get("workflow_id", ""))
    return f"INC-{wid.replace('-', '')[:8].upper()}" if wid else "INC"


def _n_tool_calls(result: dict) -> int:
    trace = ((result.get("enrichment", {}) or {}).get("tool_trace", [])) or []
    return len([t for t in trace if t.get("tool") != "_final_answer"])


def build_summary(result: dict) -> str:
    """
    Compose a human-readable narrative strictly from real state values.
    No dictionaries dumped; missing pieces are simply omitted.
    """
    alert = result.get("alert_raw", {}) or {}
    rca = result.get("rca_report", {}) or {}
    techniques = result.get("attack_techniques", []) or []
    iocs = result.get("ioc_list", []) or []
    actions = result.get("proposed_actions", []) or []
    enrichment = result.get("enrichment", {}) or {}
    trace = enrichment.get("tool_trace", []) or []
    blast = result.get("blast_radius", {}) or {}

    host = alert.get("host", "an unknown host")
    user = alert.get("user")
    ec = str(alert.get("EventCode", "") or "")
    ec_desc = EVENTCODE_DESCRIPTIONS.get(ec)
    sev = str(result.get("severity") or "unknown").lower()
    score = float(result.get("triage_score", 0) or 0)

    sents: list[str] = []

    # Sentence 1 — what the alert observed
    sig = str(alert.get("signature") or "").strip()
    lead = ""
    if ec == "4698":
        lead = f"A scheduled task was created on {host}"
    elif ec == "4625":
        lead = f"Repeated failed logons were recorded against {host}"
    elif ec == "4624":
        lead = f"A network logon was recorded on {host}"
    elif ec == "4688":
        lead = f"A new process was executed on {host}"
    elif ec == "4634":
        lead = f"An account logged off from {host}"
    else:
        lead = f"A security event was raised on {host}"
    if ec_desc:
        lead += f" (EventCode {ec} — {ec_desc})"
    elif ec:
        lead += f" (EventCode {ec})"
    if user:
        lead += f" involving account “{user}”"
    lead += "."
    if sig:
        lead += f' The SIEM signature reads: “{sig}”'
        lead = lead.rstrip(".") + "."
    sents.append(lead)

    # Sentence 2 — classification outcome
    route = _classify_route(result)
    if route == "benign" or score < 25:
        sents.append(f"Triage assessed this activity as benign with a score "
                     f"of {score:g}/100, so the investigation was closed "
                     f"without escalation.")
    else:
        sents.append(f"The classifier rated the activity {sev} with a triage "
                     f"score of {score:g}/100 and routed it to full "
                     f"investigation.")

    # Sentence 3 — what the agent gathered
    n_calls = _n_tool_calls(result)
    logs = None
    import ast
    try:
        raw = enrichment.get("log_search")
        parsed = ast.literal_eval(raw) if isinstance(raw, str) and raw else raw
        if isinstance(parsed, list):
            logs = len(parsed)
    except Exception:
        logs = None
    ev_bits: list[str] = []
    if logs:
        ev_bits.append(f"retrieved {logs} correlated log event"
                       f"{'s' if logs != 1 else ''} from OpenSearch")
    if techniques:
        top = max(techniques, key=lambda t: float(t.get("confidence", 0) or 0))
        tid = top.get("technique_id", "")
        tname = top.get("technique_name", "")
        more = (f" plus {len(techniques) - 1} other technique"
                f"{'s' if len(techniques) > 2 else ''}"
                if len(techniques) > 1 else "")
        ev_bits.append(f"mapped the behavior to MITRE ATT&amp;CK "
                       f"<span class='mono'>{C.esc(tid)}</span> ({C.esc(tname)}"
                       f"{more})")
    if iocs:
        vals = ", ".join(f"<span class='mono'>{C.esc(i.get('value'))}</span>"
                         for i in iocs[:3])
        extra = f" and {len(iocs) - 3} more" if len(iocs) > 3 else ""
        ev_bits.append(f"identified {len(iocs)} indicator"
                       f"{'s' if len(iocs) != 1 else ''} of compromise "
                       f"({vals}{extra})")
    if isinstance(blast, dict) and blast.get("reachable_count"):
        ev_bits.append(f"{blast['reachable_count']} assets are reachable in "
                       f"the knowledge graph from "
                       f"<span class='mono'>{C.esc(blast.get('start_node', '?'))}</span>")
    if ev_bits:
        lead = ("During evidence analysis the agent "
                f"made {n_calls} tool call{'s' if n_calls != 1 else ''} — "
                if n_calls else "During evidence analysis the agent ")
        sents.append(lead + "; ".join(ev_bits) + ".")
    elif n_calls:
        sents.append(f"During evidence analysis the agent made {n_calls} tool "
                     f"call{'s' if n_calls != 1 else ''} but did not surface "
                     f"additional structured findings.")

    # Sentence 4 — RCA + confidence
    conf = float(rca.get("overall_confidence", 0) or 0)
    if rca:
        root = ""
        techs = rca.get("attack_techniques", []) or []
        if ec == "4698" and techs:
            root = ("Correlated evidence suggests potential persistence "
                    "activity through a Windows scheduled task.")
        sents.append(
            f"Root-cause analysis completed with {conf:.0%} confidence."
            + (f" {root}" if root else "")
            + (f" {len(actions)} containment action"
               f"{'s' if len(actions) != 1 else ''} proposed for analyst review."
               if actions else ""))

    return " ".join(sents)


# ── main render ───────────────────────────────────────────────────────────────


def render_running() -> None:
    st.markdown("""
    <div class="empty-state">
      <div class="eic">%s</div>
      <div class="et">Investigation in progress…</div>
      <div class="eh">The agentic pipeline is ingesting the alert, classifying
      it, gathering evidence and preparing root-cause analysis.</div>
    </div>
    """ % icon("activity", 24), unsafe_allow_html=True)
    st.markdown(C.pipeline_diagram(["ingest", "classify", "investigate",
                                    "root cause", "propose actions"]),
                unsafe_allow_html=True)


def render(result: dict) -> None:
    alert = result.get("alert_raw", {}) or {}
    rca = result.get("rca_report", {}) or {}
    techniques = result.get("attack_techniques", []) or []
    iocs = result.get("ioc_list", []) or []
    actions = result.get("proposed_actions", []) or []

    severity = str(result.get("severity") or alert.get("severity")
                   or "unknown").lower()
    accent = C.SEVERITY_COLOR.get(severity, "var(--txt-3)")
    final_status = getattr(result.get("final_status"), "value",
                           result.get("final_status"))
    benign_close = str(final_status).lower() in ("completed_benign", "aborted")

    ec = str(alert.get("EventCode", "") or "—")
    host = alert.get("host") or "Unknown host"

    # ── Header ───────────────────────────────────────────────────────
    chips = [f'<span class="chip">HOST <b>{C.esc(host)}</b></span>',
             f'<span class="chip">EC <b>{C.esc(ec)}</b></span>']
    if alert.get("user"):
        chips.append(f'<span class="chip">USER <b>{C.esc(alert["user"])}</b></span>')
    if alert.get("src_ip"):
        chips.append(f'<span class="chip">SRC <b>{C.esc(alert["src_ip"])}</b></span>')
    route = _classify_route(result)
    if route:
        rc = "var(--crit)" if route == "malicious" else "var(--ok)"
        chips.append(f'<span class="chip">ROUTE <b style="color:{rc};">'
                     f'{C.esc(route.upper())}</b></span>')
    chips.append(f'<span class="chip">{C.esc(_incident_id(result))}</span>')

    status_html = C.status_pill(final_status)
    sev_html = C.severity_pill(severity)
    kicker = "Closed as benign" if benign_close else "Investigation complete"

    st.markdown(f"""
    <div class="inc-hero">
      <div style="display:flex;justify-content:space-between;gap:1rem;
                  align-items:flex-start;flex-wrap:wrap;">
        <div style="min-width:0;">
          <div class="kicker"><span style="color:{accent};display:inline-flex;">
          {icon("shield-check", 14)}</span>{C.esc(kicker)}</div>
          <h2>{C.esc(host)}
            <span style="color:var(--txt-3);font-weight:500;">·</span>
            <span style="font-weight:600;">EventCode {C.esc(ec)}</span></h2>
          <div class="inc-chips">{"".join(chips)}</div>
        </div>
        <div class="inc-right">
          <div style="display:flex;gap:.45rem;flex-wrap:wrap;
                      justify-content:flex-end;">
            {status_html}
            {sev_html}
          </div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Metrics ──────────────────────────────────────────────────────
    conf = float(rca.get("overall_confidence", 0) or 0)
    C.metric_cards([
        {"k": "Triage Score", "v": f"{float(result.get('triage_score', 0) or 0):g}",
         "u": "/ 100", "c": accent},
        {"k": "Confidence", "v": f"{min(conf, 1) * 100:.0f}", "u": "%"} if rca
        else {"k": "Confidence", "v": "—"},
        {"k": "ATT&CK Techniques", "v": len(techniques)},
        {"k": "IoCs", "v": len(iocs)},
        {"k": "Actions Proposed", "v": len(actions)},
        {"k": "Tool Calls", "v": _n_tool_calls(result), "small": True},
    ])

    # ── Summary ──────────────────────────────────────────────────────
    st.markdown(f"""
    <div class="soc-card" style="margin-top:.35rem;">
      <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.5rem;">
        <span style="color:var(--purple);display:inline-flex;"
          >{icon("sparkles", 16)}</span>
        <span style="font-size:13px;font-weight:600;color:var(--txt-2);
              letter-spacing:.02em;">Investigation Summary</span>
        <span style="font-size:11.5px;color:var(--txt-3);margin-left:.35rem;"
          >AI-generated from live pipeline findings</span>
      </div>
      <div style="font-size:15px;line-height:1.7;color:var(--txt);">
        {build_summary(result)}</div>
    </div>
    """, unsafe_allow_html=True)

    # ── Workspace tabs ───────────────────────────────────────────────
    st.markdown('<div style="height:.4rem;"></div>', unsafe_allow_html=True)
    from src.ui.views import actions as actions_view
    from src.ui.views import agent_exec, evidence, rca, timeline
    rca_view = rca

    tabs = st.tabs(["Timeline", "Evidence", "Agent Execution",
                    "Root Cause", "Actions"])
    with tabs[0]:
        timeline.render(result)
    with tabs[1]:
        evidence.render(result)
    with tabs[2]:
        agent_exec.render(result)
    with tabs[3]:
        rca_view.render(result)
        st.markdown("")
        C.section_label("Raw Alert", "initial signal · unmodified")
        C.json_details("alert_raw payload", result.get("alert_raw", {}))
    with tabs[4]:
        actions_view.render(result)
