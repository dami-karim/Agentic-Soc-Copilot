"""
Root-Cause Analysis — a professional security-report layout.

Sections: What happened? · Evidence · Likely attack technique ·
Root cause · Confidence. Typography and whitespace carry the hierarchy;
content is composed strictly from the real rca_report produced by the
rca_generator node.
"""
from __future__ import annotations

import streamlit as st

from src.ui import components as C
from src.ui.data import EVENTCODE_DESCRIPTIONS


def _sec(title: str, body_html: str, meta: str = "", plain: bool = False) -> None:
    m = (f'<span style="font-family:var(--mono);font-size:11px;'
         f'color:var(--txt-3);">{C.esc(meta)}</span>') if meta else ""
    cls = "rs-body plain" if plain else "rs-body"
    st.markdown(f"""
    <div class="rca-sec">
      <div class="rs-head"><span>{C.esc(title)}</span>{m}</div>
      <div class="{cls}">{body_html}</div>
    </div>""", unsafe_allow_html=True)


def _what_happened(result: dict) -> str:
    """Narrative paragraph built from the real alert + RCA summary.

    ``build_summary`` already escapes every interpolated value and emits a
    few safe <span> wrappers for monospace technical tokens.
    """
    from src.ui.views.investigation import build_summary
    return build_summary(result)


def render(result: dict) -> None:
    alert = result.get("alert_raw", {}) or {}
    rca = result.get("rca_report", {}) or {}

    if not rca:
        C.empty_state(
            "No root-cause report",
            "RCA is generated for alerts that pass the classification "
            "threshold and complete investigation.",
            ic="file-text",
            stages=["classify", "investigate", "rca_generator"])
        return

    conf = float(rca.get("overall_confidence", 0) or 0)
    triage = float(rca.get("triage_score", 0) or 0)

    # ── What happened? ───────────────────────────────────────────
    _sec("What happened?", _what_happened(result),
         meta=f"generated {str(rca.get('generated_at', ''))[:19].replace('T', ' ')} UTC")

    # ── Evidence ─────────────────────────────────────────────────
    iocs = rca.get("ioc_summary", []) or []
    techs = rca.get("attack_techniques", []) or []
    br = rca.get("blast_radius", {}) or {}
    ev_bits = []
    if iocs:
        vals = ", ".join(f"<span class='mono' style='color:var(--txt);'>"
                         f"{C.esc(i.get('value'))}</span>"
                         for i in iocs[:6])
        more = (f" <span style='color:var(--txt-3);'>+{len(iocs) - 6} more</span>"
                if len(iocs) > 6 else "")
        ev_bits.append(f"<b>{len(iocs)} IoCs</b> — {vals}{more}")
    if techs:
        tids = ", ".join(f"<span class='tech-id'>"
                         f"{C.esc(t.get('technique_id', '?'))}</span>"
                         for t in techs)
        ev_bits.append(f"<b>{len(techs)} ATT&amp;CK technique"
                       f"{'s' if len(techs) != 1 else ''}</b> — {tids}")
    if br.get("reachable_count"):
        ev_bits.append(
            f"<b>{br['reachable_count']} reachable assets</b> in the knowledge "
            f"graph from <span class='mono'>{C.esc(str(br.get('start_node', '?')))}"
            f"</span> (≤ {C.esc(str(br.get('max_hops', '?')))} hops)")
    evidence_html = (
        "<ul style='margin:.05rem 0 .05rem 1.15rem;padding:0;'>"
        + "".join(f"<li style='margin:.3rem 0;'>{b}</li>" for b in ev_bits)
        + "</ul>") if ev_bits else \
        "<span style='color:var(--txt-3);'>No correlated evidence recorded.</span>"
    _sec("Evidence", evidence_html)

    # ── Likely attack technique ──────────────────────────────────
    if techs:
        top = max(techs, key=lambda t: float(t.get("confidence", 0) or 0))
        tid = top.get("technique_id", "T????")
        tname = top.get("technique_name", "Unknown")
        tconf = float(top.get("confidence", 0) or 0)
        others = len(techs) - 1
        meta = f"primary of {len(techs)} mapped" if others > 0 \
            else "single technique mapped"
        body = (
            f'<div style="display:flex;align-items:center;gap:.7rem;'
            f'flex-wrap:wrap;">'
            f'<span class="tech-id">{C.esc(tid)}</span>'
            f'<span style="font-size:14.5px;font-weight:600;">'
            f'{C.esc(tname)}</span>'
            f'{C.conf_badge(tconf)}</div>'
        )
        if top.get("rationale"):
            body += (f'<div style="margin-top:.55rem;color:var(--txt-2);'
                     f'font-size:13.5px;line-height:1.6;">'
                     f'{C.esc(C.clean_text(top["rationale"]))}</div>')
        _sec("Likely attack technique", body, meta=meta)

    # ── Root cause ───────────────────────────────────────────────
    root_bits = []
    ec = str(alert.get("EventCode", ""))
    ec_desc = EVENTCODE_DESCRIPTIONS.get(ec, "")
    if ec_desc:
        root_bits.append(f"The triggering telemetry is <b>Windows Event "
                         f"{C.esc(ec)}</b> ({C.esc(ec_desc).lower()}) on "
                         f"<span class='mono'>{C.esc(alert.get('host', '?'))}</span>.")
    if techs:
        tactics = ", ".join(sorted({t.get("tactic", "") for t in techs
                                    if t.get("tactic")}))
        primary = max(techs, key=lambda t: float(t.get("confidence", 0) or 0))
        root_bits.append(
            f"The behavior is best explained by <b>{C.esc(primary.get('technique_name', ''))}</b> "
            f"(<span class='mono'>{C.esc(primary.get('technique_id', ''))}</span>)"
            + (f" within the <b>{C.esc(tactics)}</b> tactic"
               f"{'s' if ',' in tactics else ''}" if tactics else "")
            + ".")
    guidance = rca.get("containment_actions", []) or []
    summary_txt = str(rca.get("summary", "")).strip()
    if summary_txt:
        root_bits.append(C.esc(summary_txt))
    root_html = (" ".join(f"<p style='margin:.25rem 0;'>{b}</p>"
                          for b in root_bits)) or \
        "<span style='color:var(--txt-3);'>No root-cause narrative recorded.</span>"
    _sec("Root cause", root_html)

    # ── Containment guidance ─────────────────────────────────────
    if guidance:
        items = "".join(
            f"<li style='margin:.35rem 0;'>{C.esc(g)}</li>" for g in guidance)
        _sec("Containment guidance",
             f"<ol style='margin:.05rem 0 .05rem 1.2rem;padding:0;'>{items}</ol>",
             meta="tactic-mapped playbooks")

    # ── Confidence ───────────────────────────────────────────────
    st.markdown("""
    <div class="soc-card" style="display:flex;align-items:center;gap:1.4rem;
         flex-wrap:wrap;margin-top:.4rem;">
      <div style="min-width:150px;">
        <div class="mk" style="font-size:11px;font-weight:600;
             letter-spacing:.06em;color:var(--txt-3);text-transform:uppercase;">
          Overall confidence</div>
        <div style="font-size:26px;font-weight:700;color:var(--txt);
             font-family:var(--mono);" >%d%%</div>
      </div>
      <div style="flex:1;min-width:220px;">
        %s
        <div style="font-size:12px;color:var(--txt-3);margin-top:.3rem;">
          Weighted from the confidence of every mapped ATT&CK technique.</div>
      </div>
    </div>
    """ % (round(conf * 100), _confidence_bar(conf)), unsafe_allow_html=True)

    st.markdown('<div style="height:.5rem;"></div>', unsafe_allow_html=True)
    badges = (
        f"{C.pill(f'Triage {triage:g}', 'var(--warn)')} "
        f"{C.severity_pill(str(rca.get('severity') or result.get('severity') or 'unknown'))} "
        f"{C.pill(str(alert.get('host', '?')), 'var(--primary)')}"
    )
    st.markdown(badges, unsafe_allow_html=True)

    # ── Report metadata drill-down ───────────────────────────────
    with st.expander("Report metadata"):
        rows = [
            ("alert_id", f"<span class='mono'>{C.esc(rca.get('alert_id', ''))}</span>"),
            ("workflow_id", f"<span class='mono'>{C.esc(rca.get('workflow_id', ''))}</span>"),
        ]
        st.markdown(C.kv_table(rows), unsafe_allow_html=True)


def _confidence_bar(v: float) -> str:
    pct = max(0, min(100, v * 100))
    color = "var(--ok)" if pct >= 70 else ("var(--warn)" if pct >= 40
                                           else "var(--crit)")
    return (
        '<div style="height:8px;border-radius:999px;background:var(--card-3);'
        'overflow:hidden;">'
        f'<div style="height:100%;width:{pct:g}%;border-radius:999px;'
        f'background:{color};"></div></div>'
    )
