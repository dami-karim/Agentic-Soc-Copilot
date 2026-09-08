"""
Alerts — alert sources ready for investigation.

Shows the documented demo scenarios (real input payloads used by the
pipeline) and the alerts already investigated in this session. The
"Investigate" action preselects a template on the Investigations page.
"""
from __future__ import annotations

import streamlit as st

from src.ui import components as C
from src.ui.data import ALERT_TEMPLATES
from src.ui.icons import icon


def render() -> None:
    C.section_label("Alert Templates",
                    "pre-built SIEM scenarios · payloads identical to the "
                    "documented demo cases")

    cols = st.columns(2, gap="medium")
    for i, t in enumerate(ALERT_TEMPLATES):
        with cols[i % 2]:
            st.markdown(f"""
            <div class="tpl-card">
              <div class="tpl-top">
                <div><div class="tpl-title">{C.esc(t.title)}</div></div>
                <span class="chip">EventCode <b>{C.esc(t.eventcode)}</b></span>
              </div>
              <div class="tpl-desc">{C.esc(t.description)}</div>
              <div class="tpl-foot">
                <span style="display:flex;gap:.45rem;align-items:center;">
                  <span class="tech-id">{C.esc(t.tag)}</span>
                  {C.severity_pill(str(t.payload.get("severity", "unknown")))}
                </span>
                <span style="color:var(--txt-3);display:inline-flex;">
                  {t.icon_html(16)}</span>
              </div>
            </div>
            """, unsafe_allow_html=True)
            b1, _ = st.columns([1.5, 5])
            with b1:
                if st.button("Investigate", key=f"alert_inv_{t.key}",
                             use_container_width=True):
                    st.session_state["inv_mode"] = "template"
                    st.session_state["selected_template"] = t.key
                    st.session_state["result"] = None
                    st.session_state["page"] = "investigations"
                    st.rerun()

    # Session's investigated alerts
    history: list = st.session_state.get("history", [])
    if history:
        C.section_label("Investigated This Session", f"{len(history)} alerts")
        rows = []
        for h in reversed(history[-8:]):
            sev = str(h["severity"]).lower()
            color = C.SEVERITY_COLOR.get(sev, "var(--txt-3)")
            rows.append(
                f'<div style="display:flex;align-items:center;gap:.6rem;'
                f'padding:.42rem .1rem;border-bottom:1px solid var(--border);'
                f'font-size:13.5px;">'
                f'<span class="svc-dot" style="--dot:{color};"></span>'
                f'<span class="mono" style="min-width:96px;color:var(--txt);">'
                f'{C.esc(h["host"])}</span>'
                f'<span class="chip">EC {C.esc(h["ec"])}</span>'
                f'<span class="mono" style="margin-left:auto;font-size:11.5px;'
                f'color:var(--txt-3);">{C.esc(h["ts"])}</span></div>'
            )
        st.markdown("".join(rows), unsafe_allow_html=True)
