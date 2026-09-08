"""
History — investigations completed during this session.

Every entry is a real pipeline run captured when it finished. Clicking an
entry reloads its full result into the Investigations workspace.
"""
from __future__ import annotations

from datetime import datetime

import streamlit as st

from src.ui import components as C
from src.ui.icons import icon


def record(result: dict) -> None:
    """Append a finished run to the session history (called by app shell)."""
    alert = result.get("alert_raw", {}) or {}
    entry = {
        "ts": datetime.now().strftime("%H:%M:%S"),
        "host": str(alert.get("host", "?")),
        "ec": str(alert.get("EventCode", "?")),
        "severity": str(result.get("severity") or "unknown"),
        "score": float(result.get("triage_score", 0) or 0),
        "result": result,
    }
    hist: list = st.session_state.setdefault("history", [])
    hist.append(entry)


def render() -> None:
    history: list = st.session_state.get("history", [])
    if not history:
        C.empty_state(
            "No investigations yet",
            "Runs you complete in this session will be listed here with "
            "their outcomes, ready to reopen at any time.",
            ic="history",
            stages=["run an investigation", "→", "history"])
        return

    C.section_label("This Session",
                    f"{len(history)} investigation"
                    f"{'s' if len(history) != 1 else ''} completed")

    for idx, h in enumerate(reversed(history)):
        real_idx = len(history) - 1 - idx
        r = h["result"]
        status_html = C.status_pill(r.get("final_status"))
        sev_html = C.severity_pill(h["severity"])
        techniques = len(r.get("attack_techniques", []) or [])
        iocs = len(r.get("ioc_list", []) or [])

        st.markdown(f"""
        <div class="soc-card" style="padding:.8rem 1.1rem;margin-bottom:.6rem;">
          <div style="display:flex;align-items:center;gap:.9rem;flex-wrap:wrap;">
            <span class="mono" style="font-size:12px;color:var(--txt-3);
                  min-width:64px;">{C.esc(h["ts"])}</span>
            <span style="font-size:14px;font-weight:600;color:var(--txt);"
              >{C.esc(h["host"])}</span>
            <span class="chip">EC <b>{C.esc(h["ec"])}</b></span>
            {sev_html}
            {status_html}
            <span style="margin-left:auto;display:flex;gap:1.1rem;
                  font-size:12px;color:var(--txt-3);">
              <span>Score <b style="color:var(--txt);" class="mono"
                >{h["score"]:g}</b></span>
              <span>ATT&amp;CK <b style="color:var(--txt);" class="mono"
                >{techniques}</b></span>
              <span>IoCs <b style="color:var(--txt);" class="mono"
                >{iocs}</b></span>
            </span>
          </div>
        </div>
        """, unsafe_allow_html=True)

        b1, _ = st.columns([1.4, 6])
        with b1:
            if st.button("Open", key=f"hist_open_{real_idx}",
                         use_container_width=True):
                st.session_state["result"] = r
                st.session_state["page"] = "investigations"
                st.rerun()
        C.button_icon(f"hist_open_{real_idx}", "eye", 13)
