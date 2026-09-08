"""
Home — welcoming dashboard.

Time-aware greeting, a prominent New Investigation action, and three
compact cards (Active Investigations · Recent Alerts · System Status).
Everything shown is real: session investigation history and live service
probes. Nothing is mocked.
"""
from __future__ import annotations

import streamlit as st

from src.ui import components as C
from src.ui.icons import icon


def _greeting() -> str:
    h = st.session_state.get("_local_hour")
    if h is None:
        from datetime import datetime
        h = datetime.now().hour
    if 5 <= h < 12:
        return "Good morning"
    if 12 <= h < 18:
        return "Good afternoon"
    return "Good evening"


def render() -> None:
    # ── Hero ─────────────────────────────────────────────────────
    st.markdown(f"""
    <div class="hero">
      <h1>{C.esc(_greeting())}, Analyst</h1>
      <div class="hero-sub">Investigate security alerts with AI-assisted analysis,
      evidence correlation, and root-cause reasoning.</div>
    </div>
    """, unsafe_allow_html=True)

    b1, _ = st.columns([2, 6])
    with b1:
        if st.button("New Investigation",
                     key="home_new_inv", type="primary"):
            st.session_state["page"] = "investigations"
            st.rerun()
    C.button_icon("home_new_inv", "plus", 15, color="currentColor",
                  hover_color=None)

    history: list[dict] = st.session_state.get("history", [])
    result = st.session_state.get("result")

    # ── Compact overview cards ───────────────────────────────────
    c1, c2, c3 = st.columns(3, gap="medium")

    with c1:
        st.markdown(
            '<div class="soc-card" style="min-height:190px;">'
            '<div class="tb-name" style="font-size:12px;font-weight:600;'
            'letter-spacing:.06em;text-transform:uppercase;color:var(--txt-3);'
            'margin-bottom:.7rem;display:flex;align-items:center;gap:.45rem;">'
            f'{icon("activity", 14)} Active investigations</div>',
            unsafe_allow_html=True,
        )
        if result is not None:
            alert = result.get("alert_raw", {}) or {}
            host = alert.get("host", "?")
            ec = str(alert.get("EventCode", "?"))
            st.markdown(
                f'<div style="font-size:14px;color:var(--txt);">'
                f'<b>{C.esc(host)}</b> · EC {C.esc(ec)}</div>'
                f'<div style="font-size:13px;color:var(--txt-3);'
                f'margin-top:.25rem;">{C.status_pill(result.get("final_status"))}'
                f' &nbsp;{C.severity_pill(str(result.get("severity") or "unknown"))}</div>',
                unsafe_allow_html=True,
            )
            if st.button("Open result", key="home_open_result",
                         use_container_width=True):
                st.session_state["page"] = "investigations"
                st.rerun()
        elif history:
            last = history[-1]
            r = last["result"]
            st.markdown(
                f'<div style="font-size:13.5px;color:var(--txt-2);">Last run: '
                f'<b style="color:var(--txt);">{C.esc(last["host"])}</b> · '
                f'EC {C.esc(last["ec"])}</div>'
                f'<div style="margin-top:.35rem;">{C.status_pill(r.get("final_status"))}</div>',
                unsafe_allow_html=True,
            )
            if st.button("Review last result", key="home_last_result",
                         use_container_width=True):
                st.session_state["result"] = last["result"]
                st.session_state["page"] = "investigations"
                st.rerun()
        else:
            st.markdown(
                '<div style="font-size:13.5px;color:var(--txt-3);line-height:1.55;">'
                'No investigation is currently active. Start one to see live '
                'triage results here.</div>',
                unsafe_allow_html=True,
            )
        st.markdown("</div>", unsafe_allow_html=True)

    with c2:
        st.markdown(
            '<div class="soc-card" style="min-height:190px;">'
            '<div class="tb-name" style="font-size:12px;font-weight:600;'
            'letter-spacing:.06em;text-transform:uppercase;color:var(--txt-3);'
            'margin-bottom:.7rem;display:flex;align-items:center;gap:.45rem;">'
            f'{icon("alert-triangle", 14)} Recent alerts</div>',
            unsafe_allow_html=True,
        )
        if history:
            rows = []
            for h in reversed(history[-4:]):
                sev = str(h["severity"]).lower()
                color = C.SEVERITY_COLOR.get(sev, "var(--txt-3)")
                rows.append(
                    f'<div style="display:flex;align-items:center;gap:.55rem;'
                    f'padding:.28rem 0;border-bottom:1px solid var(--border);'
                    f'font-size:13px;">'
                    f'<span class="svc-dot" style="--dot:{color};"></span>'
                    f'<span class="mono" style="color:var(--txt);">{C.esc(h["host"])}</span>'
                    f'<span class="chip">EC {C.esc(h["ec"])}</span>'
                    f'<span style="margin-left:auto;color:var(--txt-3);'
                    f'font-size:11.5px;" class="mono">{C.esc(h["ts"])}</span></div>'
                )
            st.markdown("".join(rows), unsafe_allow_html=True)
        else:
            st.markdown(
                '<div style="font-size:13.5px;color:var(--txt-3);line-height:1.55;">'
                'Alerts you investigate will appear here for quick access.</div>',
                unsafe_allow_html=True,
            )
        st.markdown("</div>", unsafe_allow_html=True)

    with c3:
        from src.ui.health import get_all_statuses
        services = get_all_statuses(st)
        ok = sum(1 for s in services if s["status"] in ("online", "loaded"))
        all_ok = ok == len(services)
        head_color = "var(--ok)" if all_ok else "var(--warn)"
        st.markdown(
            '<div class="soc-card" style="min-height:190px;">'
            '<div style="display:flex;align-items:center;justify-content:'
            'space-between;margin-bottom:.7rem;">'
            '<div style="font-size:12px;font-weight:600;letter-spacing:.06em;'
            'text-transform:uppercase;color:var(--txt-3);display:flex;'
            f'align-items:center;gap:.45rem;">{icon("server", 14)} System status</div>'
            f'<span class="svc-dot" style="--dot:{head_color};"></span></div>',
            unsafe_allow_html=True,
        )
        dots = "".join(
            f'<div style="padding:.22rem 0;">{C.svc_dot(s["label"], s["status"], "")}</div>'
            for s in services
        )
        st.markdown(
            f'<div style="font-size:13px;color:var(--txt-2);">{dots}</div>',
            unsafe_allow_html=True,
        )
        if st.button("Details", key="home_status_details",
                     use_container_width=True):
            st.session_state["page"] = "status"
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

    # ── How the pipeline works ───────────────────────────────────
    st.markdown('<div style="height:.9rem;"></div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="soc-card" style="background:var(--card-2);box-shadow:none;">'
        '<div style="display:flex;align-items:center;justify-content:space-between;'
        'flex-wrap:wrap;gap:.8rem;">'
        '<div style="max-width:560px;">'
        '<div class="choice-title">How an investigation works</div>'
        '<div class="choice-desc">Each alert flows through an agentic pipeline: '
        'ingest, classify, tool-assisted evidence gathering, root-cause '
        'analysis, and action proposals — with analyst approval gates on '
        'high-risk response steps.</div></div>'
        + C.pipeline_diagram(["ingest", "classify", "investigate",
                              "root cause", "propose actions"])
        + "</div></div>",
        unsafe_allow_html=True,
    )
