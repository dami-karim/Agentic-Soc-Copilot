"""
Top bar — compact global header.

Left: product identity + workspace label + live aggregate service status
(real probes). Right: the Light/Dark theme toggle. Rendered as a two-column
row so the toggle is genuinely right-aligned — no overlay or negative-margin
hacks — with a hairline rule closing the header.
"""
from __future__ import annotations

import streamlit as st

from src.ui import components as C

_PAGE_TITLES = {
    "home":             ("SOC Co-Pilot", "Investigation Console"),
    "investigations":   ("Investigations", "Run and review alert investigations"),
    "alerts":           ("Alerts", "Alert sources ready for investigation"),
    "history":          ("History", "Investigations completed in this session"),
    "tools_opensearch": ("OpenSearch", "Log correlation engine"),
    "tools_graph":      ("Knowledge Graph", "Asset & identity relationships"),
    "tools_memory":     ("Incident Memory", "Vector search over past incidents"),
    "tools_attack":     ("MITRE ATT&CK", "Adversarial tactics & techniques"),
    "settings":         ("Settings", "Workspace configuration"),
    "status":           ("System Status", "Backend service health"),
}


def render(services: list[dict]) -> None:
    page = st.session_state.get("page", "home")
    title, sub = _PAGE_TITLES.get(page, (page.replace("_", " ").title(), ""))

    ok = [s for s in services if s["status"] in ("online", "loaded")]
    all_ok = len(ok) == len(services) and bool(services)
    dot = "var(--ok)" if all_ok else "var(--warn)"
    status_text = "Systems Operational" if all_ok \
        else f"{len(ok)} / {len(services)} systems online"

    left, right = st.columns([9, 1.9], gap="small", vertical_alignment="center")
    with left:
        st.markdown(f"""
        <div class="soc-topbar">
          <div class="tb-title">
            <span class="tb-name">{C.esc(title)}</span>
            <span class="tb-sub">{C.esc(sub)}</span>
          </div>
          <div class="tb-right">
            <span class="svc-item">
              <span class="svc-dot" style="--dot:{dot};"></span>
              {C.esc(status_text)}
            </span>
          </div>
        </div>
        """, unsafe_allow_html=True)

    with right:
        theme = st.session_state.get("theme", "light")
        target = "light" if theme == "dark" else "dark"
        ic = "sun" if theme == "dark" else "moon"
        lbl = "Light" if theme == "dark" else "Dark"
        if st.button(lbl, key="topbar_theme_toggle"):
            st.session_state["theme"] = target
            st.rerun()
        C.button_icon("topbar_theme_toggle", ic, 14, color="currentColor",
                      hover_color=None)

    st.markdown('<div class="topbar-rule"></div>', unsafe_allow_html=True)
