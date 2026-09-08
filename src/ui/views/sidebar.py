"""
Sidebar — product identity, sectioned navigation, live system summary.

Navigation groups (per design spec):
  HOME    Investigations · Alerts · History
  TOOLS   OpenSearch · Knowledge Graph · Incident Memory · MITRE ATT&CK
  SYSTEM  Settings · System Status

The active page gets a subtle highlighted pill. Icons are attached to the
native buttons as CSS-mask pseudo-elements (Streamlit escapes label HTML).
"""
from __future__ import annotations

import streamlit as st

from src.ui import components as C
from src.ui.icons import icon

_NAV = [
    # (key, label, icon)
    ("investigations", "Investigations", "search"),
    ("alerts",         "Alerts",         "alert-triangle"),
    ("fp_filter",      "FP Filter",      "filter"),
    ("history",        "History",        "history"),
    ("tools_opensearch", "OpenSearch",     "database"),
    ("tools_graph",      "Knowledge Graph","network"),
    ("tools_memory",     "Incident Memory","brain"),
    ("tools_attack",     "MITRE ATT&CK",   "book-open"),
    ("settings",       "Settings",       "settings"),
    ("status",         "System Status",  "activity"),
]

_GROUPS = [
    ("Home", ["investigations", "alerts", "fp_filter", "history"]),
    ("Tools", ["tools_opensearch", "tools_graph", "tools_memory",
               "tools_attack"]),
    ("System", ["settings", "status"]),
]


def render() -> None:
    page = st.session_state.get("page", "home")

    with st.sidebar:
        # ── Brand ────────────────────────────────────────────────────
        st.markdown(
            '<div class="side-brand">'
            f'<div class="logo">{icon("shield-check", 19)}</div>'
            '<div>'
            '<div class="nm">SOC Co-Pilot</div>'
            '<div class="sb">Agentic Security Investigation</div>'
            '</div></div>',
            unsafe_allow_html=True,
        )
        st.divider()

        for group, keys in _GROUPS:
            st.markdown(f'<div class="nav-group">{group}</div>',
                        unsafe_allow_html=True)
            for key in keys:
                label, ic = next((l, i) for k, l, i in _NAV if k == key)
                active = page == key
                if st.button(label, key=f"nav_{key}", use_container_width=True):
                    st.session_state["page"] = key
                    if key == "investigations":
                        # entering the workspace fresh keeps last result;
                        # starting a new one resets via its own flow.
                        pass
                    st.rerun()
                C.button_icon(f"nav_{key}", ic, 15,
                              color="var(--primary)" if active
                              else "var(--txt-2)")
                if active:
                    st.markdown(f"""
                    <style>
                    .st-key-nav_{key} button {{
                        background: var(--primary-soft)!important;
                    }}
                    .st-key-nav_{key} button p {{
                        color: var(--primary)!important; font-weight:600!important;
                    }}
                    </style>""", unsafe_allow_html=True)

        # ── Live service summary (real probes) ───────────────────────
        st.markdown('<div class="side-foot"></div>', unsafe_allow_html=True)
        from src.ui.health import get_all_statuses
        statuses = get_all_statuses(st)
        ok = sum(1 for s in statuses if s["status"] in ("online", "loaded"))
        total = len(statuses)
        all_ok = ok == total
        dot = "var(--ok)" if all_ok else "var(--warn)"
        label_txt = "All systems operational" if all_ok \
            else f"{ok} of {total} services online"
        st.markdown(
            f'<div style="display:flex;align-items:center;gap:.45rem;'
            f'padding:.15rem .35rem;font-size:12px;color:var(--txt-3);">'
            f'<span class="svc-dot" style="--dot:{dot};"></span>'
            f'{label_txt}</div>',
            unsafe_allow_html=True)

        cols = st.columns(2)
        with cols[0]:
            if st.button("Probe", key="side_probe", use_container_width=True,
                         help="Re-run live health checks"):
                for k in list(st.session_state.keys()):
                    if str(k).startswith("_health_cache_"):
                        del st.session_state[k]
                st.rerun()
        C.button_icon("side_probe", "refresh", 13)
        with cols[1]:
            theme = st.session_state.get("theme", "light")
            target = "light" if theme == "dark" else "dark"
            lbl = "Light mode" if theme == "dark" else "Dark mode"
            if st.button(lbl, key="side_theme", use_container_width=True):
                st.session_state["theme"] = target
                st.rerun()
        C.button_icon("side_theme", "sun" if theme == "dark" else "moon",
                      13, color="var(--warn)" if theme == "dark"
                      else "var(--primary)")
