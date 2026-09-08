"""
Settings — workspace configuration.

Real settings that affect behavior: theme, HIL auto-approve mode.
Read-only environment facts: tenant/model/thresholds from load_config().
"""
from __future__ import annotations

import streamlit as st

from src.config import load_config
from src.ui import components as C
from src.ui.icons import icon


def render() -> None:
    c1, c2 = st.columns(2, gap="large")

    with c1:
        st.markdown('<div class="sec-label" style="margin-top:.2rem;">'
                    '<span class="t">Appearance</span></div>',
                    unsafe_allow_html=True)
        st.markdown('<div class="soc-card">', unsafe_allow_html=True)
        theme = st.session_state.get("theme", "dark")
        pick = st.radio("Theme", ["light", "dark"], index=1 if theme == "dark" else 0,
                        horizontal=True,
                        format_func=str.title,
                        help="Applies instantly and persists for this session.")
        if pick != theme:
            st.session_state["theme"] = pick
            st.rerun()

        auto = st.checkbox(
            "Auto-approve HIL gates (demo mode)",
            value=not st.session_state.get("hil_enabled", True),
            help="The pipeline is built non-interactively (with_hil=False); "
                 "analyst gates are recorded as auto-approved. Disabling "
                 "this simply surfaces approval prompts in the Actions tab "
                 "of the result view.",
            key="settings_hil",
        )
        st.session_state["hil_enabled"] = not auto

        if auto:
            C.callout("<b>Demo mode active</b> — actions are simulated and "
                      "no destructive action will be executed.",
                      kind="warning", ic="lock")
        else:
            C.callout("Analyst review is emphasised across the interface; "
                      "high-risk actions require explicit approval.",
                      kind="info", ic="shield-check")
        st.markdown("</div>", unsafe_allow_html=True)

    with c2:
        st.markdown('<div class="sec-label" style="margin-top:.2rem;">'
                    '<span class="t">Workspace</span></div>',
                    unsafe_allow_html=True)
        org_id = st.text_input("Tenant ID", value=st.session_state.get("org_id", "default"),
                               key="settings_org")
        config = load_config(org_id)
        model = config.get("model", {})
        rows = C.kv_table([
            ("Tenant", f"<b>{C.esc(config.get('org_name', org_id))}</b>"),
            ("Model", f"<span class='mono'>{C.esc(model.get('model', '?'))}</span>"
                      f" &nbsp;<span style='color:var(--txt-3);'>"
                      f"{C.esc(model.get('provider', '?'))}</span>"),
            ("Endpoint", f"<span class='mono'>{C.esc(model.get('base_url', '?'))}</span>"),
            ("Benign threshold", f"<span class='mono'>"
                                 f"{config.get('benign_threshold', 30):g}</span>"),
            ("Borderline margin", f"<span class='mono'>"
                                  f"±{config.get('borderline_margin', 5):g}</span>"),
        ])
        st.markdown(f'<div class="soc-card">{rows}</div>', unsafe_allow_html=True)

        if st.button("Reload configuration",
                     key="settings_reload"):
            st.session_state["config"] = load_config(org_id)
            st.rerun()
    C.button_icon("settings_reload", "refresh", 13)
