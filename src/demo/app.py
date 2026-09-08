"""
SOC Co-Pilot — Investigation Console (entry point).

Thin orchestration shell:
  1. Loads the dual-theme design system (Light/Dark, session-persistent)
  2. Renders the navigation sidebar and global header
  3. Runs the LangGraph investigation pipeline on demand —
     build_graph(with_hil=False), exactly as before; backend untouched
  4. Routes between Home · Investigations · Alerts · History · Tools ·
     Settings · System Status through the views package

Run with:  streamlit run src/demo/app.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

import streamlit as st

from src.config import load_config
from src.ui import components as C
from src.ui.health import get_all_statuses
from src.ui.state import ensure_session_state
from src.ui.theme import font_links
from src.ui.theme import load as load_theme
from src.ui.views import (  # noqa: F401  # noqa: F401  # noqa: F401
    actions,
    agent_exec,
    alerts,
    evidence,
    fp_filter,
    history,
    home,
    investigation,
    new_investigation,
    rca,
    settings,
    status,
    timeline,
    topbar,
)
from src.ui.views import sidebar as sidebar_view
from src.ui.views.tools import TOOL_PAGES

# ── PAGE CONFIG ──────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="SOC Co-Pilot · Investigation Console",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

font_links()
load_theme()          # theme CSS for the ACTIVE palette
C.render_styles()     # component CSS
ensure_session_state()

ss = st.session_state

if not ss.get("config"):
    ss.config = load_config(ss.get("org_id", "default"))

# ── SIDEBAR ──────────────────────────────────────────────────────────────────

sidebar_view.render()

# ── GLOBAL HEADER ────────────────────────────────────────────────────────────

config = load_config(ss.get("org_id", "default"))
ss.config = config
services = get_all_statuses(st)
ss["_last_statuses"] = services          # consumed by Tools pages
topbar.render(services)

# ── PIPELINE EXECUTION (backend unchanged) ───────────────────────────────────

if ss.get("pending_run"):
    alert_payload = ss.pending_run
    with st.status("Running investigation…", expanded=True) as status:
        try:
            from src.graph import build_graph
            from src.nodes.ingest import make_initial_input

            host = alert_payload.get("host", "?")
            ec = alert_payload.get("EventCode", "?")
            st.write(f"Ingesting alert from **{host}** "
                     f"(EventCode {ec}) …")
            app = build_graph(with_hil=False)
            initial_state = make_initial_input(alert_payload)
            st.write("Classifying · investigating (ReAct) · root cause · "
                     "proposing actions …")
            result = app.invoke(initial_state)
            ss.result = result
            ss.alert = alert_payload
            ss.pending_run = None
            from src.ui.views.history import record
            record(result)
            status.update(label="Investigation complete", state="complete",
                          expanded=False)
        except Exception as e:
            ss.run_error = str(e)
            ss.pending_run = None
            status.update(label="Pipeline error", state="error",
                          expanded=False)

# Friendly error surface (keeps the original guidance)
if ss.get("run_error"):
    C.callout(f"<b>The pipeline could not complete.</b><br>"
              f"<span class='mono' style='font-size:12px;'>"
              f"{ss.run_error[:400]}</span>", kind="danger",
              ic="alert-triangle", title="Investigation failed")
    C.callout("Ensure all Docker services are running: "
              "<code>cd lab &amp;&amp; docker compose up -d</code>.",
              kind="info", ic="info")
    if st.button("Dismiss", key="dismiss_run_error"):
        ss.run_error = None
        st.rerun()
    st.stop()

# ── ROUTING ──────────────────────────────────────────────────────────────────

page = ss.get("page", "home")

if page == "home":
    home.render()
elif page == "investigations":
    new_investigation.render()
elif page == "alerts":
    alerts.render()
elif page == "fp_filter":
    fp_filter.render()
elif page == "history":
    history.render()
elif page == "settings":
    settings.render()
elif page == "status":
    status.render()
elif page.startswith("tools_"):
    TOOL_PAGES[page]()
else:
    home.render()
