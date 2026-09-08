"""
Session-state management for the SOC Co-Pilot UI.

Centralises all ``st.session_state`` initialisation into a single call
(``ensure_session_state``) and provides typed helpers for accessing and
mutating shared state. The active theme and current navigation page live
here too, so they survive Streamlit reruns within the session.
"""
from __future__ import annotations

import streamlit as st

# ── Navigation pages ──────────────────────────────────────────────────────────

PAGES = [
    "home", "investigations", "alerts", "history", "fp_filter",
    "tools_opensearch", "tools_graph", "tools_memory", "tools_attack",
    "settings", "status",
]

# ── Default values ────────────────────────────────────────────────────────────

_STATE_DEFAULTS: dict = {
    # Appearance
    "theme":              "light",    # "light" | "dark"

    # Navigation
    "page":               "home",     # one of PAGES
    "current_page":       "investigations",  # legacy alias (kept for compat)
    "inv_mode":           None,       # None | "template" | "custom" | "upload"
    "selected_template":  None,

    # Investigation pipeline
    "result":             None,       # Full SOCAgentState dict from graph.invoke()
    "alert":              None,       # Current alert dict
    "history":            [],         # Completed runs this session [{ts,result}]
    "show_full_timeline": False,
    "show_findings":      False,
    "show_incident_dialog": False,

    # Run control (UI-only)
    "pending_run":        None,       # Alert dict queued for the pipeline
    "run_error":          None,       # Last pipeline error message

    # User interactions
    "selected_technique": None,
    "selected_node":      None,
    "approved_actions":   [],
    "incident_created":   None,
    "hil_enabled":        True,
}


def ensure_session_state() -> None:
    """
    Initialise every key in ``_STATE_DEFAULTS`` if it doesn't yet exist.

    Call this **once** at the top of every Streamlit run, before any widget
    reads or writes session state.
    """
    for key, default in _STATE_DEFAULTS.items():
        if key not in st.session_state:
            st.session_state[key] = (
                list(default) if isinstance(default, list) else default
            )


# ── Typed accessors ───────────────────────────────────────────────────────────

def get_result() -> dict | None:
    """Return the full graph result (SOCAgentState dict) or ``None``."""
    return st.session_state.get("result")


def set_result(value: dict | None) -> None:
    st.session_state["result"] = value


def get_alert() -> dict | None:
    return st.session_state.get("alert")


def set_alert(value: dict | None) -> None:
    st.session_state["alert"] = value


def clear_investigation() -> None:
    """Reset everything related to a single investigation run."""
    st.session_state["result"] = None
    st.session_state["show_full_timeline"] = False
    st.session_state["show_findings"] = False
    st.session_state["show_incident_dialog"] = False
    st.session_state["approved_actions"] = []
    st.session_state["incident_created"] = None
