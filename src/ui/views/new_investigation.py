"""
Investigations — the new-investigation creation flow.

A centered, card-based entry point:
  1. Choose the alert source (Template · Custom Alert · SIEM upload)
  2a. Pick one of the pre-built security scenario cards, or
  2b. Fill in / upload your own SIEM alert
  3. Run — hands the payload to the LangGraph pipeline (unchanged backend).

Template payloads are byte-identical to the documented demo scenarios.
"""
from __future__ import annotations

import json

import streamlit as st

from src.ui import components as C
from src.ui.data import ALERT_TEMPLATES
from src.ui.icons import icon


def _mode_cards() -> None:
    c1, c2, c3 = st.columns(3, gap="medium")

    cards = [
        (c1, "template", "layers", "", "Template",
         "Pick a pre-built security scenario and run it through the full "
         "agentic pipeline."),
        (c2, "custom", "file-text", "purple", "Custom Alert",
         "Enter your own SIEM alert fields — host, event code, signature "
         "and more."),
        (c3, "upload", "upload", "green", "Upload JSON",
         "Drop a SIEM JSON/JSONL export and ingest it directly into the "
         "pipeline."),
    ]
    for col, mode, ic, tone, title, desc in cards:
        with col:
            selected = st.session_state.get("inv_mode") == mode
            cls = "choice-card selected" if selected else "choice-card"
            tone_cls = f" {tone}" if tone else ""
            st.markdown(
                f'<div class="{cls}" style="min-height:150px;">'
                f'<div class="choice-ic{tone_cls}">{icon(ic, 20)}</div>'
                f'<div class="choice-title">{title}</div>'
                f'<div class="choice-desc">{desc}</div>'
                f"</div>",
                unsafe_allow_html=True,
            )
            b1, b2, b3 = st.columns([1.1, 1.4, 1.1])
            with b2:
                if st.button("Select" if not selected else "Selected ✓",
                             key=f"mode_{mode}",
                             use_container_width=True,
                             type="primary" if selected else "secondary"):
                    _set_mode(mode)


def _set_mode(mode: str) -> None:
    st.session_state["inv_mode"] = mode
    if mode != "template":
        st.session_state["selected_template"] = None
    st.rerun()


def _template_cards() -> None:
    current = st.session_state.get("selected_template")
    cols = st.columns(2, gap="medium")
    for i, t in enumerate(ALERT_TEMPLATES):
        with cols[i % 2]:
            selected = current == t.key
            cls = "tpl-card selected" if selected else "tpl-card"
            st.markdown(
                f'<div class="{cls}" style="min-height:172px;">'
                f'<div class="tpl-top">'
                f'<div><div class="tpl-title">{C.esc(t.title)}</div></div>'
                f'<span class="chip">EventCode <b>{C.esc(t.eventcode)}</b></span>'
                f"</div>"
                f'<div class="tpl-desc">{C.esc(t.description)}</div>'
                f'<div class="tpl-foot">'
                f'<span class="tech-id">{C.esc(t.tag)}</span>'
                f'<span style="display:flex;gap:.4rem;">'
                f'{t.icon_html(16)}'
                f"</span></div>"
                f"</div>",
                unsafe_allow_html=True,
            )
            b1, b2, b3 = st.columns([1.1, 1.4, 1.1])
            with b2:
                if st.button(
                    "Select" if not selected else "Selected ✓",
                    key=f"tpl_{t.key}",
                    type="primary" if selected else "secondary",
                    use_container_width=True,
                ):
                    st.session_state["selected_template"] = t.key
                    st.rerun()

    t = next((x for x in ALERT_TEMPLATES if x.key == current), None)
    if t:
        with st.expander("Alert payload", expanded=False):
            st.json(t.payload, expanded=True)
        _run_bar(t.payload)
    else:
        C.callout("Select a scenario above, then press "
                  "<b>Run Investigation</b>.", kind="info", ic="info")


def _custom_form() -> None:
    with st.container(border=False):
        fhost, fec = st.columns(2)
        with fhost:
            host = st.text_input("Host", value="WIN-DC01", key="cu_host")
        with fec:
            ec = st.text_input("EventCode", value="4625", key="cu_ec")
        fsip, fdip = st.columns(2)
        with fsip:
            src_ip = st.text_input("Source IP", value="10.0.2.15", key="cu_src")
        with fdip:
            dest_ip = st.text_input("Destination IP", value="10.0.2.5",
                                    key="cu_dst")
        fuser, fsev = st.columns([2, 1])
        with fuser:
            user = st.text_input("User", value="administrator", key="cu_user")
        with fsev:
            sev = st.selectbox("Severity", ["low", "medium", "high", "critical"],
                               index=2, key="cu_sev")
        sig = st.text_area("Signature", value="An account failed to log on",
                           key="cu_sig")
        fstype, fcount = st.columns([3, 1])
        with fstype:
            sourcetype = st.text_input("Sourcetype",
                                       value="WinEventLog:Security",
                                       key="cu_type")
        with fcount:
            count = st.number_input("Event count", min_value=1, value=1,
                                    key="cu_count")

    payload = {
        "host": host, "EventCode": ec.strip(), "src_ip": src_ip,
        "dest_ip": dest_ip, "user": user, "signature": sig,
        "severity": sev, "sourcetype": sourcetype, "count": int(count),
    }
    _run_bar(payload)


def _upload_form() -> None:
    uploaded = st.file_uploader("SIEM alert (JSON / JSONL)",
                                type=["json", "jsonl"])
    MAX_BYTES = 200 * 1024 * 1024  # 200 MB

    payload = None
    if uploaded:
        raw = uploaded.read()
        if len(raw) > MAX_BYTES:
            C.callout(f"File too large ({len(raw) / 1024 / 1024:.1f} MB). "
                      f"Maximum allowed is 200 MB.", kind="danger", ic="alert-triangle")
        else:
            try:
                text = raw.decode("utf-8").strip()
                try:
                    parsed = json.loads(text)
                except (json.JSONDecodeError, ValueError):
                    parsed = json.loads(text.splitlines()[0])
                if isinstance(parsed, dict):
                    payload = parsed
                    C.callout(f"Loaded alert <code>{C.esc(str(payload.get('alert_id', 'imported'))[:24])}"
                              "</code> — ready to investigate.",
                              kind="success", ic="check-circle")
                else:
                    C.callout("Uploaded JSON is not an object.", kind="danger")
            except Exception as e:
                C.callout(f"Parse error: {C.esc(e)}", kind="danger")
    else:
        st.markdown('<div style="height:.4rem;"></div>', unsafe_allow_html=True)
        C.callout("Drop a SIEM JSON export here to ingest it into the "
                  "pipeline. The first line of a JSONL file is used.",
                  kind="info", ic="info")

    if payload:
        with st.expander("Parsed payload"):
            st.json(payload, expanded=True)
        _run_bar(payload)


def _run_bar(payload: dict) -> None:
    st.markdown('<div style="height:.35rem;"></div>', unsafe_allow_html=True)
    b1, b2, b3 = st.columns([2.2, 1.6, 5.2])
    with b1:
        st.markdown(
            '<div style="font-size:12.5px;color:var(--txt-3);padding-top:.55rem;'
            'display:flex;align-items:center;gap:.4rem;">'
            f'{icon("shield-check", 14)} Runs the full agentic pipeline'
            "</div>",
            unsafe_allow_html=True)
    with b2:
        go = st.button("Run Investigation",
                       key="run_investigation", type="primary",
                       use_container_width=True)
    C.button_icon("run_investigation", "play", 14, color="currentColor",
                  hover_color=None)
    if go:
        st.session_state["pending_run"] = dict(payload)
        st.session_state["result"] = None
        st.session_state["run_error"] = None
        st.rerun()


def render() -> None:
    # If a finished result exists, show the result workspace instead of
    # the creation flow; the analyst can start a new one explicitly.
    if st.session_state.get("result"):
        from src.ui.views import investigation
        investigation.render(st.session_state["result"])
        return

    if st.session_state.get("pending_run"):
        # Pipeline currently executing (handled by app shell); show progress.
        from src.ui.views import investigation
        investigation.render(None)
        return

    st.markdown("""
    <div style="text-align:center;margin:.9rem 0 .2rem 0;">
      <h2 style="font-size:24px;font-weight:700;letter-spacing:-.02em;
          color:var(--txt)!important;margin-bottom:.35rem;">
        Start a new investigation</h2>
      <div style="font-size:14.5px;color:var(--txt-2);">
        Choose how you want to provide the alert.</div>
    </div>
    """, unsafe_allow_html=True)

    if st.session_state.get("inv_mode") is None:
        _mode_cards()
        return

    # Mode header with back link
    back_col, _, _ = st.columns([1, 6, 4])
    with back_col:
        if st.button("Back", key="back_modes"):
            st.session_state["inv_mode"] = None
            st.session_state["selected_template"] = None
            st.rerun()
    C.button_icon("back_modes", "arrow-left", 13)

    mode = st.session_state["inv_mode"]
    if mode == "template":
        _template_cards()
    elif mode == "custom":
        _custom_form()
    elif mode == "upload":
        _upload_form()
