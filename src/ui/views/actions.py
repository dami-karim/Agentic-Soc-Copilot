"""
Recommended Actions — containment proposals + human approval workflow.

Proposals come from propose_actions_node. In the current non-interactive
build (with_hil=False) nothing is ever executed: every action is shown as
PROPOSED, and demo mode is labelled explicitly.

Actions flagged by the pipeline's requires_hil() logic surface a
professional analyst-approval interface (checkbox selection → Approve /
Cancel). The APPROVAL badge mirrors what the graph itself would enforce.
"""
from __future__ import annotations

import streamlit as st

from src.guardrails.hil_checkpoint import requires_hil
from src.ui import components as C
from src.ui.icons import icon


def _humanize(action_type: str) -> str:
    return str(action_type).replace("_", " ").title()


def _approval_cell(action: dict) -> str:
    if requires_hil(action):
        return C.pill("Analyst approval required", "var(--crit)")
    return C.pill("Advisory · auto", "var(--txt-3)")


def render(result: dict) -> None:
    proposals = result.get("proposed_actions", []) or []
    decisions = result.get("human_decisions", []) or []
    hil_enabled = st.session_state.get("hil_enabled", True)
    auto_mode = not hil_enabled
    n_hil = len([a for a in proposals if requires_hil(a)])

    C.section_label(
        "Recommended Containment Actions",
        f"{len(proposals)} proposed · 0 executed · {n_hil} need analyst approval")

    if auto_mode and proposals:
        C.callout(
            "Pipeline runs in <b>demo mode</b> — actions are simulated "
            "proposals only. No destructive action was executed against any "
            "system.", kind="warning", ic="lock", title="Demo mode")

    if not proposals:
        C.empty_state(
            "No actions proposed",
            "Benign alerts and low-confidence investigations produce no "
            "containment proposals.",
            ic="check-circle")
        render_audit(decisions)
        return

    for i, a in enumerate(proposals):
        risk = str(a.get("risk_level", "low")).lower()
        color = C.RISK_COLOR.get(risk, "var(--txt-3)")
        title = _humanize(a.get("action_type", "unknown"))
        target = a.get("target", "?")
        tech = a.get("technique_id")
        key = f"{a.get('action_type', i)}:{target}"

        meta_bits = [f"TARGET&nbsp;&nbsp;<b>{C.esc(target)}</b>",
                     "STATUS&nbsp;&nbsp;<b>Proposed</b>"]
        if tech:
            meta_bits.append(f"TRIGGERED BY&nbsp;&nbsp;"
                             f"<b><span class='mono'>{C.esc(tech)}</span></b>")
        meta_html = "".join(f"<span>{b}</span>" for b in meta_bits)

        just = a.get("justification", "")
        blast = a.get("blast_radius_context", "")
        just_html = (f'<div class="act-just">{C.esc(just)}</div>' if just else "")
        blast_html = (f'<div class="act-just" style="color:var(--primary);">'
                      f'{icon("info", 12)} {C.esc(blast)}</div>' if blast else "")

        st.markdown(f"""
        <div class="act-row">
          <div class="act-risk" style="--rc:{color};"></div>
          <div class="act-main">
            <div style="display:flex;align-items:center;gap:.65rem;
                        flex-wrap:wrap;">
              <span class="act-title">{C.esc(title)}</span>
              {C.risk_pill(risk)}
              {_approval_cell(a)}
            </div>
            <div class="act-meta">{meta_html}</div>
            {just_html}{blast_html}
          </div>
        </div>""", unsafe_allow_html=True)

    # ── Analyst review block ─────────────────────────────────────
    hil_actions = [a for a in proposals if requires_hil(a)]
    if hil_actions:
        render_approval(hil_actions)

    # ── HIL audit trail ──────────────────────────────────────────
    render_audit(decisions)


def render_approval(hil_actions: list[dict]) -> None:
    """Professional approval interface for destructive/high-risk actions."""
    st.markdown('<div class="sec-label"><span class="t">Analyst Review'
                '</span></div>', unsafe_allow_html=True)
    st.markdown('<div style="font-size:13.5px;color:var(--txt-2);margin:'
                '-0.2rem 0 .6rem 0;">The following actions require explicit '
                'analyst approval before they would ever be executed.</div>',
                unsafe_allow_html=True)

    choices = {}
    box_col, info_col = st.columns([0.42, 1.58])
    with box_col:
        for a in hil_actions:
            label = (_humanize(a.get("action_type", "?")) + " — "
                     + str(a.get("target", "?")))
            choices[f"{a['action_type']}:{a['target']}"] = st.checkbox(
                label, value=False, key=f"approve_{a['action_type']}_{a['target']}")
    with info_col:
        rows = []
        for a in hil_actions:
            rows.append([
                f"<span class='mono'>{C.esc(a.get('action_type', '?'))}</span>",
                C.esc(a.get("target", "?")),
                C.risk_pill(str(a.get("risk_level", "low")).lower()),
            ])
        st.markdown(C.data_table(["Action", "Target", "Risk"], rows,
                                 heights="auto"),
                    unsafe_allow_html=True)

    c1, c2, c3 = st.columns([1.4, 1.4, 4])
    with c1:
        cancel = st.button("Cancel", key="hil_cancel",
                           use_container_width=True)
    with c2:
        approve = st.button("Approve Selected",
                            key="hil_approve", type="primary",
                            use_container_width=True)
    C.button_icon("hil_approve", "shield-check", 14, color="currentColor",
                  hover_color=None)

    if cancel:
        st.session_state["approved_actions"] = []
        C.callout("Approval dismissed — no actions were approved.",
                  kind="info")
    if approve:
        selected = [k for k, v in choices.items() if v]
        if not selected:
            C.callout("Select at least one action to approve.",
                      kind="warning")
        else:
            st.session_state["approved_actions"] = selected
            C.callout(
                "<b>Demo mode</b> — recorded "
                f"{len(selected)} simulated approval"
                f"{'s' if len(selected) != 1 else ''} "
                "(" + ", ".join(f"<span class='mono'>{C.esc(k)}</span>"
                                for k in selected) + "). No system was "
                "touched.", kind="success", ic="check-circle")


def render_audit(decisions: list[dict]) -> None:
    C.section_label("Analyst Review Audit Trail",
                    f"{len(decisions)} decision(s)")
    if decisions:
        rows = []
        for d in decisions:
            gate = d.get("gate_name", "?")
            dec = str(d.get("decision", "?")).upper()
            color = ("var(--ok)" if dec == "APPROVED" else "var(--crit)")
            analyst = d.get("analyst_id", d.get("analyst_note", "") or "auto")
            ts = str(d.get("timestamp", ""))[:19].replace("T", " ")
            note = d.get("notes", "")
            action_bit = d.get("action_type", "")
            rows.append([
                f"<span class='mono'>{ts}</span>",
                f"<span class='mono'>{C.esc(gate)}</span>",
                C.esc(str(action_bit).replace("_", " ").title())
                if action_bit else "—",
                f'<b style="color:{color};">{C.esc(dec)}</b>',
                C.esc(str(analyst)[:24]),
                C.esc(note or ""),
            ])
        st.markdown(C.data_table(
            ["Timestamp", "Gate", "Action", "Decision", "Analyst", "Notes"],
            rows),
            unsafe_allow_html=True)
    else:
        st.markdown(
            '<div class="svc-item">'
            '<span class="svc-dot" style="--dot:var(--warn);"></span>'
            'No manual decisions recorded — auto-approve mode bypassed '
            'the gates during this run.</div>',
            unsafe_allow_html=True)
