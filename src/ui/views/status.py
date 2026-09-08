"""
System Status page — live health of every backend dependency.

All checks are real probes of the same endpoints/credentials used by the
pipeline (src/ui/health.py). Nothing simulated; failures are shown as such.
"""
from __future__ import annotations

import streamlit as st

from src.ui import components as C
from src.ui.icons import icon


def render() -> None:
    from src.ui.health import get_all_statuses, CACHE_TTL_SECONDS
    services = get_all_statuses(st)

    ok = [s for s in services if s["status"] in ("online", "loaded")]
    all_ok = len(ok) == len(services) and bool(services)

    # Aggregate banner
    if all_ok:
        C.callout("All backend services are connected and responding.",
                  kind="success", ic="check-circle", title="Systems operational")
    else:
        down = ", ".join(s["label"] for s in services
                         if s["status"] not in ("online", "loaded"))
        C.callout(
            f"The following need attention: <b>{C.esc(down)}</b>. "
            "Start services with <code>cd lab &amp;&amp; docker compose up -d</code>.",
            kind="warning", ic="alert-triangle", title="Degenerated services")

    # Service rows — compact list, not giant cards
    rows_html = []
    for s in services:
        dot_color = {"online": "var(--ok)", "loaded": "var(--ok)",
                     "degraded": "var(--warn)", "missing": "var(--warn)",
                     "error": "var(--crit)", "offline": "var(--crit)"
                     }.get(s["status"], "var(--txt-3)")
        status_word = {"online": "Connected", "loaded": "Loaded",
                       "degraded": "Degraded", "missing": "Missing",
                       "error": "Error", "offline": "Offline"
                       }.get(s["status"], s["status"].title())
        ms = s.get("ms")
        latency = f"{ms} ms" if ms is not None else ""
        detail = s.get("detail") or ""
        ic = {"llm": "brain", "opensearch": "database", "neo4j": "network",
              "qdrant": "server", "corpus": "book-open"}.get(
            s["key"], "server")
        rows_html.append(f"""
        <div style="display:flex;align-items:center;gap:.9rem;padding:.72rem .2rem;
             border-bottom:1px solid var(--border);">
          <span style="color:var(--txt-3);display:inline-flex;">{icon(ic, 17)}</span>
          <span style="font-size:14px;font-weight:600;color:var(--txt);
                min-width:150px;">{C.esc(s["label"])}</span>
          <span style="display:inline-flex;align-items:center;gap:.45rem;
                font-size:13px;">
            <span class="svc-dot" style="--dot:{dot_color};"></span>
            <span style="color:{dot_color};font-weight:600;font-size:12.5px;"
              >{status_word}</span>
          </span>
          <span class="mono" style="margin-left:auto;font-size:12px;
                color:var(--txt-3);">{C.esc(latency)}</span>
          <span style="font-size:12.5px;color:var(--txt-3);max-width:340px;
                text-align:right;overflow:hidden;text-overflow:ellipsis;
                white-space:nowrap;" >{C.esc(detail)}</span>
        </div>""")

    st.markdown('<div style="height:.4rem;"></div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="soc-card" style="padding:.35rem 1.2rem;">'
        + "".join(rows_html) + "</div>",
        unsafe_allow_html=True,
    )

    b1, _ = st.columns([1.6, 6])
    with b1:
        if st.button("Re-probe services",
                     key="status_reprobe", use_container_width=True):
            for k in list(st.session_state.keys()):
                if str(k).startswith("_health_cache_"):
                    del st.session_state[k]
            st.rerun()
    C.button_icon("status_reprobe", "refresh", 14)

    st.caption(f"Health probes are cached for {CACHE_TTL_SECONDS}s to keep "
               "the console responsive.")
