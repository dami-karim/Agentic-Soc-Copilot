"""
Evidence workspace — tabbed technical evidence browser.

Tabs: OVERVIEW · LOGS · IoCs · ATT&CK · GRAPH · PAST INCIDENTS.
All data is parsed from the live investigation state (tool outputs
persisted in enrichment, ioc_list, attack_techniques, blast_radius).
Nothing simulated.
"""
from __future__ import annotations

import ast

import streamlit as st

from src.ui import components as C
from src.ui.data import EVENTCODE_DESCRIPTIONS
from src.ui.icons import icon


def _parse_py(raw):
    try:
        val = ast.literal_eval(raw)
        return val if isinstance(val, (list, dict)) else None
    except (ValueError, SyntaxError, TypeError):
        return None


def render(result: dict) -> None:
    tabs = st.tabs([
        "Overview", "Logs", "IoCs", "ATT&CK", "Graph", "Past Incidents",
    ])
    with tabs[0]:
        _tab_overview(result)
    with tabs[1]:
        _tab_logs(result)
    with tabs[2]:
        _tab_iocs(result)
    with tabs[3]:
        _tab_attack(result)
    with tabs[4]:
        _tab_graph(result)
    with tabs[5]:
        _tab_incidents(result)


# ── OVERVIEW ──────────────────────────────────────────────────────────────────


def _tab_overview(result: dict) -> None:
    enrichment = result.get("enrichment", {}) or {}
    techniques = result.get("attack_techniques", []) or []
    iocs = result.get("ioc_list", []) or []
    blast = result.get("blast_radius", {}) or {}

    raw_logs = enrichment.get("log_search")
    events = None
    try:
        parsed = _parse_py(raw_logs) if isinstance(raw_logs, str) and raw_logs else raw_logs
        if isinstance(parsed, list):
            events = [e for e in parsed if isinstance(e, dict)]
            if events and "error" in events[0]:
                events = None
    except Exception:
        events = None

    incidents = None
    raw_inc = enrichment.get("similar_incidents")
    if raw_inc:
        parsed = _parse_py(raw_inc) if isinstance(raw_inc, str) else raw_inc
        if isinstance(parsed, list):
            incidents = len([i for i in parsed if isinstance(i, dict)])

    # Evidence coverage cards
    def cov(ic: str, title: str, value: str, sub: str,
            tone: str = "var(--primary)") -> str:
        return (
            f'<div class="metric-card" style="flex:1 1 200px;">'
            f'<div style="display:flex;align-items:center;gap:.5rem;'
            f'margin-bottom:.35rem;">'
            f'<span style="color:{tone};display:inline-flex;">'
            f'{icon(ic, 15)}</span>'
            f'<span class="mk">{C.esc(title)}</span></div>'
            f'<div class="mv small">{value}</div>'
            f'<div style="font-size:12px;color:var(--txt-3);margin-top:.2rem;">'
            f'{sub}</div></div>'
        )

    cards = []
    cards.append(cov("database", "Correlated logs",
                     str(len(events)) if events else "—",
                     "events from OpenSearch" if events
                     else "no log query recorded"))
    cards.append(cov("book-open", "ATT&CK mapping",
                     str(len(techniques)),
                     "techniques identified" if techniques
                     else "no techniques mapped",
                     tone="var(--purple)"))
    cards.append(cov("crosshair", "IoCs extracted",
                     str(len(iocs)),
                     "indicators found" if iocs else "no indicators",
                     tone="var(--warn)"))
    cards.append(cov("network", "Graph reachability",
                     str(blast.get("reachable_count")) if blast else "—",
                     f"hops ≤ {blast.get('max_hops', '—')}" if blast
                     else "no graph traversal"))
    cards.append(cov("brain", "Similar incidents",
                     str(incidents) if incidents is not None else "—",
                     "from vector memory" if incidents else "no vector search",
                     tone="var(--ok)"))

    st.markdown(f'<div class="metric-row">{"".join(cards)}</div>',
                unsafe_allow_html=True)

    # Key findings strip
    findings: list[str] = []
    for t in sorted(techniques, key=lambda x: -(float(x.get("confidence", 0) or 0)))[:3]:
        findings.append(
            f'<span class="tech-id">{C.esc(t.get("technique_id", "?"))}</span>'
            f'<span style="font-size:13px;color:var(--txt-2);">'
            f'{C.esc(t.get("technique_name", ""))}'
            f' &nbsp;{C.conf_badge(float(t.get("confidence", 0) or 0))}</span>')
    top_iocs = sorted(iocs, key=lambda x: -(float(x.get("confidence", 0) or 0)))[:4]
    for i in top_iocs:
        findings.append(
            f'<span class="chip">{C.esc(str(i.get("type", "?")).upper())} '
            f'<b>{C.esc(i.get("value", ""))}</b></span>')

    st.markdown('<div class="sec-label"><span class="t">Key findings</span>'
                '</div>', unsafe_allow_html=True)
    if findings:
        rows = "".join(
            f'<div style="display:flex;align-items:center;gap:.6rem;'
            f'padding:.34rem .1rem;border-bottom:1px solid var(--border);">'
            f'{f}</div>'
            for f in findings
        )
        st.markdown(rows, unsafe_allow_html=True)
    else:
        C.callout("No structured findings were produced during this "
                  "investigation. Check the Logs and Agent Execution tabs "
                  "for details.", kind="info")


# ── LOGS ──────────────────────────────────────────────────────────────────────


def json_dump(obj) -> str:
    import json
    try:
        return json.dumps(obj, indent=2, default=str)
    except Exception:
        return str(obj)


def _tab_logs(result: dict) -> None:
    enrichment = result.get("enrichment", {}) or {}
    raw = enrichment.get("log_search")

    if raw is None or raw == "":
        C.empty_state(
            "No log correlation data",
            "The agent did not run search_logs during this investigation.",
            ic="database",
            stages=["search_logs", "opensearch", "soc-alerts"])
        return

    events = _parse_py(raw)
    if events is None:
        C.json_details("Raw log_search payload", raw)
        return
    if not events:
        C.callout("The correlation query returned <b>0 matching events</b> — "
                  "no related log records were found in the retention window.",
                  kind="warning", ic="info", title="OpenSearch")
        return

    if isinstance(events[0], dict) and "error" in events[0]:
        C.callout(C.esc(events[0]["error"]), kind="danger",
                  title="OpenSearch error")
        return

    fltr = st.text_input("Filter events", placeholder="Filter by host, user, "
                         "event code, IP…", label_visibility="collapsed"
                         ).lower().strip()

    def matches(ev: dict) -> bool:
        if not fltr:
            return True
        return any(fltr in str(v).lower() for v in ev.values())

    shown = [e for e in events if isinstance(e, dict) and matches(e)]

    st.markdown(f'<div style="font-size:12px;color:var(--txt-3);margin:'
                f'.15rem 0 .45rem 0;">{len(shown)} / {len(events)} events · '
                'click a row to expand the full record</div>',
                unsafe_allow_html=True)

    rows = []
    for ev in shown:
        ts = str(ev.get("_time", ev.get("timestamp", ""))).replace("T", " ")[:19]
        host = ev.get("host") or "—"
        code = str(ev.get("EventCode") or "—")
        user = ev.get("user") or "—"
        src = ev.get("src_ip") or ev.get("Source_Network_Address") or ""
        sig = ev.get("signature") or ev.get("message") or ""
        ec_desc = EVENTCODE_DESCRIPTIONS.get(code, "")
        summary_line = f"{sig}{'  [' + ec_desc + ']' if ec_desc else ''}"
        rows.append(
            '<details class="logrow">'
            '<summary>'
            f'<span class="ts">{C.esc(ts)}</span>'
            f'<span class="host">{C.esc(host)}</span>'
            f'<span class="code">EC {C.esc(code)}</span>'
            f'<span style="min-width:110px;color:var(--txt-2);">{C.esc(user)}</span>'
            f'<span style="min-width:96px;color:var(--txt-3);">{C.esc(src)}</span>'
            f'<span class="sig">{C.esc(summary_line)}</span>'
            '</summary>'
            f'<pre>{C.esc(json_dump(ev))}</pre>'
            '</details>')

    if not rows:
        C.callout("No events match the filter.", kind="info")
        return

    header = (
        '<table class="dt"><thead><tr>'
        '<th style="padding-left:.8rem;">Timestamp</th><th>Host</th>'
        '<th>EventCode</th><th>User</th><th>Source IP</th>'
        '<th style="width:40%;">Event</th>'
        '</tr></thead></table>'
    )
    st.markdown(
        '<div class="dt-wrap" style="max-height:430px;">'
        + header +
        '<div>' + "".join(rows) + "</div></div>",
        unsafe_allow_html=True)


# ── INDICATORS ────────────────────────────────────────────────────────────────


def _tab_iocs(result: dict) -> None:
    iocs = result.get("ioc_list", []) or []
    if not iocs:
        C.empty_state(
            "No indicators of compromise were identified",
            "The investigation did not produce IoC entries.",
            ic="crosshair",
            stages=["ioc_list", "extracted from", "log_search"])
        return

    C.section_label("Indicators of Compromise", f"{len(iocs)} total")

    rows = []
    for ioc in iocs:
        typ = str(ioc.get("type", "?")).upper()
        val = f"<span class='mono'>{C.esc(ioc.get('value', ''))}</span>"
        conf = float(ioc.get("confidence", 0) or 0)
        src = C.esc(ioc.get("source", ""))
        rows.append([typ, val, C.conf_badge(conf), src])
    st.markdown(C.data_table(["Type", "Value", "Confidence", "Source"], rows),
                unsafe_allow_html=True)


# ── ATT&CK ────────────────────────────────────────────────────────────────────


def _tab_attack(result: dict) -> None:
    techniques = result.get("attack_techniques", []) or []
    if not techniques:
        C.empty_state(
            "No ATT&CK techniques mapped",
            "The agent did not map this behavior to MITRE ATT&CK techniques.",
            ic="book-open",
            stages=["observed behavior", "→", "ATT&CK corpus"])
        return

    ordered = sorted(techniques,
                     key=lambda x: -(float(x.get("confidence", 0) or 0)))
    C.section_label("MITRE ATT&CK Techniques",
                    f"{len(ordered)} mapped · expand a card for the match rationale")

    for t in ordered:
        tid = t.get("technique_id", "T????")
        name = t.get("technique_name", "Unknown")
        conf = float(t.get("confidence", 0) or 0)
        rationale = t.get("rationale", "")
        st.markdown(
            f'<div class="tech-card">'
            f'<div style="display:flex;align-items:center;gap:.7rem;'
            f'flex-wrap:wrap;">'
            f'<span class="tech-id">{C.esc(tid)}</span>'
            f'<span class="tech-name">{C.esc(name)}</span>'
            f'<span style="margin-left:auto;">{C.conf_badge(conf)}</span>'
            f'</div><div class="tech-body">'
            f'<div class="tb-k">Why it matched</div>'
            f'{C.esc(C.clean_text(rationale) or "No match rationale recorded.")}'
            f'</div></div>', unsafe_allow_html=True)


# ── BLAST RADIUS / GRAPH ─────────────────────────────────────────────────────


def _tab_graph(result: dict) -> None:
    br = result.get("blast_radius", {}) or {}

    if not br:
        C.empty_state(
            "No graph traversal data",
            "The agent did not query the Neo4j asset graph.",
            ic="network",
            stages=["query_blast_radius", "neo4j", "asset graph"])
        return

    start = br.get("start_node", "?")
    hops = br.get("max_hops", "?")
    count = br.get("reachable_count", len(br.get("reachable_assets") or []))

    st.markdown(f"""
    <div style="display:flex;gap:.55rem;align-items:center;font-size:13.5px;
         color:var(--txt-2);margin-bottom:.65rem;">
      <span class="chip"><b>{C.esc(start)}</b></span>
      <span style="color:var(--txt-3);display:inline-flex;"
        >{icon("arrow-right", 14)}</span>
      <b style="color:var(--txt);">{count} reachable assets</b>
      <span style="color:var(--txt-3);">· max {C.esc(str(hops))} hops</span>
    </div>
    """, unsafe_allow_html=True)

    if br.get("error"):
        C.callout(C.esc(br["error"]), kind="warning", title="Graph query note")

    assets = br.get("reachable_assets") or []
    if assets:
        # Hop ladder — lateral movement depth, one tier per hop distance.
        tiers: dict[int, list] = {}
        for a in assets:
            tiers.setdefault(int(a.get("hops", 99) or 99), []).append(a)

        tier_rows = []
        for depth in sorted(tiers):
            nodes_html = "".join(
                f'<span class="hop-node">'
                f'<span class="nlab">{C.esc(", ".join(a.get("labels", [])) or "?")}</span>'
                f'<b>{C.esc(a.get("id", "?"))}</b></span>'
                for a in sorted(tiers[depth], key=lambda x: str(x.get("id", "")))
            )
            badge = "Entry" if depth == 1 else f"Hop {depth}"
            bc = "var(--crit)" if depth == 1 else ("var(--warn)" if depth == 2
                                                   else "var(--txt-3)")
            tier_rows.append(
                f'<div class="hop-tier">'
                f'<span class="hop-badge" style="--hc:{bc};">{badge}</span>'
                f'<span class="hop-nodes">{nodes_html}</span></div>')
            if depth != max(tiers):
                tier_rows.append(f'<div class="hop-link">│</div>')

        st.markdown(
            '<div class="soc-card"><div class="tb-k" style="margin-bottom:'
            '.5rem;">Lateral reach from <span class="mono">'
            f'{C.esc(start)}</span></div>'
            '<div class="hop-ladder">' + "".join(tier_rows) + "</div></div>",
            unsafe_allow_html=True)

        # Detailed table
        rows = []
        for a in sorted(assets, key=lambda x: x.get("hops", 99)):
            aid = a.get("id", "?")
            labels = ", ".join(a.get("labels", [])) or "node"
            hop = a.get("hops", "?")
            accent = "var(--crit)" if str(hop) == "1" else "var(--warn)"
            hop_cell = (f'<span style="color:{accent};font-weight:600;">'
                        f'{"direct" if hop == 1 else f"{hop} hops"}</span>')
            rows.append([f"<span class='mono'>{C.esc(aid)}</span>",
                         C.esc(labels), hop_cell])
        st.markdown("")
        st.markdown(C.data_table(
            ["Asset", "Node Type", "Distance"], rows), unsafe_allow_html=True)
        st.caption("Reachability computed by Neo4j variable-depth traversal "
                   "(undirected paths); distance is minimum path length observed.")
    elif not br.get("error"):
        C.callout("Traversal completed — no other assets are reachable from "
                  "this node in the asset graph.", kind="success",
                  ic="check-circle")


# ── SIMILAR INCIDENTS ─────────────────────────────────────────────────────────


def _tab_incidents(result: dict) -> None:
    enrichment = result.get("enrichment", {}) or {}
    raw = enrichment.get("similar_incidents")

    if not raw:
        C.empty_state(
            "No vector search results",
            "The agent did not query Qdrant for precedent incidents.",
            ic="brain",
            stages=["search_similar_incidents", "qdrant", "past_incidents"])
        return

    incidents = _parse_py(raw)
    if incidents is None or not incidents:
        if isinstance(incidents, list):
            C.callout("No precedent incidents matched in the vector store.",
                      kind="info", title="Qdrant")
        else:
            C.json_details("Raw similar_incidents payload", raw)
        return

    C.section_label("Precedent Incidents",
                    f"{len(incidents)} retrieved from incident memory")
    rows = []
    for inc in incidents:
        if not isinstance(inc, dict):
            continue
        score = inc.get("score")
        score_cell = (f'<span class="mono" style="color:var(--primary);">'
                      f'{float(score):.0%}</span>'
                      if isinstance(score, (int, float)) else "—")
        iid = inc.get("incident_id", inc.get("id", "—"))
        tech = (f"<span class='tech-id'>{C.esc(inc.get('technique', '—'))}"
                f"</span>")
        res = inc.get("resolution", "—")
        rows.append([score_cell, f"<span class='mono'>{C.esc(iid)}</span>",
                     tech, C.esc(res)])

    st.markdown(C.data_table(
        ["Similarity", "Incident ID", "Technique", "Resolution"], rows),
        unsafe_allow_html=True)
