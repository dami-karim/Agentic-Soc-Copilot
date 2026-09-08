"""
Tools pages — live windows onto the four backend tools the agent uses.

Every figure shown is queried READ-ONLY from the real service at render
time (same endpoints/credentials as src/tools/*):
  · OpenSearch      — cluster health + indices
  · Knowledge Graph — Neo4j node/relationship inventory
  · Incident Memory — Qdrant collections & point counts
  · MITRE ATT&CK    — STIX corpus statistics + real keyword search
"""
from __future__ import annotations

import os

import httpx
import streamlit as st

from src.ui import components as C
from src.ui.icons import icon


def _svc_banner(key: str) -> None:
    """Show a degraded-service notice when the backing service is down."""
    for s in st.session_state.get("_last_statuses", []):
        if s["key"] == key and s["status"] not in ("online", "loaded"):
            C.callout(f"<b>{C.esc(s['label'])}</b> is not reachable right now "
                      f"({C.esc(str(s.get('detail', ''))[:90])}). Start it "
                      "with <code>cd lab &amp;&amp; docker compose up -d</code>.",
                      kind="warning", ic="alert-triangle")


# ── OpenSearch ────────────────────────────────────────────────────────────────


def render_opensearch() -> None:
    _svc_banner("opensearch")
    url = os.getenv("OPENSEARCH_URL", "http://localhost:9200")

    try:
        r = httpx.get(url, timeout=2.5)
        info = r.json()
        version = info.get("version", {}).get("number", "?")
        h = httpx.get(f"{url}/_cluster/health", timeout=2.5).json()
        C.metric_cards([
            {"k": "Cluster Status",
             "v": str(h.get("status", "?")).upper(),
             "c": "var(--ok)" if h.get("status") in ("green", "yellow")
             else "var(--crit)", "small": True},
            {"k": "Version", "v": f"v{version}", "small": True},
            {"k": "Nodes", "v": h.get("number_of_nodes", "?")},
            {"k": "Indices", "v": "…"},
        ])
        idx = httpx.get(f"{url}/_cat/indices?format=json", timeout=2.5).json()
        if isinstance(idx, list) and idx:
            rows = []
            for i in sorted(idx, key=lambda x: x.get("index", "")):
                rows.append([
                    f"<span class='mono'>{C.esc(i.get('index', '?'))}</span>",
                    C.esc(i.get("health", "—")),
                    f"<span class='mono'>{int(i.get('docs.count', 0) or 0):,}</span>",
                    f"<span class='mono'>{int(i.get('store.size', '0b').replace('b', '') or 0):,}"
                    f"{C.esc(str(i.get('store.size', 'b'))[-1:])}</span>",
                ])
            C.section_label("Indices", f"{len(idx)} found")
            st.markdown(C.data_table(
                ["Index", "Health", "Documents", "Store Size"], rows),
                unsafe_allow_html=True)
        else:
            C.callout("No indices exist yet — run an investigation; the "
                      "agent queries <code>soc-alerts</code> through "
                      "<code>search_logs</code>.", kind="info")
    except Exception as e:
        C.empty_state("OpenSearch unreachable", C.esc(e)[:120], ic="database")
        return

    st.markdown('<div style="height:.5rem;"></div>', unsafe_allow_html=True)
    C.callout(
        "The investigation agent uses OpenSearch through the guarded "
        "<code>search_logs</code> tool to correlate events around each alert.",
        kind="info", ic="info")


# ── Knowledge Graph ───────────────────────────────────────────────────────────


def render_graph() -> None:
    _svc_banner("neo4j")
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    pwd = os.getenv("NEO4J_PASSWORD", "")

    driver = None
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(uri, auth=(user, pwd),
                                      connection_timeout=2.5)
        driver.verify_connectivity()

        with driver.session() as session:
            labels = session.run(
                "MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n "
                "ORDER BY n DESC").data()
            rels = session.run(
                "MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS n "
                "ORDER BY n DESC").data()
            total = session.run("MATCH (n) RETURN count(n) AS n").single()["n"]

        C.metric_cards([
            {"k": "Total Nodes", "v": f"{total:,}"},
            {"k": "Node Labels", "v": len(labels)},
            {"k": "Relationship Types", "v": len(rels)},
        ])

        col1, col2 = st.columns(2, gap="large")
        with col1:
            C.section_label("Node Labels")
            rows = [[f"<span class='mono'>{C.esc(l['label'])}</span>",
                     f"<span class='mono'>{l['n']:,}</span>"] for l in labels]
            st.markdown(C.data_table(["Label", "Count"], rows),
                        unsafe_allow_html=True)
        with col2:
            C.section_label("Relationships")
            rows = [[f"<span class='mono'>{C.esc(r['type'])}</span>",
                     f"<span class='mono'>{r['n']:,}</span>"] for r in rels]
            st.markdown(C.data_table(["Type", "Count"], rows),
                        unsafe_allow_html=True)
    except Exception as e:
        C.empty_state("Neo4j unreachable", C.esc(e)[:120], ic="network")
        return
    finally:
        if driver:
            try:
                driver.close()
            except Exception:
                pass

    st.markdown('<div style="height:.5rem;"></div>', unsafe_allow_html=True)
    C.callout(
        "The agent traverses this asset graph through <code>"
        "query_blast_radius</code> to measure how far an attacker could "
        "move laterally from a compromised host.", kind="info", ic="info")


# ── Incident Memory ───────────────────────────────────────────────────────────


def render_memory() -> None:
    _svc_banner("qdrant")
    url = os.getenv("QDRANT_URL", "http://localhost:6333")

    try:
        cols_r = httpx.get(f"{url}/collections", timeout=2.5).json()
        names = [c.get("name") for c in
                 cols_r.get("result", {}).get("collections", [])]
        cards = []
        details_rows = []
        for name in names:
            info = httpx.get(f"{url}/collections/{name}", timeout=2.5).json()
            res = info.get("result", {})
            points = res.get("points_count", 0) or 0
            status = res.get("status", "?")
            vsize = res.get("vectors_count", res.get("vector_size", "—"))
            cards.append({"k": name, "v": f"{points:,}",
                          "u": "vectors", "small": True,
                          "c": "var(--ok)" if status == "green"
                          else "var(--warn)"})
            details_rows.append([
                f"<span class='mono'>{C.esc(name)}</span>",
                C.pill(status.title(), "var(--ok)" if status == "green"
                       else "var(--warn)"),
                f"<span class='mono'>{points:,}</span>",
                f"<span class='mono'>{vsize}</span>" if vsize != "—" else "—",
            ])
        if cards:
            C.metric_cards(cards)
        else:
            C.callout("No collections exist yet.", kind="info")
        if details_rows:
            C.section_label("Collections", f"{len(names)} found")
            st.markdown(C.data_table(
                ["Collection", "Status", "Points", "Vectors"], details_rows),
                unsafe_allow_html=True)
    except Exception as e:
        C.empty_state("Qdrant unreachable", C.esc(e)[:120], ic="brain")
        return

    st.markdown('<div style="height:.5rem;"></div>', unsafe_allow_html=True)
    C.callout(
        "The agent searches precedent incidents through <code>"
        "search_similar_incidents</code>; embeddings of resolved cases are "
        "stored here and retrieved by semantic similarity.",
        kind="info", ic="info")


# ── MITRE ATT&CK ──────────────────────────────────────────────────────────────


@st.cache_resource(show_spinner="Loading ATT&CK corpus …")
def _attack_tool():
    from src.tools.attack_corpus_tool import AttackStixTool
    return AttackStixTool()


def render_attack() -> None:
    _svc_banner("corpus")

    # Corpus statistics (cheap — reuse health probe cache)
    for s in st.session_state.get("_last_statuses", []):
        if s["key"] == "corpus":
            detail = s.get("detail", "")
            if s["status"] == "loaded":
                C.metric_cards([
                    {"k": "Corpus", "v": "Enterprise ATT&CK", "small": True},
                    {"k": "Techniques", "v": detail.split(" ")[0]},
                    {"k": "Source", "v": "STIX · local", "small": True},
                ])
            break

    q = st.text_input("Search techniques", placeholder=
                      "e.g. scheduled task · brute force · credential dumping",
                      key="attack_q")
    if q.strip():
        try:
            results = _attack_tool().query_techniques(q.strip(), top_k=8)
        except Exception as e:
            C.callout(f"Corpus search failed: {C.esc(e)}", kind="danger")
            return
        if not results:
            C.callout(f"No techniques matched “{C.esc(q)}”.", kind="info")
            return
        C.section_label("Matches", f"{len(results)} techniques")
        for t in results:
            st.markdown(
                '<div class="tech-card">'
                '<div style="display:flex;align-items:center;gap:.7rem;'
                'flex-wrap:wrap;">'
                f'<span class="tech-id">{C.esc(t.get("technique_id", "T????"))}'
                '</span>'
                f'<span class="tech-name">{C.esc(t.get("technique_name", ""))}'
                '</span>'
                f'<span style="margin-left:auto;">'
                + C.pill(f"score {t.get('score', 0)}", "var(--primary)") +
                '</span></div>'
                '<div class="tech-body">'
                f'{C.esc(C.clean_text(t.get("description", ""))[:220])}…'
                '</div></div>',
                unsafe_allow_html=True)
    else:
        C.callout("Type keywords above to search the real ATT&CK corpus the "
                  "agent uses during investigations.", kind="info",
                  ic="book-open")


TOOL_PAGES = {
    "tools_opensearch": render_opensearch,
    "tools_graph": render_graph,
    "tools_memory": render_memory,
    "tools_attack": render_attack,
}
