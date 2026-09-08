"""
Reusable UI building blocks for the SOC Co-Pilot interface.

Every component references the CSS variables published by src/ui/theme.py,
so all markup adapts automatically when the analyst switches Light/Dark.
Styles are consolidated in ``render_styles()`` and injected once per run by
the app shell.
"""
from __future__ import annotations

import html as _html
import json as _json
import re as _re

import streamlit as st

from src.ui.icons import data_uri, icon


def button_icon(key: str, name: str, size: int = 15,
                color: str = "var(--txt-3)",
                hover_color: str | None = "currentColor") -> None:
    """
    Attach an SVG-mask icon to a Streamlit widget button via its ``key``.

    Streamlit escapes HTML inside button labels, so icons are drawn with a
    CSS mask pseudo-element instead — crisp, theme-aware, no webfonts.
    The mask uses currentColor, so it follows the label color (including
    active/hover states).
    """
    uri = data_uri(name)
    if not uri:
        return
    hover = ""
    if hover_color == "currentColor":
        hover = (f'.st-key-{key} button:hover::before '
                 f'{{ background-color:currentColor; }}')
    st.markdown(f"""
    <style>
    .st-key-{key} button::before {{
      content:""; display:inline-block; width:{size}px; height:{size}px;
      margin-right:.5rem; flex-shrink:0; background-color:{color};
      -webkit-mask:url("{uri}") no-repeat center / contain;
      mask:url("{uri}") no-repeat center / contain;
    }}
    {hover}
    </style>""", unsafe_allow_html=True)

# ── Escaping ──────────────────────────────────────────────────────────────────


def esc(v) -> str:
    return _html.escape(str(v if v is not None else ""))


def clean_text(v) -> str:
    """Strip markup tags (e.g. STIX <code>/<code-sample>) & squeeze whitespace."""
    s = _re.sub(r"<[^>]+>", " ", str(v if v is not None else ""))
    return _re.sub(r"\s+", " ", s).strip()


# ── Semantic color mapping (CSS variables → theme-aware) ──────────────────────

SEVERITY_COLOR = {
    "critical": "var(--crit)",
    "high":     "var(--crit)",
    "medium":   "var(--warn)",
    "low":      "var(--primary)",
    "unknown":  "var(--txt-3)",
    "benign":   "var(--ok)",
}

STATUS_COLOR = {
    "completed":        "var(--ok)",
    "completed_benign": "var(--ok)",
    "escalated":        "var(--crit)",
    "aborted":          "var(--txt-3)",
    "error":            "var(--crit)",
    "running":          "var(--warn)",
}

STATUS_LABEL = {
    "completed":        "Completed",
    "completed_benign": "Completed · Benign",
    "escalated":        "Escalated",
    "aborted":          "Aborted",
    "error":            "Error",
    "running":          "Running",
}

RISK_COLOR = {"high": "var(--crit)", "medium": "var(--warn)", "low": "var(--ok)"}

_DOT_COLORS = {"online": "var(--ok)", "loaded": "var(--ok)", "ok": "var(--ok)",
               "degraded": "var(--warn)", "missing": "var(--warn)",
               "error": "var(--crit)", "offline": "var(--crit)"}


def _tint(var_name: str, pct: int = 12) -> str:
    """Theme-aware translucent fill behind colored badges."""
    return f"color-mix(in srgb, {var_name} {pct}%, transparent)"


# ── Component stylesheet ──────────────────────────────────────────────────────


def render_styles() -> None:
    st.markdown("""
    <style>
    /* ══ Top bar ═══════════════════════════════════════════════ */
    .soc-topbar {
        display:flex; align-items:center; justify-content:space-between;
        gap:1rem; min-height:44px; padding:.1rem 0 .45rem 0;
    }
    .soc-topbar .tb-title {
        display:flex; align-items:baseline; gap:.6rem; min-width:0;
    }
    .soc-topbar .tb-name {
        font-size:15px; font-weight:700; color:var(--txt); letter-spacing:-.01em;
        white-space:nowrap;
    }
    .soc-topbar .tb-sub {
        font-size:13px; color:var(--txt-3); white-space:nowrap;
    }
    .tb-right { display:flex; align-items:center; gap:.9rem; }

    .svc-strip { display:flex; align-items:center; gap:.95rem; flex-wrap:wrap; }
    .svc-item {
        display:inline-flex; align-items:center; gap:.38rem;
        font-size:12px; color:var(--txt-3);
    }
    .svc-dot {
        width:7px; height:7px; border-radius:50%; display:inline-block;
        flex-shrink:0; background:var(--dot,var(--ok));
        box-shadow:0 0 0 3px color-mix(in srgb, var(--dot,var(--ok)) 18%, transparent);
    }
    .svc-val { color:var(--txt-2); font-family:var(--mono); font-size:11.5px; }

    /* Hairline under the compact header row */
    .topbar-rule {
        height:1px; background:var(--border);
        margin:-.35rem 0 .85rem 0;
    }

    /* ══ Sidebar brand & nav ═══════════════════════════════════ */
    .side-brand { display:flex; align-items:center; gap:.65rem; padding:.2rem .15rem .55rem .15rem; }
    .side-brand .logo {
        width:34px; height:34px; border-radius:10px; flex-shrink:0;
        background:linear-gradient(135deg, var(--primary), color-mix(in srgb, var(--purple) 70%, var(--primary)));
        color:#fff; display:flex; align-items:center; justify-content:center;
        box-shadow:var(--shadow);
    }
    .side-brand .nm { font-size:14.5px; font-weight:700; color:var(--txt); line-height:1.2; letter-spacing:-.01em; }
    .side-brand .sb { font-size:11.5px; color:var(--txt-3); line-height:1.35; }

    .nav-group {
        font-size:11px; font-weight:600; letter-spacing:.09em;
        color:var(--txt-3); text-transform:uppercase;
        margin:.85rem 0 .35rem .55rem;
    }
    [data-testid="stSidebar"] .stButton > button,
    [data-testid="stSidebar"] button[data-testid^="stBaseButton-"] {
        width:100%; display:flex; align-items:center; justify-content:flex-start;
        background:transparent; border:none; box-shadow:none;
        border-radius:8px; color:var(--txt-2);
        font-size:13.5px; font-weight:500; padding:.42rem .6rem;
        transition:background .13s ease, color .13s ease;
    }
    [data-testid="stSidebar"] .stButton > button:hover,
    [data-testid="stSidebar"] button[data-testid^="stBaseButton-"]:hover {
        background:var(--hover-fill); border:none; box-shadow:none; color:var(--txt);
    }
    [data-testid="stSidebar"] .stButton > button p {
        font-size:13.5px; font-weight:500; text-align:left; color:inherit;
        text-transform:none; letter-spacing:0; font-family:var(--sans);
    }
    [data-testid="stSidebar"] .stButton > button .nv-ic {
        display:inline-flex; margin-right:.6rem; color:var(--txt-3);
        vertical-align:-4px;
    }
    [data-testid="stSidebar"] .stButton > button:hover .nv-ic { color:var(--txt-2); }
    .side-note {
        font-size:11.5px; color:var(--txt-3); background:var(--card-2);
        border:1px solid var(--border); border-radius:9px;
        padding:.5rem .6rem; line-height:1.5;
    }
    .side-note b { color:var(--txt-2); font-weight:600; }
    .side-foot { margin-top:.9rem; padding-top:.75rem; border-top:1px solid var(--border); }

    /* Theme toggle button in the header row (right column) */
    .st-key-topbar_theme_toggle {
        width: 100% !important;
        display: flex !important;
        justify-content: flex-end !important;
        align-items: center !important;
        margin-top: .85rem!important;
    }
    .st-key-topbar_theme_toggle button,
    .theme-btn button {
        border-radius:999px!important; font-size:12.5px!important;
        padding:.3rem .85rem!important;
    }
    .theme-btn button {
        min-width:64px!important; padding:.3rem .7rem!important;
    }
    .theme-btn button .tg-ic, .st-key-topbar_theme_toggle button .tg-ic {
        vertical-align:-3px; margin-right:.3rem;
    }

    /* ══ Cards ═════════════════════════════════════════════════ */
    .soc-card {
        background:var(--card); border:1px solid var(--border);
        border-radius:14px; padding:1.05rem 1.2rem;
        box-shadow:var(--shadow);
    }
    .soc-card.flush { padding:0; overflow:hidden; }
    .soc-card .card-head {
        display:flex; align-items:center; justify-content:space-between;
        gap:.75rem; padding:.85rem 1.2rem; border-bottom:1px solid var(--border);
    }
    .soc-card .card-title { font-size:13px; font-weight:600; color:var(--txt-2);
        letter-spacing:.02em; display:flex; align-items:center; gap:.5rem; }
    .soc-card .card-body { padding:1rem 1.2rem; }

    /* Home hero */
    .hero { padding:.4rem 0 1.2rem 0; }
    .hero h1 {
        font-size:26px!important; font-weight:700; letter-spacing:-.02em;
        color:var(--txt)!important; margin:0 0 .3rem 0;
    }
    .hero .hero-sub { font-size:15px; color:var(--txt-2); max-width:620px; }

    /* Section labels */
    .sec-label {
        display:flex; align-items:baseline; justify-content:space-between;
        margin:1.35rem 0 .6rem 0;
    }
    .sec-label .t {
        font-size:12px; font-weight:600; letter-spacing:.07em;
        color:var(--txt-3); text-transform:uppercase;
    }
    .sec-label .m { font-size:12px; color:var(--txt-3); }

    /* Metric cards */
    .metric-row { display:flex; gap:.75rem; flex-wrap:wrap; margin:.25rem 0; }
    .metric-card {
        flex:1 1 150px; min-width:140px;
        background:var(--card); border:1px solid var(--border);
        border-radius:12px; padding:.75rem 1rem; box-shadow:var(--shadow);
    }
    .metric-card .mk {
        font-size:11px; font-weight:600; letter-spacing:.06em;
        color:var(--txt-3); text-transform:uppercase; white-space:nowrap;
    }
    .metric-card .mv {
        font-size:22px; font-weight:700; color:var(--txt);
        margin-top:.15rem; line-height:1.15; letter-spacing:-.01em;
        font-family:var(--mono);
    }
    .metric-card .mv .u { font-size:12px; color:var(--txt-3); font-weight:400; }
    .metric-card .mv.small { font-size:17px; }

    /* Pills & chips */
    .pill {
        display:inline-flex; align-items:center; gap:.3rem;
        font-size:11.5px; font-weight:600; letter-spacing:.01em;
        padding:.14rem .6rem; border-radius:999px; white-space:nowrap;
        color:var(--pc,var(--txt-2)); background:color-mix(in srgb, var(--pc,var(--txt-2)) 12%, transparent);
        border:none;
    }
    .pill.solid { color:#fff!important; background:var(--pc,var(--txt-3)); }
    .chip {
        font-family:var(--mono); font-size:11.5px; color:var(--txt-2);
        background:var(--card-2); border:1px solid var(--border);
        border-radius:6px; padding:.1rem .48rem; white-space:nowrap;
    }
    .chip b { color:var(--txt); font-weight:600; }
    .mono { font-family:var(--mono); }

    /* Incident / result header */
    .inc-hero {
        background:var(--card); border:1px solid var(--border);
        border-radius:16px; box-shadow:var(--shadow);
        padding:1.15rem 1.35rem; margin-bottom:.9rem;
    }
    .inc-hero .kicker {
        font-size:12px; font-weight:600; letter-spacing:.08em;
        color:var(--txt-3); text-transform:uppercase;
        display:flex; align-items:center; gap:.45rem; margin-bottom:.35rem;
    }
    .inc-hero h2 {
        font-size:21px!important; font-weight:700; letter-spacing:-.015em;
        margin:0 0 .5rem 0; color:var(--txt)!important;
    }
    .inc-chips { display:flex; gap:.4rem; flex-wrap:wrap; align-items:center; }
    .inc-right { display:flex; flex-direction:column; gap:.4rem; align-items:flex-end; }

    /* Key-value grid */
    .kv { width:100%; border-collapse:collapse; }
    .kv td { padding:.3rem .6rem .3rem 0; vertical-align:top; font-size:13px; }
    .kv td.k {
        color:var(--txt-3); font-size:11.5px; font-weight:500;
        letter-spacing:.04em; text-transform:uppercase; white-space:nowrap;
        width:150px; padding-top:.42rem;
    }
    .kv td.v { color:var(--txt); }
    .kv td.v.mono, .kv td.v code { font-family:var(--mono); font-size:12.5px; }
    .kv tr + tr td { border-top:1px solid var(--border); }

    /* Data tables */
    .dt-wrap {
        border:1px solid var(--border); border-radius:12px; overflow:auto;
        background:var(--card); box-shadow:var(--shadow); max-height:430px;
    }
    table.dt { width:100%; border-collapse:collapse; font-size:13px; }
    table.dt th {
        position:sticky; top:0; z-index:1;
        background:var(--card-2); color:var(--txt-3);
        font-size:11px; font-weight:600; letter-spacing:.05em; text-transform:uppercase;
        text-align:left; padding:.5rem .75rem;
        border-bottom:1px solid var(--border); white-space:nowrap;
    }
    table.dt td {
        padding:.44rem .75rem; border-bottom:1px solid var(--border);
        color:var(--txt-2); vertical-align:top;
    }
    table.dt tbody tr:nth-child(even) td {
        background:color-mix(in srgb, var(--card-2) 45%, transparent);
    }
    table.dt tbody tr:last-child td { border-bottom:none; }
    table.dt tbody tr:hover td { background:var(--hover-fill); }
    table.dt td.mono, table.dt span.mono { font-family:var(--mono); font-size:12.5px; color:var(--txt); }
    table.dt td.wrap { white-space:normal; word-break:break-word; min-width:220px; }

    /* Expandable log rows */
    details.logrow { border-bottom:1px solid var(--border); background:var(--card); }
    details.logrow:last-child { border-bottom:none; }
    details.logrow summary {
        list-style:none; cursor:pointer; display:flex; gap:.75rem;
        padding:.42rem .8rem; font-family:var(--mono); font-size:12px;
        align-items:baseline;
    }
    details.logrow summary::-webkit-details-marker { display:none; }
    details.logrow summary:hover { background:var(--hover-fill); }
    details.logrow summary::before {
        content:"›"; color:var(--txt-3); font-size:12px; flex-shrink:0;
        transition:transform .12s ease;
    }
    details.logrow[open] summary::before { transform:rotate(90deg); }
    details.logrow summary .ts { color:var(--txt-3); white-space:nowrap; min-width:132px; }
    details.logrow summary .host { color:var(--primary); min-width:92px; }
    details.logrow summary .code { color:var(--warn); min-width:58px; }
    details.logrow summary .sig {
        color:var(--txt-2); white-space:nowrap; overflow:hidden;
        text-overflow:ellipsis; max-width:520px;
    }
    details.logrow pre {
        margin:0; padding:.55rem .85rem; background:var(--card-3);
        font-family:var(--mono); font-size:11.5px; line-height:1.6;
        color:var(--txt-2); border-top:1px solid var(--border);
        white-space:pre-wrap; border-radius:0;
    }

    /* Timeline */
    .tl { position:relative; margin-left:.45rem; padding-left:1.35rem;
          border-left:2px solid var(--border); }
    details.tl-ev { position:relative; padding:.28rem 0; }
    details.tl-ev::before {
        content:""; position:absolute; left:calc(-1.35rem - 6px); top:.62rem;
        width:10px; height:10px; border-radius:50%;
        background:var(--tl-color,var(--ok));
        box-shadow:0 0 0 3px color-mix(in srgb, var(--tl-color,var(--ok)) 20%, transparent);
    }
    details.tl-ev summary {
        list-style:none; cursor:pointer; display:flex; gap:.7rem;
        align-items:baseline; flex-wrap:wrap; padding:.32rem .55rem;
        border-radius:8px;
    }
    details.tl-ev summary::-webkit-details-marker { display:none; }
    details.tl-ev summary:hover { background:var(--hover-fill); }
    details.tl-ev summary .chev {
        margin-left:auto; color:var(--txt-3); font-size:12px;
        transition:transform .12s ease;
    }
    details.tl-ev[open] summary .chev { transform:rotate(90deg); }
    .tl-time { font-family:var(--mono); font-size:11.5px; color:var(--txt-3); min-width:60px; }
    .tl-node {
        font-size:13px; font-weight:600; color:var(--txt); min-width:170px;
    }
    .tl-sum { font-size:13.5px; color:var(--txt-2); }
    .tl-extra { font-family:var(--mono); font-size:11.5px; color:var(--txt-3); }
    .tl-body {
        margin:.25rem 0 .5rem 0; padding:.6rem .8rem;
        background:var(--card-2); border:1px solid var(--border);
        border-radius:10px;
    }
    .tl-body .kv td.k { width:120px; }
    .tl-mini { font-size:13px; color:var(--txt-2); padding:.14rem 0; }
    .tl-mini b { color:var(--txt); font-weight:600; }
    .tl-mini .arr { color:var(--txt-3); padding:0 .25rem; }
    .tb-k {
        font-size:11px; font-weight:600; letter-spacing:.05em;
        color:var(--txt-3); text-transform:uppercase; margin-bottom:.15rem;
    }

    /* Choice cards (New Investigation) */
    .stApp [data-testid="stVerticalBlock"] { gap:.6rem; }
    .choice-grid { display:flex; gap:1rem; flex-wrap:wrap; margin:.9rem 0 .4rem 0; }
    .choice-card {
        flex:1 1 240px; max-width:340px;
        background:var(--card); border:1px solid var(--border);
        border-radius:14px; padding:1.15rem 1.2rem;
        box-shadow:var(--shadow); cursor:default;
        transition:border-color .16s ease, box-shadow .16s ease, transform .16s ease;
    }
    .choice-card:hover {
        border-color:color-mix(in srgb, var(--primary) 55%, var(--border));
        box-shadow:var(--shadow-lift); transform:translateY(-2px);
    }
    .choice-card.selected {
        border-color:var(--primary);
        outline:2px solid color-mix(in srgb, var(--primary) 30%, transparent);
    }
    .choice-ic {
        width:40px; height:40px; border-radius:10px;
        display:flex; align-items:center; justify-content:center;
        background:var(--primary-soft); color:var(--primary); margin-bottom:.7rem;
    }
    .choice-ic.purple { background:var(--purple-soft); color:var(--purple); }
    .choice-ic.green { background:var(--ok-soft); color:var(--ok); }
    .choice-title { font-size:15px; font-weight:600; color:var(--txt); margin-bottom:.2rem; }
    .choice-desc { font-size:13px; color:var(--txt-2); line-height:1.5; }

    /* Template cards */
    .tpl-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(300px,1fr));
                gap:.85rem; margin:.8rem 0; }
    .tpl-card {
        background:var(--card); border:1px solid var(--border);
        border-radius:14px; padding:1.05rem 1.15rem; box-shadow:var(--shadow);
        display:flex; flex-direction:column; gap:.5rem;
        transition:border-color .16s ease, box-shadow .16s ease, transform .16s ease;
    }
    .tpl-card:hover {
        border-color:color-mix(in srgb, var(--primary) 55%, var(--border));
        box-shadow:var(--shadow-lift); transform:translateY(-2px);
    }
    .tpl-card.selected {
        border-color:var(--primary);
        outline:2px solid color-mix(in srgb, var(--primary) 30%, transparent);
    }
    .tpl-top { display:flex; align-items:flex-start; justify-content:space-between; gap:.6rem; }
    .tpl-title { font-size:14.5px; font-weight:600; color:var(--txt); line-height:1.35; }
    .tpl-desc { font-size:13px; color:var(--txt-2); line-height:1.5; flex-grow:1; }
    .tpl-foot { display:flex; align-items:center; justify-content:space-between; gap:.5rem; }

    /* ATT&CK technique cards */
    .tech-card {
        background:var(--card); border:1px solid var(--border); border-radius:12px;
        padding:.9rem 1.1rem; box-shadow:var(--shadow); margin-bottom:.65rem;
    }
    .tech-id {
        font-family:var(--mono); font-size:12px; font-weight:600;
        color:var(--purple); background:var(--purple-soft);
        border-radius:6px; padding:.14rem .5rem; white-space:nowrap;
    }
    .tech-name { font-size:14px; color:var(--txt); font-weight:600; }
    .tech-body {
        border-top:1px solid var(--border); margin-top:.6rem; padding-top:.6rem;
        font-size:13px; color:var(--txt-2); line-height:1.55;
    }

    /* Action cards */
    .act-row {
        display:flex; align-items:stretch; border:1px solid var(--border);
        border-radius:12px; background:var(--card); box-shadow:var(--shadow);
        margin-bottom:.6rem; overflow:hidden;
    }
    .act-risk { width:4px; flex-shrink:0; background:var(--rc,var(--ok)); }
    .act-main { padding:.75rem .95rem; flex:1; min-width:0; }
    .act-title { font-size:14px; font-weight:600; color:var(--txt); letter-spacing:0; }
    .act-meta {
        display:flex; gap:1.1rem; flex-wrap:wrap; margin-top:.3rem;
        font-size:12px; color:var(--txt-3);
    }
    .act-meta b { color:var(--txt-2); font-weight:600; }
    .act-just { font-size:13px; color:var(--txt-2); margin-top:.35rem; line-height:1.5; }

    /* Blast radius hop ladder */
    .hop-ladder { font-size:13px; }
    .hop-tier { display:flex; align-items:flex-start; gap:.7rem; }
    .hop-badge {
        flex-shrink:0; font-size:10.5px; font-weight:600; letter-spacing:.06em;
        color:var(--hc,var(--txt-3)); background:color-mix(in srgb, var(--hc,var(--txt-3)) 10%, transparent);
        border-radius:999px; padding:.14rem .55rem; margin-top:.1rem; min-width:66px;
        text-align:center; text-transform:uppercase;
    }
    .hop-nodes { display:flex; flex-wrap:wrap; gap:.4rem; }
    .hop-node {
        display:inline-flex; align-items:center; gap:.35rem;
        font-size:12.5px; color:var(--txt); background:var(--card-2);
        border:1px solid var(--border-strong); border-radius:8px;
        padding:.24rem .58rem;
    }
    .hop-node .nlab { font-size:10px; letter-spacing:.05em; color:var(--txt-3);
                      text-transform:uppercase; font-weight:600; }
    .hop-link { color:var(--border-strong); padding:.05rem 0 .22rem 34px;
                font-size:11px; user-select:none; }

    /* Banners / callouts */
    .callout {
        display:flex; align-items:flex-start; gap:.65rem;
        border-radius:11px; padding:.65rem .9rem; margin:.6rem 0;
        font-size:13.5px; color:var(--txt-2); line-height:1.5;
        background:var(--cbg,var(--card-2)); border:1px solid
            color-mix(in srgb, var(--cacc,var(--txt-3)) 35%, var(--border));
    }
    .callout .c-ic { color:var(--cacc,var(--txt-2)); flex-shrink:0; margin-top:.1rem; }
    .callout b { color:var(--txt); }

    /* Empty states */
    .empty-state {
        border:1.5px dashed var(--border-strong); border-radius:16px;
        background:var(--card); padding:2.4rem 1.5rem; text-align:center;
    }
    .empty-state .eic {
        width:52px; height:52px; border-radius:14px; margin:0 auto .85rem auto;
        background:var(--card-2); color:var(--txt-3);
        display:flex; align-items:center; justify-content:center;
    }
    .empty-state .et { font-size:15.5px; font-weight:600; color:var(--txt); }
    .empty-state .eh { font-size:13.5px; color:var(--txt-3); margin-top:.3rem; max-width:420px;
                       margin-left:auto; margin-right:auto; line-height:1.55; }
    .pipe-diagram {
        display:inline-flex; align-items:center; gap:.5rem; margin-top:1.15rem;
        flex-wrap:wrap; justify-content:center;
    }
    .pipe-stage {
        font-family:var(--mono); font-size:11.5px; color:var(--txt-2);
        border:1px solid var(--border); border-radius:999px;
        padding:.22rem .68rem; background:var(--card-2);
    }
    .pipe-arrow { color:var(--txt-3); font-size:11px; }

    /* Guardrail flag rows */
    .flag-row {
        display:flex; gap:.6rem; align-items:baseline; padding:.45rem .75rem;
        border:1px solid color-mix(in srgb, var(--crit) 35%, var(--border));
        background:var(--crit-soft); border-radius:10px;
        margin-bottom:.35rem; font-size:12.5px; color:var(--txt-2);
    }
    .flag-row .fl { color:var(--crit); font-weight:700; font-size:10.5px;
                    letter-spacing:.07em; }

    /* Agent tool-call cards */
    .tool-card {
        border:1px solid var(--border); border-radius:12px;
        background:var(--card); box-shadow:var(--shadow);
        margin-bottom:.55rem; overflow:hidden;
    }
    .tool-card .tc-head {
        display:flex; align-items:center; gap:.65rem; padding:.5rem .9rem;
        border-bottom:1px solid var(--border); background:var(--card-2);
    }
    .tool-card .tc-step {
        font-family:var(--mono); font-size:10.5px; color:var(--txt-3);
        border:1px solid var(--border); border-radius:6px; padding:.04rem .4rem;
    }
    .tool-card .tc-name {
        font-family:var(--mono); font-size:13px; font-weight:600;
        color:var(--primary);
    }
    .tool-card .tc-body { padding:.6rem .9rem .7rem .9rem; }
    .tc-field { margin-bottom:.4rem; }
    .tc-field:last-child { margin-bottom:0; }
    .tc-fk { font-size:10.5px; font-weight:600; letter-spacing:.06em;
             color:var(--txt-3); text-transform:uppercase; margin-bottom:.08rem; }
    .tc-fv { font-size:13px; color:var(--txt-2); font-family:var(--mono);
             white-space:pre-wrap; word-break:break-word; }
    .tc-inline-details summary {
        cursor:pointer; list-style:none; font-size:11px; font-weight:600;
        letter-spacing:.06em; color:var(--txt-3); text-transform:uppercase;
    }
    .tc-inline-details summary::-webkit-details-marker { display:none; }
    .tc-inline-details summary:hover { color:var(--txt-2); }
    .tc-inline-details pre {
        margin:.3rem 0 0 0; padding:.5rem .6rem; background:var(--card-3);
        border:1px solid var(--border); border-radius:8px;
        font-family:var(--mono); font-size:11.5px; line-height:1.55;
        color:var(--txt-2); max-height:230px; overflow:auto; white-space:pre-wrap;
    }

    /* RCA report sections */
    .rca-sec { margin-bottom:1.1rem; }
    .rca-sec .rs-head {
        font-size:12px; font-weight:600; letter-spacing:.07em;
        color:var(--txt-3); text-transform:uppercase; margin-bottom:.4rem;
        display:flex; align-items:baseline; justify-content:space-between;
    }
    .rca-sec .rs-body {
        font-size:14.5px; color:var(--txt); line-height:1.65;
        background:var(--card); border:1px solid var(--border);
        border-radius:12px; padding:.95rem 1.15rem; box-shadow:var(--shadow);
    }
    .rca-sec .rs-body.plain {
        background:transparent; border:none; box-shadow:none; padding:.15rem .1rem;
    }

    @media (max-width: 1500px) {
        .metric-card { min-width:130px; }
    }
    </style>
    """, unsafe_allow_html=True)


# ── Status indicators ─────────────────────────────────────────────────────────


def svc_dot(label: str, status: str, detail: str = "") -> str:
    """Compact '● LABEL detail' indicator."""
    c = _DOT_COLORS.get(str(status).lower(), "var(--txt-3)")
    d = f' <span class="svc-val">{esc(detail)}</span>' if detail else ""
    return (f'<span class="svc-item">'
            f'<span class="svc-dot" style="--dot:{c};"></span>'
            f'<span>{esc(label)}</span>{d}</span>')


def pill(text: str, color: str = "var(--txt-2)") -> str:
    return (f'<span class="pill" style="--pc:{color};">{esc(text)}</span>')


def severity_pill(severity: str) -> str:
    c = SEVERITY_COLOR.get(str(severity).lower(), "var(--txt-3)")
    return pill(str(severity).upper(), c)


def status_pill(final_status) -> str:
    val = getattr(final_status, "value", final_status)
    key = str(val or "running").lower()
    c = STATUS_COLOR.get(key, "var(--txt-3)")
    return pill(STATUS_LABEL.get(key, key.replace("_", " ").title()), c)


def conf_badge(conf: float) -> str:
    pct = float(conf)
    if pct <= 1.0:
        pct *= 100
    if pct >= 70:
        c = "var(--ok)"
    elif pct >= 40:
        c = "var(--warn)"
    else:
        c = "var(--txt-3)"
    return pill(f"{pct:.0f}% confidence", c)


def risk_pill(risk: str) -> str:
    c = RISK_COLOR.get(str(risk).lower(), "var(--txt-3)")
    return pill(f"{str(risk).capitalize()} risk", c)


def hil_badge(required: bool) -> str:
    if required:
        return pill("Analyst approval required", "var(--crit)")
    return pill("Advisory", "var(--txt-3)")


# ── Layout blocks ─────────────────────────────────────────────────────────────


def section_label(title: str, meta: str = "") -> None:
    m = f'<span class="m">{esc(meta)}</span>' if meta else ""
    st.markdown(f'<div class="sec-label"><span class="t">{esc(title)}</span>{m}</div>',
                unsafe_allow_html=True)


def callout(text_html: str, kind: str = "info", ic: str | None = None,
            title: str = "") -> None:
    """Soft themed callout. kind: info | success | warning | danger"""
    acc = {"info": "var(--primary)", "success": "var(--ok)",
           "warning": "var(--warn)", "danger": "var(--crit)"}.get(kind, "var(--txt-3)")
    bg = {"info": "var(--primary-soft)", "success": "var(--ok-soft)",
          "warning": "var(--warn-soft)", "danger": "var(--crit-soft)"}.get(
        kind, "var(--card-2)")
    ic_name = ic or {"info": "info", "success": "check-circle",
                     "warning": "alert-triangle", "danger": "alert-triangle"}[kind]
    t = f'<div><b>{esc(title)}</b>&nbsp; ' if title else "<div>"
    st.markdown(
        f'<div class="callout" style="--cacc:{acc};--cbg:{bg};">'
        f'<span class="c-ic">{icon(ic_name, 16)}</span>'
        f'{t}{text_html}</div></div>',
        unsafe_allow_html=True)


def metric_cards(items: list[dict]) -> None:
    """
    Compact metric cards.
    items: [{k: label, v: value, u?: unit, c?: css color, small?: bool}]
    """
    cells = []
    for it in items:
        color = f"color:{it['c']};" if it.get("c") else ""
        unit = f'<span class="u"> {esc(it["u"])}</span>' if it.get("u") else ""
        cls = "mv small" if it.get("small") else "mv"
        val = it["v"]
        cells.append(
            f'<div class="metric-card"><div class="mk">{esc(it["k"])}</div>'
            f'<div class="{cls}" style="{color}">{val}{unit}</div></div>'
        )
    st.markdown(f'<div class="metric-row">{"".join(cells)}</div>',
                unsafe_allow_html=True)


def kv_table(rows: list[tuple[str, str]]) -> str:
    body = "".join(
        f'<tr><td class="k">{esc(k)}</td><td class="v">{v}</td></tr>'
        for k, v in rows
    )
    return f'<table class="kv">{body}</table>'


def data_table(headers: list[str], rows: list[list[str]],
               heights: str = "360px") -> str:
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>"
                   for r in rows)
    return (f'<div class="dt-wrap" style="max-height:{heights};">'
            f'<table class="dt"><thead><tr>{head}</tr></thead>'
            f"<tbody>{body}</tbody></table></div>")


def timeline_event(node_label: str, color: str, time_str: str,
                   headline_html: str, extra: str, body_html: str) -> str:
    """
    One expandable node in the investigation timeline.
    Emitted as a single HTML line — Streamlit's markdown parser escapes
    indented multi-line markup into code blocks otherwise.
    """
    extra_html = f'<span class="tl-extra"> · {esc(extra)}</span>' if extra else ""
    return (f'<details class="tl-ev" style="--tl-color:{color};">'
            f'<summary>'
            f'<span class="tl-time">{esc(time_str)}</span>'
            f'<span class="tl-node">{esc(node_label)}</span>'
            f'<span class="tl-sum">{headline_html}</span>'
            f'{extra_html}'
            f'<span class="chev">{icon("chevron-right", 13)}</span>'
            f'</summary>'
            f'<div class="tl-body">{body_html}</div>'
            f'</details>')


def pipeline_diagram(stages: list[str]) -> str:
    parts = []
    for i, s in enumerate(stages):
        if i:
            parts.append(f'<span class="pipe-arrow">{icon("arrow-right", 12)}</span>')
        parts.append(f'<span class="pipe-stage">{esc(s)}</span>')
    return f'<div class="pipe-diagram">{"".join(parts)}</div>'


def empty_state(title: str, hint: str = "", ic: str = "search",
                stages: list[str] | None = None) -> None:
    h = f'<div class="eh">{hint}</div>' if hint else ""
    diagram = pipeline_diagram(stages) if stages else ""
    st.markdown(
        '<div class="empty-state">'
        f'<div class="eic">{icon(ic, 24)}</div>'
        f'<div class="et">{esc(title)}</div>{h}{diagram}</div>',
        unsafe_allow_html=True)


# Backwards-compatible alias used by older views.
def empty_console(title: str, hint: str = "", stages: list[str] | None = None) -> None:
    empty_state(title, hint, ic="search", stages=stages)


def banner(tag: str, text: str) -> None:
    callout(f'<span class="mono">{esc(tag)}</span> — {text}', kind="info")


def json_details(label: str, obj) -> None:
    """Collapsible raw-JSON block for technical drill-down."""
    try:
        txt = _json.dumps(obj, indent=2, default=str)
    except Exception:
        txt = str(obj)
    txt = esc(txt)
    st.markdown(
        '<details class="logrow"><summary>'
        f'<span style="color:var(--txt-3);font-family:var(--mono);font-size:11.5px;">'
        f'{esc(label)}</span></summary><pre>{txt}</pre></details>',
        unsafe_allow_html=True)
