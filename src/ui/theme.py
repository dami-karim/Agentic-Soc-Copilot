"""
Global theme system — Light & Dark palettes driven by CSS variables.

The active theme is stored in ``st.session_state["theme"]`` ("light"/"dark")
and survives Streamlit reruns within the session. ``load()`` emits one
stylesheet whose ``:root`` variables are resolved from the active palette,
so every component (native widgets and custom HTML alike) adapts instantly.

Design language: modern enterprise product — warm off-white canvas and
white cards in light mode, soft charcoal (never pure black) in dark mode,
hairline borders, restrained semantic color, generous whitespace.
"""
from __future__ import annotations

import streamlit as st

# ── Palettes ──────────────────────────────────────────────────────────────────

PALETTES: dict[str, dict[str, str]] = {
    "light": {
        "bg":            "#F7F8FA",   # app canvas (warm off-white)
        "bg-accent":     "#EEF1F5",   # subtle section tint on canvas
        "card":          "#FFFFFF",   # raised card surface
        "card-2":        "#F3F5F8",   # secondary fill inside cards
        "card-3":        "#EBEEF3",   # sunken fill / code surfaces
        "border":        "#E5E7EB",
        "border-strong": "#D3D9E3",
        "txt":           "#1F2937",
        "txt-2":         "#667085",   # secondary text
        "txt-3":         "#98A2B3",   # faint labels
        "primary":       "#3565D9",
        "primary-hov":   "#2B54BB",
        "primary-soft":  "#E8EFFC",   # tinted background for primary chips
        "purple":        "#6D53C8",
        "purple-soft":   "#EEEAF9",
        "ok":            "#178A56",
        "ok-soft":       "#E3F4EC",
        "warn":          "#B47710",
        "warn-soft":     "#FBF0DC",
        "crit":          "#CF4444",
        "crit-soft":     "#FBEAEA",
        "shadow":        "0 1px 2px rgba(16,24,40,.05)",
        "shadow-lift":   "0 6px 16px -6px rgba(16,24,40,.12)",
        "scroll-thumb":  "#CBD2DC",
        "hover-fill":    "#F2F4F8",
    },
    "dark": {
        "bg":            "#111318",
        "bg-accent":     "#14171D",
        "card":          "#181B22",
        "card-2":        "#20242C",
        "card-3":        "#262B34",
        "border":        "#2A2F3A",
        "border-strong": "#383F4D",
        "txt":           "#F3F4F6",
        "txt-2":         "#9CA3AF",
        "txt-3":         "#6B7280",
        "primary":       "#7AA2F0",
        "primary-hov":   "#93B4F4",
        "primary-soft":  "#1D2739",
        "purple":        "#A18BEA",
        "purple-soft":   "#232135",
        "ok":            "#4BC48C",
        "ok-soft":       "#17291F",
        "warn":          "#D9A648",
        "warn-soft":     "#2B2312",
        "crit":          "#E06C63",
        "crit-soft":     "#2D1B19",
        "shadow":        "0 1px 2px rgba(0,0,0,.25)",
        "shadow-lift":   "0 8px 20px -8px rgba(0,0,0,.45)",
        "scroll-thumb":  "#333A46",
        "hover-fill":    "#1F242D",
    },
}

SANS = ("'Inter','Segoe UI',system-ui,-apple-system,'Helvetica Neue',"
        "Arial,sans-serif")
MONO = ("'JetBrains Mono','SF Mono','Cascadia Code',Consolas,"
        "'Liberation Mono',monospace")


def current_theme() -> str:
    t = st.session_state.get("theme", "light")
    return t if t in PALETTES else "light"


def palette() -> dict[str, str]:
    """Python-side view of the active palette (for the rare non-CSS use)."""
    return PALETTES[current_theme()]


def font_links() -> None:
    """Best-effort webfont load; silent graceful fallback when offline."""
    st.markdown(
        '<link rel="preconnect" href="https://fonts.googleapis.com">'
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
        '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;'
        '500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" '
        'rel="stylesheet">',
        unsafe_allow_html=True,
    )


def load() -> None:
    """Inject the global stylesheet for the ACTIVE theme (once per run)."""
    p = PALETTES[current_theme()]
    v = "".join(f"--{k}:{val};" for k, val in p.items())
    st.markdown(f"""
    <style>
    :root {{{v}
        --sans:{SANS}; --mono:{MONO};
    }}

    /* ── App chrome ─────────────────────────────────────────────── */
    .stApp {{
        background: var(--bg); color: var(--txt);
        font-family: var(--sans); font-size: 14px; line-height: 1.55;
    }}
    [data-testid="stHeader"] {{
        background: transparent; height: 0; min-height: 0;
    }}
    [data-testid="stHeader"] * {{ display: none; }}
    #MainMenu, footer, [data-testid="stStatusWidget"] {{ visibility: hidden; }}
    /* Streamlit ≥1.59 publishes the main canvas as stMainBlockContainer;
       older builds used .block-container under stAppViewContainer. */
    [data-testid="stMainBlockContainer"],
    [data-testid="stAppViewContainer"] > .main .block-container {{
        padding: 1.05rem 2rem 3rem 2rem!important; max-width: 1460px;
    }}
    h1,h2,h3,h4,h5,h6 {{
        color: var(--txt)!important; font-weight: 600;
        letter-spacing: -.01em; line-height: 1.3;
    }}
    p {{ margin-bottom: .35rem; }}
    a {{ color: var(--primary); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    code {{
        font-family: var(--mono); font-size: .88em;
        background: var(--card-3); color: var(--txt);
        border: 1px solid var(--border); border-radius: 5px;
        padding: .08em .38em;
    }}
    hr {{ border: none; border-top: 1px solid var(--border); margin: .7rem 0; }}
    ::selection {{ background: var(--primary); color: #fff; }}

    ::-webkit-scrollbar {{ width: 10px; height: 10px; }}
    ::-webkit-scrollbar-track {{ background: transparent; }}
    ::-webkit-scrollbar-thumb {{
        background: var(--scroll-thumb); border-radius: 6px;
        border: 2px solid var(--bg);
    }}
    ::-webkit-scrollbar-thumb:hover {{ filter: brightness(.92); }}

    /* ── Sidebar ────────────────────────────────────────────────── */
    [data-testid="stSidebar"] {{
        background: var(--card);
        border-right: 1px solid var(--border);
        min-width: 264px; max-width: 264px;
    }}
    [data-testid="stSidebar"] .block-container {{
        padding: .9rem .8rem 1.6rem .8rem;
    }}
    [data-testid="stSidebar"] hr {{
        margin: .65rem 0!important; border-color: var(--border)!important;
    }}
    [data-testid="stSidebar"] [data-testid="stSidebarHeader"] {{
        display: none; height: 0;
    }}
    [data-testid="stSidebar"] * {{ font-size: 13px; }}

    /* ── Widgets: inputs, selects, textarea ─────────────────────── */
    .stTextInput input, .stTextArea textarea, .stNumberInput input {{
        background: var(--card)!important;
        border: 1px solid var(--border-strong)!important;
        color: var(--txt)!important;
        font-family: var(--sans); font-size: 13.5px!important;
        border-radius: 9px!important; padding: .42rem .75rem!important;
        box-shadow: var(--shadow)!important;
    }}
    .stTextInput input::placeholder, .stTextArea textarea::placeholder {{
        color: var(--txt-3)!important;
    }}
    .stTextInput input:focus, .stTextArea textarea:focus, .stNumberInput input:focus {{
        border-color: var(--primary)!important;
        box-shadow: 0 0 0 3px color-mix(in srgb, var(--primary) 16%, transparent)!important;
    }}
    div[data-baseweb="select"] > div {{
        background: var(--card)!important;
        border: 1px solid var(--border-strong)!important;
        border-radius: 9px!important; font-size: 13.5px!important;
        color: var(--txt)!important; min-height: 38px;
        box-shadow: var(--shadow)!important;
    }}
    div[data-baseweb="popover"] {{
        background: var(--card)!important;
        border: 1px solid var(--border-strong)!important;
        border-radius: 10px!important;
        box-shadow: var(--shadow-lift)!important;
        font-family: var(--sans); font-size: 13.5px;
    }}
    div[data-baseweb="popover"] li {{
        color: var(--txt)!important; border-radius: 6px;
    }}
    div[data-baseweb="popover"] li:hover {{
        background: var(--hover-fill)!important;
    }}
    .stRadio label, .stCheckbox label {{
        font-size: 13.5px; color: var(--txt-2);
    }}
    .stRadio [role="radiogroup"] {{ gap: .35rem; }}
    span[data-testid="stFileUploaderDropzone"] {{
        background: var(--card); border: 1.5px dashed var(--border-strong);
        border-radius: 10px; font-size: 13px; color: var(--txt-2);
    }}
    span[data-testid="stFileUploaderDropzone"] button {{
        background: var(--card-2)!important; border: 1px solid var(--border)!important;
        color: var(--txt)!important; border-radius: 7px!important;
    }}
    label[data-testid="stWidgetLabel"] p {{ color: var(--txt-2)!important; }}

    /* ── Buttons ────────────────────────────────────────────────── */
    /* Streamlit ≥1.59 no longer wraps buttons in a '.stButton' div; it
       ships 'button[data-testid=stBaseButton-...]' directly, so both
       selectors are needed. Without this, plain buttons fall back to
       Streamlit's always-light base theme and vanish on light canvas. */
    .stButton > button,
    button[data-testid^="stBaseButton-"] {{
        background: var(--card); color: var(--txt);
        border: 1px solid var(--border-strong); border-radius: 9px;
        font-family: var(--sans); font-size: 13.5px; font-weight: 500;
        padding: .38rem .95rem;
        box-shadow: var(--shadow);
        transition: background .15s ease, border-color .15s ease,
                    box-shadow .15s ease, transform .15s ease;
    }}
    .stButton > button:hover,
    button[data-testid^="stBaseButton-"]:hover {{
        background: var(--hover-fill); border-color: var(--border-strong);
        color: var(--txt);
    }}
    .stButton > button:focus-visible,
    button[data-testid^="stBaseButton-"]:focus-visible {{
        outline: 2px solid color-mix(in srgb, var(--primary) 55%, transparent);
        outline-offset: 1px;
    }}
    .stButton > button[kind="primary"],
    .stButton > button[data-testid*="aseButton-primary"],
    button[data-testid^="stBaseButton-primary"] {{
        background: var(--primary)!important; border-color: var(--primary)!important;
        color: #fff!important; font-weight: 600;
    }}
    .stButton > button[kind="primary"]:hover,
    .stButton > button[data-testid*="aseButton-primary"]:hover,
    button[data-testid^="stBaseButton-primary"]:hover {{
        background: var(--primary-hov)!important; border-color: var(--primary-hov)!important;
        box-shadow: var(--shadow-lift);
    }}
    .stButton > button:disabled,
    button[data-testid^="stBaseButton-"]:disabled {{
        background: var(--card-2)!important; border-color: var(--border)!important;
        color: var(--txt-3)!important; box-shadow: none;
    }}
    button[data-testid^="stDownloadButton"] button {{
        background: var(--card); color: var(--txt);
        border: 1px solid var(--border-strong); border-radius: 9px;
        font-family: var(--sans); font-size: 13.5px; font-weight: 500;
        padding: .38rem .95rem; box-shadow: var(--shadow);
    }}
    button[data-testid^="stDownloadButton"] button:hover {{
        background: var(--hover-fill); border-color: var(--border-strong);
    }}

    /* ── Tabs ───────────────────────────────────────────────────── */
    .stTabs [data-baseweb="tab-list"] {{
        gap: .25rem; background: transparent; border-bottom: 1px solid var(--border);
    }}
    .stTabs [data-baseweb="tab"] {{
        background: transparent; border: none; border-radius: 8px 8px 0 0;
        padding: 7px 15px; margin-bottom: -1px;
    }}
    .stTabs [data-baseweb="tab"]:hover p {{ color: var(--txt)!important; }}
    .stTabs [aria-selected="true"] {{
        background: transparent!important;
        border-bottom: 2px solid var(--primary)!important;
    }}
    .stTabs [data-baseweb="tab-highlight"],
    .stTabs [data-baseweb="tab-border"] {{ display: none; }}
    .stTabs button p {{
        font-family: var(--sans); font-size: 13.5px; font-weight: 500;
        letter-spacing: 0; color: var(--txt-2); text-transform: none;
    }}
    .stTabs [aria-selected="true"] p {{ color: var(--primary)!important; font-weight: 600; }}

    /* ── Expanders ──────────────────────────────────────────────── */
    details[data-testid="stExpander"], [data-testid="stExpander"] {{
        border: 1px solid var(--border)!important; border-radius: 11px!important;
        background: var(--card); overflow: hidden;
        box-shadow: var(--shadow);
    }}
    details[data-testid="stExpander"] summary, [data-testid="stExpander"] summary {{
        padding: .55rem .9rem; font-size: 13.5px;
    }}
    details[data-testid="stExpander"] summary:hover,
    [data-testid="stExpander"] summary:hover {{ background: var(--hover-fill); }}
    details[data-testid="stExpander"] summary strong {{ font-weight: 600; }}

    /* ── Alerts → soft callouts ─────────────────────────────────── */
    div[data-testid="stAlert"] {{
        background: var(--card-2); border: 1px solid var(--border);
        border-radius: 10px; color: var(--txt-2);
        font-size: 13.5px; padding: .6rem .85rem;
    }}
    div[data-testid="stAlert"] p {{ font-size: 13.5px; color: var(--txt-2); }}

    /* ── Dataframes / JSON / status ─────────────────────────────── */
    [data-testid="stDataFrame"] {{
        border: 1px solid var(--border); border-radius: 10px;
        background: var(--card);
    }}
    [data-testid="stJson"] {{
        background: var(--card-3)!important; border: 1px solid var(--border);
        border-radius: 8px; font-family: var(--mono); font-size: 12px;
        color: var(--txt-2);
    }}
    div[data-testid="stStatus"] {{
        background: var(--card); border: 1px solid var(--border);
        border-radius: 12px; box-shadow: var(--shadow);
        font-size: 13.5px; color: var(--txt);
    }}
    div[data-testid="stStatus"] details {{ background: transparent; }}
    div[data-testid="stSpinner"] {{ color: var(--txt-2); }}

    /* ── Markdown tables (native) ───────────────────────────────── */
    .stMarkdown table {{
        border-collapse: collapse; width: 100%;
        font-size: 13.5px;
    }}
    .stMarkdown th {{
        text-align: left; color: var(--txt-3); font-weight: 600;
        font-size: 12px; letter-spacing: .04em; text-transform: uppercase;
        padding: .45rem .7rem; border-bottom: 1px solid var(--border);
    }}
    .stMarkdown td {{
        padding: .5rem .7rem; border-bottom: 1px solid var(--border);
        color: var(--txt);
    }}

    /* Smooth theme switch on the big surfaces */
    .stApp, [data-testid="stSidebar"],
    .soc-card, .soc-topbar, .nav-item {{
        transition: background-color .22s ease, border-color .22s ease;
    }}
    </style>
    """, unsafe_allow_html=True)
