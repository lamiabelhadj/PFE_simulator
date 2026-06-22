"""
IoT Authentication Simulator — Streamlit UI

Run from the IoT_auth_simulator/ directory:
    streamlit run simulator/UI/ui_app.py
"""

import sys
import time
from pathlib import Path

# Windows consoles default to cp1252, which cannot encode characters like '→'
# used in log/print output across the simulator.
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
import seaborn as sns

from simulator.config.settings import cfg, DATA_DIR


# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IoT Auth Simulator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<link rel="stylesheet"
  href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;600;700&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">

<style>
  :root {
    --accent: #4f9cf0;
    --accent-2: #6f5cf0;
    --accent-3: #36d6c3;
    --accent-glow: rgba(79,156,240,0.55);
    --grad: linear-gradient(135deg, #4f9cf0 0%, #6f5cf0 55%, #8b5cf6 100%);
    --grad-soft: linear-gradient(135deg, rgba(79,156,240,0.16), rgba(111,92,240,0.13));
    --card: rgba(255,255,255,0.028);
    --card-2: rgba(255,255,255,0.04);
    --card-border: rgba(255,255,255,0.08);
    --card-border-hi: rgba(79,156,240,0.42);
    --muted: rgba(201,209,217,0.55);
    --text: #e8edf4;
    --shadow: 0 18px 48px -24px rgba(0,0,0,0.85);
    --shadow-hi: 0 24px 60px -22px rgba(79,156,240,0.45);
  }

  html, body, [class*="css"], [data-testid="stAppViewContainer"] {
    font-family: 'Inter', -apple-system, sans-serif;
    color: var(--text);
  }

  /* ── Animated aurora background ─────────────────────────────────────────── */
  [data-testid="stAppViewContainer"] {
    background:
      radial-gradient(1100px 520px at 78% -12%, rgba(79,156,240,0.13), transparent 60%),
      radial-gradient(900px 500px at 8% 6%, rgba(111,92,240,0.10), transparent 55%),
      radial-gradient(760px 460px at 92% 88%, rgba(54,214,195,0.07), transparent 60%),
      #080a10;
  }
  [data-testid="stAppViewContainer"]::before {
    content: ""; position: fixed; inset: 0; z-index: 0; pointer-events: none;
    background:
      radial-gradient(620px 620px at 18% 22%, rgba(111,92,240,0.10), transparent 62%),
      radial-gradient(680px 680px at 82% 78%, rgba(79,156,240,0.10), transparent 62%);
    animation: drift 22s ease-in-out infinite alternate;
  }
  @keyframes drift {
    0%   { transform: translate3d(0,0,0) scale(1); opacity: 0.85; }
    100% { transform: translate3d(0,-26px,0) scale(1.06); opacity: 1; }
  }
  /* faint grid overlay for a "telemetry" feel */
  [data-testid="stAppViewContainer"]::after {
    content: ""; position: fixed; inset: 0; z-index: 0; pointer-events: none;
    background-image:
      linear-gradient(rgba(255,255,255,0.022) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,0.022) 1px, transparent 1px);
    background-size: 46px 46px;
    mask-image: radial-gradient(1200px 800px at 50% 0%, #000 30%, transparent 80%);
  }
  [data-testid="stAppViewContainer"] > .main { padding-top: 1.2rem; position: relative; z-index: 1; }
  .block-container { padding-top: 2rem; max-width: 1300px; position: relative; z-index: 1; }

  /* entrance animation for top-level blocks */
  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(14px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  .block-container > div > div > [data-testid="stVerticalBlock"] > div { animation: fadeUp 0.5s cubic-bezier(.2,.7,.3,1) both; }

  /* custom scrollbar */
  ::-webkit-scrollbar { width: 10px; height: 10px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb {
    background: linear-gradient(180deg, rgba(79,156,240,0.4), rgba(111,92,240,0.4));
    border-radius: 999px; border: 2px solid transparent; background-clip: padding-box;
  }
  ::-webkit-scrollbar-thumb:hover { background: linear-gradient(180deg, #4f9cf0, #6f5cf0); background-clip: padding-box; }

  /* ── Top header band: slim + reveal on hover ───────────────────────────── */
  [data-testid="stHeader"] {
    height: 2.3rem !important;
    min-height: 2.3rem !important;
    background: transparent !important;
    box-shadow: none !important;
    opacity: 0.1;
    transition: opacity 0.28s ease, background 0.28s ease;
  }
  [data-testid="stHeader"]:hover {
    opacity: 1;
    background: rgba(8,10,16,0.72) !important;
    backdrop-filter: blur(10px);
    border-bottom: 1px solid rgba(255,255,255,0.06);
  }
  [data-testid="stToolbar"] { right: 0.4rem; top: 0.15rem; }
  /* recolour the thin top decoration line to the brand gradient */
  [data-testid="stDecoration"] {
    background-image: var(--grad) !important;
    height: 2px !important;
  }

  /* ── Sidebar ───────────────────────────────────────────────────────────── */
  [data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0d111a 0%, #090c12 100%);
    border-right: 1px solid rgba(255,255,255,0.06);
    box-shadow: 14px 0 40px -28px rgba(0,0,0,0.9);
  }
  [data-testid="stSidebar"] > div:first-child { padding: 1.4rem 0.9rem; }

  /* ── Typography ────────────────────────────────────────────────────────── */
  h1 { font-family: 'Space Grotesk','Inter',sans-serif; font-size: 1.65rem !important; font-weight: 700 !important; letter-spacing: -0.02em; }
  h2 { font-size: 1.12rem  !important; font-weight: 600 !important; letter-spacing: -0.01em; }
  h3 { font-size: 0.95rem !important; font-weight: 600 !important; }

  .section-label {
    font-size: 0.66rem; font-weight: 700;
    letter-spacing: 0.14em; text-transform: uppercase;
    color: var(--muted); margin: 1.05rem 0 0.45rem;
    display: flex; align-items: center; gap: 8px;
  }
  .section-label::after {
    content: ""; flex: 1; height: 1px;
    background: linear-gradient(90deg, rgba(255,255,255,0.10), transparent);
  }

  /* ── Brand block ───────────────────────────────────────────────────────── */
  .brand-block {
    display: flex; align-items: center; gap: 12px;
    padding-bottom: 1rem;
    border-bottom: 1px solid rgba(255,255,255,0.07);
    margin-bottom: 0.5rem;
  }
  .brand-icon {
    position: relative;
    width: 40px; height: 40px; border-radius: 12px;
    background: var(--grad-soft);
    border: 1px solid rgba(79,156,240,0.32);
    display: flex; align-items: center; justify-content: center;
    font-size: 19px; color: #8cc2ff;
    box-shadow: 0 0 0 1px rgba(79,156,240,0.06), 0 8px 22px -10px rgba(79,156,240,0.6);
  }
  .brand-icon::after {
    content: ""; position: absolute; inset: -1px; border-radius: 12px;
    background: var(--grad); opacity: 0.0; filter: blur(9px); z-index: -1;
    transition: opacity 0.3s ease;
  }
  .brand-block:hover .brand-icon::after { opacity: 0.45; }
  .brand-name {
    font-family: 'Space Grotesk','Inter',sans-serif;
    font-size: 0.98rem; font-weight: 700; letter-spacing: -0.01em;
    background: linear-gradient(90deg, #fff, #b9c6ff);
    -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
  }
  .brand-sub  { font-size: 0.68rem; color: var(--muted); letter-spacing: 0.03em; }

  /* ── Sidebar nav buttons ───────────────────────────────────────────────── */
  [data-testid="stSidebar"] .stButton > button {
    width: 100%;
    justify-content: flex-start;
    text-align: left;
    border-radius: 11px;
    border: 1px solid transparent;
    background: transparent;
    color: #c2cbd6;
    font-weight: 500;
    padding: 0.58rem 0.85rem;
    transition: all 0.18s cubic-bezier(.2,.7,.3,1);
  }
  [data-testid="stSidebar"] .stButton > button:hover {
    background: rgba(255,255,255,0.05);
    border-color: rgba(255,255,255,0.09);
    color: #fff; transform: translateX(3px);
  }
  /* Active nav (primary) */
  [data-testid="stSidebar"] .stButton > button[kind="primary"],
  [data-testid="stSidebar"] [data-testid="stBaseButton-primary"] {
    background: linear-gradient(135deg, rgba(79,156,240,0.26), rgba(111,92,240,0.20));
    border: 1px solid rgba(79,156,240,0.45);
    color: #fff;
    box-shadow: inset 0 0 0 1px rgba(79,156,240,0.08), 0 10px 26px -16px rgba(79,156,240,0.9);
  }
  [data-testid="stSidebar"] .stButton > button[kind="primary"]::before {
    content: ""; position: absolute; left: 6px; top: 50%; transform: translateY(-50%);
    width: 3px; height: 18px; border-radius: 3px; background: var(--grad);
    box-shadow: 0 0 10px var(--accent-glow);
  }
  [data-testid="stSidebar"] .stButton > button { position: relative; }

  /* ── Primary action buttons (main area) ────────────────────────────────── */
  .stButton > button[kind="primary"],
  [data-testid="stBaseButton-primary"] {
    position: relative; overflow: hidden;
    background: var(--grad);
    border: none; color: #fff; font-weight: 600;
    border-radius: 11px;
    box-shadow: 0 12px 30px -12px rgba(79,156,240,0.75);
    transition: transform 0.16s ease, box-shadow 0.16s ease, filter 0.16s ease;
  }
  .stButton > button[kind="primary"]:hover {
    filter: brightness(1.08);
    transform: translateY(-2px);
    box-shadow: 0 18px 40px -12px rgba(111,92,240,0.85);
  }
  .stButton > button[kind="primary"]:active { transform: translateY(0); }
  /* sheen sweep */
  .stButton > button[kind="primary"]::after {
    content: ""; position: absolute; top: 0; left: -120%; width: 60%; height: 100%;
    background: linear-gradient(100deg, transparent, rgba(255,255,255,0.28), transparent);
    transform: skewX(-20deg); transition: left 0.6s ease;
  }
  .stButton > button[kind="primary"]:hover::after { left: 140%; }

  /* secondary buttons */
  .stButton > button[kind="secondary"] {
    border-radius: 11px; border: 1px solid var(--card-border);
    background: var(--card-2); transition: all 0.16s ease;
  }
  .stButton > button[kind="secondary"]:hover {
    border-color: var(--card-border-hi); color: #fff;
    background: rgba(79,156,240,0.08); transform: translateY(-1px);
  }

  /* ── Metric cards ──────────────────────────────────────────────────────── */
  [data-testid="stMetric"] {
    position: relative; overflow: hidden;
    background: linear-gradient(160deg, rgba(255,255,255,0.05), rgba(255,255,255,0.015));
    border: 1px solid var(--card-border);
    border-radius: 16px;
    padding: 15px 17px;
    box-shadow: var(--shadow);
    transition: transform 0.18s ease, border-color 0.18s ease, box-shadow 0.18s ease;
  }
  [data-testid="stMetric"]::before {
    content: ""; position: absolute; top: 0; left: 0; right: 0; height: 3px;
    background: var(--grad); opacity: 0; transition: opacity 0.18s ease;
  }
  [data-testid="stMetric"]:hover {
    transform: translateY(-3px);
    border-color: var(--card-border-hi);
    box-shadow: var(--shadow-hi);
  }
  [data-testid="stMetric"]:hover::before { opacity: 1; }
  [data-testid="stMetricLabel"] {
    color: var(--muted); font-size: 0.7rem !important;
    text-transform: uppercase; letter-spacing: 0.07em; font-weight: 600;
  }
  [data-testid="stMetricValue"] {
    font-family: 'Space Grotesk','Inter',sans-serif;
    font-weight: 700; font-size: 1.6rem;
    background: linear-gradient(90deg, #ffffff, #c8d6ff);
    -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
  }

  /* ── Page header ───────────────────────────────────────────────────────── */
  .page-head { display: flex; align-items: center; gap: 14px; margin-bottom: 0.5rem; }
  .page-head-icon {
    position: relative;
    width: 46px; height: 46px; border-radius: 13px;
    background: var(--grad-soft);
    border: 1px solid rgba(79,156,240,0.3);
    display: flex; align-items: center; justify-content: center;
    color: #8cc2ff; font-size: 22px;
    box-shadow: 0 10px 26px -12px rgba(79,156,240,0.7);
  }
  .page-head-icon::after {
    content: ""; position: absolute; inset: -2px; border-radius: 13px;
    background: var(--grad); filter: blur(12px); opacity: 0.30; z-index: -1;
  }
  .page-head-title {
    font-family: 'Space Grotesk','Inter',sans-serif;
    font-size: 1.55rem; font-weight: 700; letter-spacing: -0.02em;
    background: linear-gradient(90deg, #ffffff 30%, #a9b8ff);
    -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
  }
  .page-head-sub   { font-size: 0.83rem; color: var(--muted); margin-top: 2px; max-width: 720px; }

  /* ── Panel card ────────────────────────────────────────────────────────── */
  .panel {
    background: var(--card);
    border: 1px solid var(--card-border);
    border-radius: 18px;
    padding: 1.1rem 1.25rem;
    margin-bottom: 1rem;
    box-shadow: var(--shadow);
    backdrop-filter: blur(6px);
  }

  /* ── Status pill ───────────────────────────────────────────────────────── */
  .status-pill {
    display: inline-flex; align-items: center; gap: 8px;
    font-size: 0.72rem; font-weight: 600;
    padding: 7px 12px; border-radius: 999px;
    border: 1px solid var(--card-border);
    backdrop-filter: blur(4px);
  }
  .pill-on  { background: rgba(46,160,67,0.13);  border-color: rgba(46,160,67,0.4);  color: #56d364; }
  .pill-off { background: rgba(201,209,217,0.06); color: var(--muted); }
  .dot { width: 8px; height: 8px; border-radius: 50%; }
  .dot-on  { background: #3fb950; box-shadow: 0 0 0 0 rgba(63,185,80,0.7); animation: pulse 2s infinite; }
  .dot-off { background: #8b949e; }
  @keyframes pulse {
    0%   { box-shadow: 0 0 0 0 rgba(63,185,80,0.6); }
    70%  { box-shadow: 0 0 0 7px rgba(63,185,80,0); }
    100% { box-shadow: 0 0 0 0 rgba(63,185,80,0); }
  }

  /* ── Empty state ───────────────────────────────────────────────────────── */
  .empty-card {
    position: relative; overflow: hidden;
    text-align: center; padding: 3.6rem 1.5rem;
    background: linear-gradient(160deg, rgba(255,255,255,0.04), rgba(255,255,255,0.012));
    border: 1px dashed var(--card-border);
    border-radius: 20px; margin-top: 1rem;
    box-shadow: var(--shadow);
  }
  .empty-card::before {
    content: ""; position: absolute; inset: 0;
    background: radial-gradient(420px 200px at 50% 0%, rgba(79,156,240,0.12), transparent 70%);
    pointer-events: none;
  }
  .empty-icon {
    position: relative; display: inline-flex; align-items: center; justify-content: center;
    width: 76px; height: 76px; border-radius: 20px; margin-bottom: 0.9rem;
    background: var(--grad-soft); border: 1px solid rgba(79,156,240,0.25);
    font-size: 34px; color: #8cc2ff;
  }
  .empty-title { font-size: 1.15rem; font-weight: 700; }
  .empty-sub { color: var(--muted); font-size: 0.86rem; margin-top: 0.3rem; }

  /* ── Misc ──────────────────────────────────────────────────────────────── */
  .chart-title {
    font-size: 0.78rem; font-weight: 700; color: #d6dee9; margin-bottom: 0.55rem;
    display: flex; align-items: center; gap: 7px; letter-spacing: 0.01em;
  }
  .chart-title::before {
    content: ""; width: 6px; height: 6px; border-radius: 2px;
    background: var(--grad); box-shadow: 0 0 8px var(--accent-glow);
  }
  .stProgress > div > div { background: var(--grad) !important; border-radius: 999px !important; box-shadow: 0 0 14px rgba(79,156,240,0.5); }
  .stProgress > div { border-radius: 999px !important; }
  hr { border-color: rgba(255,255,255,0.07) !important; margin: 1.15rem 0; }

  [data-testid="stDownloadButton"] > button {
    width: 100%; border-radius: 11px !important; font-weight: 600;
    background: linear-gradient(135deg, #36d6c3 0%, #2bb6a6 50%, #37c66f 100%) !important;
    border: none !important; color: #06231f !important;
    box-shadow: 0 12px 30px -14px rgba(54,214,195,0.7);
    transition: transform 0.16s ease, box-shadow 0.16s ease;
  }
  [data-testid="stDownloadButton"] > button:hover {
    transform: translateY(-2px); box-shadow: 0 18px 38px -14px rgba(55,198,111,0.85);
  }

  [data-testid="stExpander"] {
    border-radius: 14px !important; border: 1px solid var(--card-border) !important;
    background: var(--card) !important; box-shadow: var(--shadow);
    overflow: hidden;
  }
  [data-testid="stExpander"] summary:hover { color: #8cc2ff; }

  /* sliders */
  [data-testid="stSlider"] [data-baseweb="slider"] [role="slider"] {
    background: var(--grad) !important; border: 2px solid #0b0e14 !important;
    box-shadow: 0 0 0 3px rgba(79,156,240,0.25) !important;
  }
  [data-testid="stSlider"] [data-baseweb="slider"] > div > div > div { background: var(--grad) !important; }

  /* inputs / selects / textareas */
  [data-testid="stNumberInput"] input,
  [data-testid="stTextInput"] input,
  [data-baseweb="select"] > div {
    border-radius: 10px !important;
    background: var(--card-2) !important;
    border-color: var(--card-border) !important;
    transition: border-color 0.16s ease, box-shadow 0.16s ease;
  }
  [data-testid="stNumberInput"] input:focus,
  [data-testid="stTextInput"] input:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 3px rgba(79,156,240,0.18) !important;
  }

  /* dataframe container */
  [data-testid="stDataFrame"] {
    border-radius: 14px !important; overflow: hidden;
    border: 1px solid var(--card-border); box-shadow: var(--shadow);
  }

  /* success / alert tweaks */
  [data-testid="stAlert"] { border-radius: 12px !important; }

  /* code chips */
  code { font-family: 'JetBrains Mono', monospace !important; font-size: 0.82em !important; }
</style>
""", unsafe_allow_html=True)


# ── Theme constants ───────────────────────────────────────────────────────────
BG      = "#0b0e14"          # solid reference (pie wedge edges, etc.)
BG2     = "#141824"
CLR     = "#c9d1d9"
GRID    = "#222838"

# One colour per attack type (9 types + normal) — brightened for the dark glass UI
PALETTE = {
    "normal":                  "#4f9cf0",
    "replay_token":            "#e0a93b",
    "nonce_reuse":             "#ef5350",
    "timestamp_inconsistency": "#b07be8",
    "duplicate_sequence":      "#37c66f",
    "impersonation":           "#f6a623",
    "identity_token_mismatch": "#ff6b6b",
    "access_without_auth":     "#36d6c3",
    "abnormal_failure_rate":   "#ff8a4c",
    "abnormal_renewal":        "#5aa9ff",
}

plt.rcParams.update({
    "figure.facecolor": "none",  "axes.facecolor":  "none",   # transparent → blends with cards
    "savefig.facecolor": "none", "savefig.transparent": True,
    "axes.edgecolor":   "#2c3344", "axes.labelcolor": CLR,
    "axes.titlecolor":  "#e8edf4",
    "xtick.color": CLR, "ytick.color": CLR,
    "text.color":  CLR, "grid.color":  GRID,
    "grid.linewidth": 0.7, "grid.alpha": 0.35,
    "legend.facecolor": BG2, "legend.edgecolor": "#2c3344", "legend.framealpha": 0.55,
    "axes.spines.top": False, "axes.spines.right": False,
    "font.size": 8, "font.family": "DejaVu Sans",
})


# ── Helpers ───────────────────────────────────────────────────────────────────
def icon(name, size=16, style=""):
    return (f'<i class="ti ti-{name}" aria-hidden="true" '
            f'style="font-size:{size}px;vertical-align:-2px;{style}"></i>')

def section_label(text):
    st.markdown(f'<div class="section-label">{text}</div>', unsafe_allow_html=True)

def chart_title(text):
    st.markdown(f'<div class="chart-title">{text}</div>', unsafe_allow_html=True)

def page_header(icon_name, title, subtitle):
    st.markdown(
        f"""<div class="page-head">
              <div class="page-head-icon">{icon(icon_name, 21)}</div>
              <div>
                <div class="page-head-title">{title}</div>
                <div class="page-head-sub">{subtitle}</div>
              </div>
            </div>""",
        unsafe_allow_html=True,
    )

def empty_state(title, subtitle):
    st.markdown(
        f"""<div class="empty-card">
              <div class="empty-icon">{icon("database-off", 38)}</div>
              <div class="empty-title">{title}</div>
              <div class="empty-sub">{subtitle}</div>
            </div>""",
        unsafe_allow_html=True,
    )
    _, mid, _ = st.columns([2, 1, 2])
    with mid:
        if st.button("Go to Load page", use_container_width=True, type="primary"):
            st.session_state.page = "Load"
            st.rerun()


# ── Navigation state ──────────────────────────────────────────────────────────
NAV = [
    ("Load",      "adjustments-alt",   "Configure & generate"),
    ("Numbers",   "list-numbers",      "Metrics & tables"),
    ("Dashboard", "layout-dashboard",  "Charts & insights"),
]
if "page" not in st.session_state:
    st.session_state.page = "Load"

has_data = "df" in st.session_state


# ══════════════════════════════════════════════════════════════════════════════
# Sidebar — brand + navigation
# ══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown(
        f"""<div class="brand-block">
              <div class="brand-icon">{icon("cpu", 19)}</div>
              <div>
                <div class="brand-name">IoT Auth Simulator</div>
                <div class="brand-sub">dataset generator</div>
              </div>
            </div>""",
        unsafe_allow_html=True,
    )

    section_label("Navigation")
    for label, ic, _sub in NAV:
        active = st.session_state.page == label
        st.markdown(
            f"<div style='position:relative'>"
            f"<div style='position:absolute;left:-2px;top:9px;z-index:2;"
            f"color:{'#6fb0f5' if active else 'rgba(201,209,217,0.6)'};"
            f"pointer-events:none'>{icon(ic, 16, 'margin-left:8px')}</div></div>",
            unsafe_allow_html=True,
        )
        if st.button(f" {label}", key=f"nav_{label}",
                     use_container_width=True,
                     type="primary" if active else "secondary"):
            st.session_state.page = label
            st.rerun()

    st.markdown("<div style='height:1.2rem'></div>", unsafe_allow_html=True)
    section_label("Status")
    if has_data:
        n_sess = len(st.session_state["df"])
        n_evt  = len(st.session_state["event_df"])
        st.markdown(
            f"<div class='status-pill pill-on'><span class='dot dot-on'></span>"
            f"Dataset ready</div>"
            f"<div style='font-size:0.72rem;color:var(--muted);margin-top:0.5rem'>"
            f"{n_sess:,} sessions · {n_evt:,} events</div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            "<div class='status-pill pill-off'><span class='dot dot-off'></span>"
            "No dataset yet</div>",
            unsafe_allow_html=True,
        )


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: Load — configuration & generation
# ══════════════════════════════════════════════════════════════════════════════
def render_load():
    page_header(
        "adjustments-alt", "Generate Dataset",
        "Configure the simulation parameters, then run to produce a labelled "
        "IoT authentication event dataset.",
    )
    st.markdown("<br>", unsafe_allow_html=True)

    # ── Simulation parameters ────────────────────────────────────────────────
    section_label("Simulation parameters")
    # Device pool is fixed by config (cfg.simulation.num_devices) — not user-tunable.
    num_devices = cfg.simulation.num_devices
    p1, p2 = st.columns(2)
    with p1:
        num_normal = st.slider("Normal sessions", 50, 2000,
                               cfg.simulation.num_sessions_normal, 50)
    with p2:
        num_attack = st.slider("Attack sessions", 10, 500,
                               cfg.simulation.num_sessions_attack, 10)

    # ── Attack distribution ──────────────────────────────────────────────────
    section_label("Attack distribution")
    st.caption("Relative weights — auto-normalised to 100%.")

    attack_types = [
        "replay_token", "nonce_reuse", "timestamp_inconsistency",
        "duplicate_sequence", "impersonation", "identity_token_mismatch",
        "access_without_auth", "abnormal_failure_rate", "abnormal_renewal",
    ]
    default_weights = [12, 12, 12, 11, 12, 12, 12, 9, 8]

    dist_cols = st.columns(3)
    raw_weights = {}
    for i, (atype, dw) in enumerate(zip(attack_types, default_weights)):
        with dist_cols[i % 3]:
            raw_weights[atype] = st.slider(
                atype.replace("_", " ").title(),
                0, 50, dw, 1,
            )

    total_w = sum(raw_weights.values()) or 1
    attack_dist = {k: round(v / total_w, 4) for k, v in raw_weights.items()}
    # Ensure sum == 1.0 exactly (fix rounding on largest bucket)
    diff = 1.0 - sum(attack_dist.values())
    largest = max(attack_dist, key=attack_dist.get)
    attack_dist[largest] = round(attack_dist[largest] + diff, 4)

    # ── Options ──────────────────────────────────────────────────────────────
    section_label("Options")
    o1, o2, o3 = st.columns([1, 2, 1])
    with o1:
        seed = st.number_input("Random seed", value=42, step=1)
    with o2:
        out_name = st.text_input("Output filename", value="iot_auth_dataset.csv")
    with o3:
        st.markdown("<div style='height:1.8rem'></div>", unsafe_allow_html=True)
        save_parquet = st.checkbox("Export Parquet")

    # ── Live preview ─────────────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    section_label("Preview")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Device pool",     f"{num_devices:,}")
    c2.metric("Gateways",        f"{cfg.simulation.num_gateways:,}")
    c3.metric("Normal sessions", f"{num_normal:,}")
    c4.metric("Attack sessions", f"{num_attack:,}")
    c5.metric("Total sessions",  f"{num_normal + num_attack:,}")

    st.markdown("<br>", unsafe_allow_html=True)
    run_col, _ = st.columns([1, 2])
    with run_col:
        run_btn = st.button("Run simulation", type="primary",
                            use_container_width=True, icon=":material/play_arrow:")

    # ── Simulation run (logic unchanged) ─────────────────────────────────────
    if run_btn:
        # Push config overrides
        cfg.simulation.num_devices         = num_devices
        cfg.simulation.num_sessions_normal = num_normal
        cfg.simulation.num_sessions_attack = num_attack
        cfg.simulation.random_seed         = int(seed)
        cfg.simulation.output_filename     = out_name
        cfg.simulation.attack_distribution = attack_dist

        progress_bar = st.progress(0)
        status_text  = st.empty()

        from simulator.runner import run_simulation
        from simulator.data.exporter import save
        from simulator.data.output_views import to_feature_df, to_event_df

        def _progress(current, total, msg):
            progress_bar.progress(min(current / total, 1.0))
            status_text.text(msg)

        t0        = time.time()
        sequences = run_simulation(progress_callback=_progress)
        elapsed   = time.time() - t0

        progress_bar.progress(1.0)
        status_text.empty()

        csv_path = save(sequences, filename=out_name, parquet=save_parquet)
        st.success(f"Completed in {elapsed:.1f}s — saved to `{csv_path}`")

        st.session_state["df"]       = to_feature_df(sequences)
        st.session_state["event_df"] = to_event_df(sequences)
        st.session_state["csv_path"] = csv_path
        st.session_state["elapsed"]  = elapsed

        # Download both views of the freshly generated dataset right away
        feature_csv_name = csv_path.name                                       # <stem>_features.csv
        event_csv_name   = csv_path.name.replace("_features.csv", "_event_log.csv")
        dl1, dl2 = st.columns(2)
        with dl1:
            st.download_button(
                label=f"Feature CSV — {feature_csv_name}",
                data=st.session_state["df"].to_csv(index=False).encode("utf-8"),
                file_name=feature_csv_name,
                mime="text/csv",
                use_container_width=True,
                icon=":material/download:",
            )
        with dl2:
            st.download_button(
                label=f"Event log CSV — {event_csv_name}",
                data=st.session_state["event_df"].to_csv(index=False).encode("utf-8"),
                file_name=event_csv_name,
                mime="text/csv",
                use_container_width=True,
                icon=":material/download:",
            )

        # Quick jump to results
        j1, j2, _ = st.columns([1, 1, 2])
        with j1:
            if st.button("View Numbers", use_container_width=True):
                st.session_state.page = "Numbers"
                st.rerun()
        with j2:
            if st.button("Open Dashboard", use_container_width=True, type="primary"):
                st.session_state.page = "Dashboard"
                st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: Numbers — metrics, tables & export
# ══════════════════════════════════════════════════════════════════════════════
def render_numbers():
    page_header(
        "list-numbers", "Numbers",
        "Quantitative overview of the generated dataset — counts, per-attack "
        "signal averages, sample rows and export.",
    )

    if not has_data:
        empty_state("No dataset generated yet",
                    "Head to the Load page and run a simulation to see the numbers.")
        return

    df       = st.session_state["df"]
    event_df = st.session_state["event_df"]
    csv_path = Path(st.session_state["csv_path"])
    elapsed  = st.session_state["elapsed"]

    normal_n = int((df["is_anomaly"] == 0).sum())
    attack_n = int((df["is_anomaly"] == 1).sum())

    st.markdown("<br>", unsafe_allow_html=True)
    section_label("Overview")
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total events",   f"{len(event_df):,}")
    m2.metric("Sessions",       f"{len(df):,}")
    m3.metric("Normal sess.",   f"{normal_n:,}")
    m4.metric("Attack sess.",   f"{attack_n:,}")
    m5.metric("Runtime",        f"{elapsed:.1f}s")

    # ── Anomaly signal summary ───────────────────────────────────────────────
    st.markdown("---")
    st.markdown(
        f'<h2>{icon("radar", 15, "margin-right:6px;")} Anomaly signal summary</h2>',
        unsafe_allow_html=True,
    )
    st.caption("Mean of each Phase 4/5 anomaly signal, grouped by attack type.")

    sig_cols = [
        "replay_window_violation", "token_age_at_replay",
        "nonce_age_at_reuse", "timestamp_delta_s",
        "duplicate_session_count", "identity_claim_mismatch",
        "token_device_mismatch", "unauthorized_access_attempt",
        "failed_auth_count", "re_auth_required",
    ]
    sig_cols_present = [c for c in sig_cols if c in df.columns]
    if sig_cols_present:
        sig_df = (
            df[["attack_type"] + sig_cols_present]
            .groupby("attack_type")[sig_cols_present]
            .mean()
            .round(3)
        )
        st.dataframe(sig_df, use_container_width=True)

    # ── Sample rows (per-event log) ──────────────────────────────────────────
    st.markdown("---")
    st.markdown(
        f'<h2>{icon("list-details", 15, "margin-right:6px;")} Sample rows '
        f'<span style="opacity:0.5;font-size:0.8rem;">(one row per event)</span></h2>',
        unsafe_allow_html=True,
    )
    if "attack_type" in event_df.columns:
        col_f, _ = st.columns([2, 5])
        with col_f:
            filter_type = st.selectbox(
                "Filter by attack type",
                ["All"] + sorted(event_df["attack_type"].unique().tolist()),
                label_visibility="collapsed",
            )
        view_df = event_df if filter_type == "All" \
                  else event_df[event_df["attack_type"] == filter_type]
    else:
        view_df = event_df
    st.dataframe(view_df.head(100), use_container_width=True, height=320)

    # ── Attack phase breakdown ───────────────────────────────────────────────
    with st.expander("Attack phase breakdown"):
        phase_df = (
            df[df["is_anomaly"] == 1]
            .groupby(["attack_type", "attack_phase"])
            .size()
            .reset_index(name="count")
        )
        st.dataframe(phase_df, use_container_width=True)

    # ── Download ─────────────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown(
        f'<h2>{icon("download", 15, "margin-right:6px;")} Export</h2>',
        unsafe_allow_html=True,
    )
    st.caption("Two views of the same run — the per-session feature table (for ML) "
               "and the per-event authentication log.")
    feature_csv_name = csv_path.name                                       # <stem>_features.csv
    event_csv_name   = csv_path.name.replace("_features.csv", "_event_log.csv")
    e1, e2 = st.columns(2)
    with e1:
        st.download_button(
            label=f"Feature CSV — {feature_csv_name}",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name=feature_csv_name,
            mime="text/csv",
            use_container_width=True,
            icon=":material/download:",
        )
    with e2:
        st.download_button(
            label=f"Event log CSV — {event_csv_name}",
            data=event_df.to_csv(index=False).encode("utf-8"),
            file_name=event_csv_name,
            mime="text/csv",
            use_container_width=True,
            icon=":material/download:",
        )


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: Dashboard — charts & insights
# ══════════════════════════════════════════════════════════════════════════════
def render_dashboard():
    page_header(
        "layout-dashboard", "Dashboard",
        "Visual breakdown of attack composition and behavioural signal "
        "distributions across the generated sessions.",
    )

    if not has_data:
        empty_state("Nothing to visualise yet",
                    "Generate a dataset on the Load page to populate the dashboard.")
        return

    df       = st.session_state["df"]
    event_df = st.session_state["event_df"]

    normal_n = int((df["is_anomaly"] == 0).sum())
    attack_n = int((df["is_anomaly"] == 1).sum())

    st.markdown("<br>", unsafe_allow_html=True)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total events",  f"{len(event_df):,}")
    m2.metric("Sessions",      f"{len(df):,}")
    m3.metric("Normal sess.",  f"{normal_n:,}")
    m4.metric("Attack sess.",  f"{attack_n:,}")

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Charts ───────────────────────────────────────────────────────────────
    ch1, ch2, ch3 = st.columns(3)

    with ch1:
        chart_title("Attack type distribution")
        type_counts = df["attack_type"].value_counts()
        colors = [PALETTE.get(k, "#888") for k in type_counts.index]
        fig, ax = plt.subplots(figsize=(4, 3.2))
        wedges, texts, autotexts = ax.pie(
            type_counts.values,
            labels=None,
            autopct=lambda p: f"{p:.0f}%" if p >= 6 else "",
            pctdistance=0.79,
            colors=colors,
            textprops={"fontsize": 7, "color": "#ffffff", "fontweight": "bold"},
            wedgeprops={"linewidth": 2, "edgecolor": BG, "width": 0.42},
            startangle=90,
        )
        # donut centre — total session count
        ax.text(0, 0.08, f"{int(type_counts.sum()):,}", ha="center", va="center",
                fontsize=14, fontweight="bold", color="#ffffff")
        ax.text(0, -0.16, "sessions", ha="center", va="center",
                fontsize=6.5, color=CLR)
        ax.legend(
            wedges, type_counts.index,
            loc="lower center", bbox_to_anchor=(0.5, -0.28),
            ncol=2, fontsize=6, framealpha=0.3,
        )
        fig.tight_layout()
        st.pyplot(fig)
        plt.close()

    with ch2:
        chart_title("Message rate by attack type")
        fig, ax = plt.subplots(figsize=(4, 3.2))
        for label, color in PALETTE.items():
            subset = df[df["attack_type"] == label]["message_rate"].dropna()
            if not subset.empty:
                clipped = subset.clip(upper=subset.quantile(0.99))
                clipped.hist(ax=ax, bins=25, alpha=0.45, label=label, color=color,
                             histtype="stepfilled", edgecolor=color, linewidth=1.0)
        ax.set_xlabel("Message rate (msg/s)", fontsize=8)
        ax.set_ylabel("Count", fontsize=8)
        ax.legend(fontsize=6, ncol=2)
        ax.grid(axis="y", alpha=0.3)
        fig.tight_layout()
        st.pyplot(fig)
        plt.close()

    with ch3:
        chart_title("Trust score distribution")
        fig, ax = plt.subplots(figsize=(4, 3.2))
        for label, color in PALETTE.items():
            subset = df[df["attack_type"] == label]["trust_score"].dropna()
            if not subset.empty:
                subset.hist(ax=ax, bins=20, alpha=0.45, label=label, color=color,
                            histtype="stepfilled", edgecolor=color, linewidth=1.0)
        ax.set_xlabel("Trust score", fontsize=8)
        ax.set_ylabel("Count", fontsize=8)
        ax.legend(fontsize=6, ncol=2)
        ax.grid(axis="y", alpha=0.3)
        fig.tight_layout()
        st.pyplot(fig)
        plt.close()

    # ── Correlation heatmap ──────────────────────────────────────────────────
    st.markdown("---")
    with st.expander("Feature correlation heatmap", expanded=True):
        num_cols = [c for c in df.select_dtypes(include="number").columns
                    if df[c].std() > 0][:24]
        corr = df[num_cols].corr()
        fig, ax = plt.subplots(figsize=(11, 9))
        sns.heatmap(corr, ax=ax, cmap="mako", center=0,
                    annot=False, linewidths=0.4, linecolor=BG,
                    square=True, cbar_kws={"shrink": 0.7, "aspect": 30})
        ax.tick_params(labelsize=6.5)
        fig.tight_layout()
        st.pyplot(fig)
        plt.close()


# ══════════════════════════════════════════════════════════════════════════════
# Router
# ══════════════════════════════════════════════════════════════════════════════
PAGES = {
    "Load":      render_load,
    "Numbers":   render_numbers,
    "Dashboard": render_dashboard,
}
PAGES.get(st.session_state.page, render_load)()
