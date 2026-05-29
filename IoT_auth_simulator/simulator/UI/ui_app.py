"""
ui/app.py
──────────
Streamlit UI for the IoT Authentication Simulator.

Run with:
    streamlit run ui/app.py
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import seaborn as sns

from config.settings import cfg, DATA_DIR


# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IoT Auth Simulator",
    page_icon=None,
    layout="wide",
)


# ── Global styles + Tabler Icons ─────────────────────────────────────────────
st.markdown("""
<link rel="stylesheet"
  href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css">

<style>
  /* ── Layout ── */
  [data-testid="stAppViewContainer"] > .main { padding-top: 1.5rem; }
  [data-testid="stSidebar"] { padding-top: 1rem; }
  [data-testid="stSidebar"] > div:first-child { padding: 1.5rem 1rem; }

  /* ── Typography ── */
  h1, h2, h3 { font-weight: 500 !important; letter-spacing: -0.01em; }
  h1 { font-size: 1.6rem !important; }
  h2 { font-size: 1.2rem !important; }
  h3 { font-size: 1rem !important; }

  /* ── Sidebar brand ── */
  .brand-block {
    display: flex; align-items: center; gap: 10px;
    padding-bottom: 1rem;
    border-bottom: 0.5px solid rgba(128,128,128,0.2);
    margin-bottom: 0.5rem;
  }
  .brand-icon {
    width: 34px; height: 34px; border-radius: 8px;
    background: rgba(56, 139, 220, 0.15);
    display: flex; align-items: center; justify-content: center;
    font-size: 18px; color: #388bdc;
  }
  .brand-name { font-size: 0.9rem; font-weight: 500; line-height: 1.2; }
  .brand-sub  { font-size: 0.7rem; opacity: 0.5; }

  /* ── Section labels ── */
  .section-label {
    font-size: 0.68rem; font-weight: 600;
    letter-spacing: 0.08em; text-transform: uppercase;
    opacity: 0.45; margin-bottom: 0.5rem; margin-top: 0.25rem;
  }

  /* ── Metric cards ── */
  .metric-card {
    background: rgba(128,128,128,0.07);
    border-radius: 10px;
    padding: 0.85rem 1.1rem;
    height: 100%;
  }
  .metric-label {
    font-size: 0.7rem; opacity: 0.5;
    text-transform: uppercase; letter-spacing: 0.05em;
    margin-bottom: 4px;
  }
  .metric-value { font-size: 1.6rem; font-weight: 500; line-height: 1.1; }
  .metric-sub   { font-size: 0.7rem; opacity: 0.4; margin-top: 2px; }

  /* ── Badges ── */
  .badge {
    display: inline-block; font-size: 0.68rem; font-weight: 500;
    padding: 2px 8px; border-radius: 20px;
  }
  .badge-normal       { background: rgba(46,160,67,0.15); color: #2ea043; }
  .badge-replay       { background: rgba(186,117,23,0.15); color: #c17d14; }
  .badge-impersonation{ background: rgba(226,75,74,0.15);  color: #e24b4a; }
  .badge-dos          { background: rgba(56,139,220,0.15); color: #388bdc; }

  /* ── Chart card title ── */
  .chart-card-title {
    font-size: 0.75rem; font-weight: 500; opacity: 0.6;
    display: flex; align-items: center; gap: 6px;
    margin-bottom: 0.6rem;
  }

  /* ── Progress bar ── */
  .stProgress > div > div { background-color: #388bdc; border-radius: 4px; }

  /* ── Table ── */
  [data-testid="stDataFrame"] { border-radius: 8px; overflow: hidden; }

  /* ── Buttons ── */
  .stButton > button {
    border-radius: 8px !important;
    font-weight: 500 !important;
    letter-spacing: 0.01em !important;
  }

  /* ── DoS pill ── */
  .dos-pill {
    font-size: 0.75rem;
    background: rgba(186,117,23,0.12);
    color: #c17d14;
    border-radius: 6px;
    padding: 5px 10px;
    margin-top: 4px;
  }

  /* ── Divider ── */
  hr { border-color: rgba(128,128,128,0.15) !important; margin: 0.5rem 0 !important; }

  /* ── Download button ── */
  [data-testid="stDownloadButton"] > button {
    width: 100%;
    border-radius: 8px !important;
    font-weight: 500 !important;
  }
</style>
""", unsafe_allow_html=True)


# ── Matplotlib dark theme ─────────────────────────────────────────────────────
BG_CHART = "#0e1117"
BG_PANEL = "#1a1d27"
CLR_TEXT = "#c9d1d9"
PALETTE  = {
    "normal":        "#388bdc",
    "replay":        "#c17d14",
    "impersonation": "#e24b4a",
    "dos_flooding":  "#2ea043",
}

plt.rcParams.update({
    "figure.facecolor": BG_CHART,
    "axes.facecolor":   BG_CHART,
    "axes.edgecolor":   "#30363d",
    "axes.labelcolor":  CLR_TEXT,
    "xtick.color":      CLR_TEXT,
    "ytick.color":      CLR_TEXT,
    "text.color":       CLR_TEXT,
    "grid.color":       "#21262d",
    "legend.facecolor": BG_PANEL,
    "legend.edgecolor": "#30363d",
    "font.size":        8,
})


# ── Helpers ───────────────────────────────────────────────────────────────────
def metric_card(label, value, sub=""):
    st.metric(label=label, value=value, help=sub if sub else None)


def icon(name, size=16, style=""):
    return (
        f'<i class="ti ti-{name}" '
        f'aria-hidden="true" style="font-size:{size}px;vertical-align:-2px;{style}"></i>'
    )


def section_label(text):
    st.markdown(f'<div class="section-label">{text}</div>', unsafe_allow_html=True)


def chart_card_title(icon_name, text):
    st.markdown(
        f'<div class="chart-card-title">{icon(icon_name, 14)} {text}</div>',
        unsafe_allow_html=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Sidebar
# ══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown(
        f"""<div class="brand-block">
              <div class="brand-icon">{icon("cpu", 18)}</div>
              <div>
                <div class="brand-name">IoT Auth Simulator</div>
                <div class="brand-sub">dataset generator</div>
              </div>
            </div>""",
        unsafe_allow_html=True,
    )

    section_label("Device pool")
    num_devices = st.slider("Number of devices", 10, 500, cfg.simulation.num_devices, 10,
                            label_visibility="collapsed")
    st.caption(f"{num_devices} unique device IDs")

    section_label("Sessions")
    num_normal = st.slider("Normal sessions", 50, 2000, cfg.simulation.num_sessions_normal, 50)
    num_attack = st.slider("Attack sessions", 10, 1000, cfg.simulation.num_sessions_attack, 10)

    section_label("Attack distribution")
    replay_pct        = st.slider("Replay (%)",        0, 100, 35, 5)
    impersonation_pct = st.slider("Impersonation (%)", 0, 100 - replay_pct, 35, 5)
    dos_pct           = 100 - replay_pct - impersonation_pct
    st.markdown(
        f'<div class="dos-pill">'
        f'{icon("alert-triangle", 13, "margin-right:5px;")} '
        f'DoS / Flooding: <strong>{dos_pct}%</strong> (auto-computed)'
        f'</div>',
        unsafe_allow_html=True,
    )

    section_label("Options")
    seed         = st.number_input("Random seed", value=42, step=1)
    out_name     = st.text_input("Output filename", value="iot_auth_dataset.csv")
    save_parquet = st.checkbox("Export Parquet")

    st.markdown("<br>", unsafe_allow_html=True)
    run_btn = st.button(
        "Run simulation",
        type="primary",
        use_container_width=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Main area — header
# ══════════════════════════════════════════════════════════════════════════════
st.markdown(
    f"""<div style="display:flex;align-items:center;gap:10px;margin-bottom:0.25rem">
          <div style="width:36px;height:36px;border-radius:9px;
                      background:rgba(56,139,220,0.12);
                      display:flex;align-items:center;justify-content:center;
                      font-size:20px;color:#388bdc;">{icon("shield-lock", 20)}</div>
          <h1 style="margin:0">IoT Authentication Flows simulator</h1>
        </div>""",
    unsafe_allow_html=True,
)
st.markdown(
    "<p style='opacity:0.55;font-size:0.85rem;margin-bottom:1rem;'>"
    "Generate labelled IoT authentication flows — normal, replay, impersonation, "
    "and DoS/flooding — for anomaly-detection.</p>",
    unsafe_allow_html=True,
)

# ── Summary stats ─────────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
with c1: metric_card("Device pool",     f"{num_devices:,}", "unique IDs")
with c2: metric_card("Normal sessions", f"{num_normal:,}",  "labelled benign")
with c3: metric_card("Attack sessions", f"{num_attack:,}",  "labelled anomaly")
with c4: metric_card("Total rows",      f"{num_normal + num_attack:,}", "dataset size")

st.markdown("<br>", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# Simulation run
# ══════════════════════════════════════════════════════════════════════════════
if run_btn:
    cfg.simulation.num_devices         = num_devices
    cfg.simulation.num_sessions_normal = num_normal
    cfg.simulation.num_sessions_attack = num_attack
    cfg.simulation.random_seed         = int(seed)
    cfg.simulation.output_filename     = out_name
    cfg.simulation.attack_distribution = {
        "replay":        round(replay_pct / 100, 2),
        "impersonation": round(impersonation_pct / 100, 2),
        "dos_flooding":  round(dos_pct / 100, 2),
    }

    st.caption("Running simulation…")
    progress_bar = st.progress(0)
    status_text  = st.empty()

    from simulator.runner import run_simulation
    from data.exporter import save

    def ui_progress(current, total, msg):
        progress_bar.progress(min(current / total, 1.0))
        status_text.text(msg)

    t0      = time.time()
    events  = run_simulation(progress_callback=ui_progress)
    elapsed = time.time() - t0

    progress_bar.progress(1.0)
    status_text.empty()

    csv_path = save(events, filename=out_name, parquet=save_parquet)

    st.success(f"Completed in {elapsed:.1f}s — dataset saved to `{csv_path}`")

    st.session_state["events"]   = events
    st.session_state["csv_path"] = csv_path
    st.session_state["elapsed"]  = elapsed


# ══════════════════════════════════════════════════════════════════════════════
# Dashboard
# ══════════════════════════════════════════════════════════════════════════════
if "events" in st.session_state:
    events   = st.session_state["events"]
    csv_path = Path(st.session_state["csv_path"])
    elapsed  = st.session_state["elapsed"]
    df       = pd.DataFrame(events)

    st.markdown(
        f'<h2 style="margin:0 0 0.75rem;">'
        f'{icon("table", 16, "margin-right:6px;")} Dataset overview</h2>',
        unsafe_allow_html=True,
    )

    normal_n = int((df["is_anomaly"] == 0).sum())
    attack_n = int((df["is_anomaly"] == 1).sum())

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1: metric_card("Total rows", f"{len(df):,}")
    with m2: metric_card("Features",   f"{len(df.columns):,}")
    with m3: metric_card("Normal",     f"{normal_n:,}")
    with m4: metric_card("Attacks",    f"{attack_n:,}")
    with m5: metric_card("Runtime",    f"{elapsed:.1f}s")

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("---")

    # ── Charts ────────────────────────────────────────────────────────────────
    ch1, ch2, ch3 = st.columns(3)

    with ch1:
        chart_card_title("chart-pie", "Attack type distribution")
        type_counts = df["attack_type"].value_counts()
        colors = [PALETTE.get(k, "#888") for k in type_counts.index]
        fig, ax = plt.subplots(figsize=(4, 3))
        ax.pie(
            type_counts.values,
            labels=type_counts.index,
            autopct="%1.1f%%",
            colors=colors,
            textprops={"fontsize": 8, "color": CLR_TEXT},
            wedgeprops={"linewidth": 0.5, "edgecolor": BG_CHART},
            startangle=90,
        )
        st.pyplot(fig)
        plt.close()

    with ch2:
        chart_card_title("chart-bar", "Message rate: normal vs attack")
        fig, ax = plt.subplots(figsize=(4, 3))
        for label, color in PALETTE.items():
            subset = df[df["attack_type"] == label]["message_rate"].dropna()
            if not subset.empty:
                subset.clip(upper=subset.quantile(0.99)).hist(
                    ax=ax, bins=30, alpha=0.65, label=label, color=color
                )
        ax.set_xlabel("Message rate (msg/s)", fontsize=8)
        ax.set_ylabel("Count", fontsize=8)
        ax.tick_params(labelsize=7)
        ax.legend(fontsize=7)
        ax.grid(axis="y", alpha=0.3)
        st.pyplot(fig)
        plt.close()

    with ch3:
        chart_card_title("activity", "Trust score distribution")
        fig, ax = plt.subplots(figsize=(4, 3))
        for label, color in PALETTE.items():
            subset = df[df["attack_type"] == label]["trust_score"].dropna()
            if not subset.empty:
                subset.hist(ax=ax, bins=20, alpha=0.65, label=label, color=color)
        ax.set_xlabel("Trust score", fontsize=8)
        ax.set_ylabel("Count", fontsize=8)
        ax.tick_params(labelsize=7)
        ax.legend(fontsize=7)
        ax.grid(axis="y", alpha=0.3)
        st.pyplot(fig)
        plt.close()

    # ── Sample rows ───────────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown(
        f'<h2 style="margin:0 0 0.75rem;">'
        f'{icon("list-details", 16, "margin-right:6px;")} Sample rows</h2>',
        unsafe_allow_html=True,
    )

    col_filter, _ = st.columns([2, 5])
    with col_filter:
        filter_type = st.selectbox(
            "Filter by type",
            ["All"] + sorted(df["attack_type"].unique().tolist()),
            label_visibility="collapsed",
        )

    view_df = df if filter_type == "All" else df[df["attack_type"] == filter_type]
    st.dataframe(view_df.head(50), use_container_width=True, height=300)

    # ── Correlation heatmap ───────────────────────────────────────────────────
    with st.expander("Feature correlation heatmap (numeric features)"):
        num_cols = df.select_dtypes(include="number").columns.tolist()
        num_cols = [c for c in num_cols if df[c].std() > 0][:20]
        corr = df[num_cols].corr()
        fig, ax = plt.subplots(figsize=(10, 8))
        sns.heatmap(
            corr, ax=ax, cmap="coolwarm", center=0,
            annot=False, linewidths=0.3,
            cbar_kws={"shrink": 0.8},
        )
        ax.tick_params(labelsize=7)
        st.pyplot(fig)
        plt.close()

    # ── Attack phase breakdown ────────────────────────────────────────────────
    with st.expander("Attack phase breakdown"):
        phase_df = (
            df[df["is_anomaly"] == 1]
            .groupby(["attack_type", "attack_phase"])
            .size()
            .reset_index(name="count")
        )
        st.dataframe(phase_df, use_container_width=True)

    # ── Download ──────────────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown(
        f'<h2 style="margin:0 0 0.75rem;">'
        f'{icon("download", 16, "margin-right:6px;")} Export</h2>',
        unsafe_allow_html=True,
    )
    with open(csv_path, "rb") as f:
        st.download_button(
            label=f"Download CSV — {csv_path.name}",
            data=f,
            file_name=csv_path.name,
            mime="text/csv",
            use_container_width=True,
        )   