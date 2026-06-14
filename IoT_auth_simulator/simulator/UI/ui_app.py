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
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">

<style>
  :root {
    --accent: #4f9cf0;
    --accent-2: #6f5cf0;
    --card: rgba(255,255,255,0.025);
    --card-border: rgba(255,255,255,0.07);
    --muted: rgba(201,209,217,0.55);
  }

  html, body, [class*="css"], [data-testid="stAppViewContainer"] {
    font-family: 'Inter', -apple-system, sans-serif;
  }

  /* App background with soft glow */
  [data-testid="stAppViewContainer"] {
    background:
      radial-gradient(1100px 520px at 78% -12%, rgba(79,156,240,0.10), transparent 60%),
      radial-gradient(900px 500px at 8% 8%, rgba(111,92,240,0.07), transparent 55%),
      #0b0e14;
  }
  [data-testid="stAppViewContainer"] > .main { padding-top: 1.2rem; }
  .block-container { padding-top: 2rem; max-width: 1300px; }

  /* Sidebar */
  [data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0e121b 0%, #0a0d13 100%);
    border-right: 1px solid rgba(255,255,255,0.06);
  }
  [data-testid="stSidebar"] > div:first-child { padding: 1.4rem 0.9rem; }

  /* Typography */
  h1 { font-size: 1.6rem !important; font-weight: 700 !important; letter-spacing: -0.02em; }
  h2 { font-size: 1.1rem  !important; font-weight: 600 !important; letter-spacing: -0.01em; }
  h3 { font-size: 0.95rem !important; font-weight: 600 !important; }

  .section-label {
    font-size: 0.66rem; font-weight: 700;
    letter-spacing: 0.1em; text-transform: uppercase;
    color: var(--muted); margin: 1rem 0 0.4rem;
  }

  /* Brand block */
  .brand-block {
    display: flex; align-items: center; gap: 11px;
    padding-bottom: 1rem;
    border-bottom: 1px solid rgba(255,255,255,0.07);
    margin-bottom: 0.5rem;
  }
  .brand-icon {
    width: 38px; height: 38px; border-radius: 11px;
    background: linear-gradient(135deg, rgba(79,156,240,0.25), rgba(111,92,240,0.25));
    border: 1px solid rgba(79,156,240,0.3);
    display: flex; align-items: center; justify-content: center;
    font-size: 19px; color: #6fb0f5;
  }
  .brand-name { font-size: 0.95rem; font-weight: 700; letter-spacing: -0.01em; }
  .brand-sub  { font-size: 0.68rem; color: var(--muted); }

  /* Sidebar nav buttons */
  [data-testid="stSidebar"] .stButton > button {
    width: 100%;
    justify-content: flex-start;
    text-align: left;
    border-radius: 10px;
    border: 1px solid transparent;
    background: transparent;
    color: #c9d1d9;
    font-weight: 500;
    padding: 0.55rem 0.8rem;
    transition: all 0.15s ease;
  }
  [data-testid="stSidebar"] .stButton > button:hover {
    background: rgba(255,255,255,0.05);
    border-color: rgba(255,255,255,0.08);
    color: #fff;
  }
  /* Active nav (primary) */
  [data-testid="stSidebar"] .stButton > button[kind="primary"],
  [data-testid="stSidebar"] [data-testid="stBaseButton-primary"] {
    background: linear-gradient(135deg, rgba(79,156,240,0.22), rgba(111,92,240,0.18));
    border: 1px solid rgba(79,156,240,0.4);
    color: #fff;
    box-shadow: inset 0 0 0 1px rgba(79,156,240,0.06);
  }

  /* Primary action buttons (main area) */
  .stButton > button[kind="primary"],
  [data-testid="stBaseButton-primary"] {
    background: linear-gradient(135deg, #4f9cf0, #6f5cf0);
    border: none; color: #fff; font-weight: 600;
    border-radius: 10px;
  }
  .stButton > button[kind="primary"]:hover { filter: brightness(1.08); }

  /* Metric cards */
  [data-testid="stMetric"] {
    background: var(--card);
    border: 1px solid var(--card-border);
    border-radius: 14px;
    padding: 14px 16px;
    transition: border-color 0.15s ease;
  }
  [data-testid="stMetric"]:hover { border-color: rgba(79,156,240,0.35); }
  [data-testid="stMetricLabel"] {
    color: var(--muted); font-size: 0.7rem !important;
    text-transform: uppercase; letter-spacing: 0.05em;
  }
  [data-testid="stMetricValue"] { font-weight: 700; font-size: 1.5rem; }

  /* Page header */
  .page-head { display: flex; align-items: center; gap: 13px; margin-bottom: 0.4rem; }
  .page-head-icon {
    width: 42px; height: 42px; border-radius: 12px;
    background: linear-gradient(135deg, rgba(79,156,240,0.18), rgba(111,92,240,0.14));
    border: 1px solid rgba(79,156,240,0.28);
    display: flex; align-items: center; justify-content: center;
    color: #6fb0f5; font-size: 21px;
  }
  .page-head-title { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; }
  .page-head-sub   { font-size: 0.82rem; color: var(--muted); margin-top: 1px; }

  /* Panel card */
  .panel {
    background: var(--card);
    border: 1px solid var(--card-border);
    border-radius: 16px;
    padding: 1.1rem 1.25rem;
    margin-bottom: 1rem;
  }

  /* Status pill */
  .status-pill {
    display: inline-flex; align-items: center; gap: 7px;
    font-size: 0.72rem; font-weight: 500;
    padding: 6px 11px; border-radius: 999px;
    border: 1px solid var(--card-border);
  }
  .pill-on  { background: rgba(46,160,67,0.12);  border-color: rgba(46,160,67,0.35);  color: #3fb950; }
  .pill-off { background: rgba(201,209,217,0.06); color: var(--muted); }
  .dot { width: 7px; height: 7px; border-radius: 50%; }
  .dot-on  { background: #3fb950; box-shadow: 0 0 8px rgba(63,185,80,0.8); }
  .dot-off { background: #8b949e; }

  /* Empty state */
  .empty-card {
    text-align: center; padding: 3.5rem 1.5rem;
    background: var(--card); border: 1px dashed var(--card-border);
    border-radius: 18px; margin-top: 1rem;
  }
  .empty-icon { font-size: 40px; color: var(--muted); margin-bottom: 0.6rem; }
  .empty-title { font-size: 1.1rem; font-weight: 600; }
  .empty-sub { color: var(--muted); font-size: 0.85rem; margin-top: 0.25rem; }

  .chart-title { font-size: 0.78rem; font-weight: 600; color: var(--muted); margin-bottom: 0.5rem; }
  .stProgress > div > div { background: linear-gradient(90deg,#4f9cf0,#6f5cf0) !important; border-radius: 4px; }
  hr { border-color: rgba(255,255,255,0.07) !important; margin: 1.1rem 0; }
  [data-testid="stDownloadButton"] > button { width: 100%; border-radius: 10px !important; font-weight: 600; }
  [data-testid="stExpander"] { border-radius: 12px !important; border-color: var(--card-border) !important; }
</style>
""", unsafe_allow_html=True)


# ── Theme constants ───────────────────────────────────────────────────────────
BG      = "#0e1117"
BG2     = "#1a1d27"
CLR     = "#c9d1d9"

# One colour per attack type (9 types + normal)
PALETTE = {
    "normal":                  "#388bdc",
    "replay_token":            "#c17d14",
    "nonce_reuse":             "#e24b4a",
    "timestamp_inconsistency": "#9b59b6",
    "duplicate_sequence":      "#2ea043",
    "impersonation":           "#f39c12",
    "identity_token_mismatch": "#e74c3c",
    "access_without_auth":     "#1abc9c",
    "abnormal_failure_rate":   "#e67e22",
    "abnormal_renewal":        "#3498db",
}

plt.rcParams.update({
    "figure.facecolor": BG,  "axes.facecolor":  BG,
    "axes.edgecolor":   "#30363d", "axes.labelcolor": CLR,
    "xtick.color": CLR, "ytick.color": CLR,
    "text.color":  CLR, "grid.color":  "#21262d",
    "legend.facecolor": BG2, "legend.edgecolor": "#30363d",
    "font.size": 8,
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
    p1, p2, p3 = st.columns(3)
    with p1:
        num_devices = st.slider("Number of devices", 10, 500,
                                cfg.simulation.num_devices, 10)
        st.caption(f"{num_devices} unique device IDs")
    with p2:
        num_normal = st.slider("Normal sessions", 50, 2000,
                               cfg.simulation.num_sessions_normal, 50)
    with p3:
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
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Device pool",     f"{num_devices:,}")
    c2.metric("Normal sessions", f"{num_normal:,}")
    c3.metric("Attack sessions", f"{num_attack:,}")
    c4.metric("Total sessions",  f"{num_normal + num_attack:,}")

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

        # Download the freshly generated dataset right away
        event_csv_name = csv_path.name.replace("_features.csv", "_event_log.csv")
        st.download_button(
            label=f"Download dataset — {event_csv_name}",
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
    event_csv_name = csv_path.name.replace("_features.csv", "_event_log.csv")
    st.download_button(
        label=f"Download CSV — {event_csv_name}",
        data=event_df.to_csv(index=False).encode("utf-8"),
        file_name=event_csv_name,
        mime="text/csv",
        use_container_width=True,
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
            autopct="%1.0f%%",
            colors=colors,
            textprops={"fontsize": 7, "color": CLR},
            wedgeprops={"linewidth": 0.5, "edgecolor": BG},
            startangle=90,
        )
        ax.legend(
            wedges, type_counts.index,
            loc="lower center", bbox_to_anchor=(0.5, -0.28),
            ncol=2, fontsize=6, framealpha=0.3,
        )
        st.pyplot(fig)
        plt.close()

    with ch2:
        chart_title("Message rate by attack type")
        fig, ax = plt.subplots(figsize=(4, 3.2))
        for label, color in PALETTE.items():
            subset = df[df["attack_type"] == label]["message_rate"].dropna()
            if not subset.empty:
                clipped = subset.clip(upper=subset.quantile(0.99))
                clipped.hist(ax=ax, bins=25, alpha=0.55, label=label, color=color)
        ax.set_xlabel("Message rate (msg/s)", fontsize=8)
        ax.set_ylabel("Count", fontsize=8)
        ax.legend(fontsize=6, ncol=2)
        ax.grid(axis="y", alpha=0.3)
        st.pyplot(fig)
        plt.close()

    with ch3:
        chart_title("Trust score distribution")
        fig, ax = plt.subplots(figsize=(4, 3.2))
        for label, color in PALETTE.items():
            subset = df[df["attack_type"] == label]["trust_score"].dropna()
            if not subset.empty:
                subset.hist(ax=ax, bins=20, alpha=0.55, label=label, color=color)
        ax.set_xlabel("Trust score", fontsize=8)
        ax.set_ylabel("Count", fontsize=8)
        ax.legend(fontsize=6, ncol=2)
        ax.grid(axis="y", alpha=0.3)
        st.pyplot(fig)
        plt.close()

    # ── Correlation heatmap ──────────────────────────────────────────────────
    st.markdown("---")
    with st.expander("Feature correlation heatmap", expanded=True):
        num_cols = [c for c in df.select_dtypes(include="number").columns
                    if df[c].std() > 0][:24]
        corr = df[num_cols].corr()
        fig, ax = plt.subplots(figsize=(11, 9))
        sns.heatmap(corr, ax=ax, cmap="coolwarm", center=0,
                    annot=False, linewidths=0.3, cbar_kws={"shrink": 0.8})
        ax.tick_params(labelsize=6.5)
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
