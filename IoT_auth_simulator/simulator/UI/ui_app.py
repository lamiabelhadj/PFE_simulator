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

# Add the parent directories to the path so we can import from the project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import seaborn as sns

from config.settings import cfg, DATA_DIR

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IoT Auth Simulator",
    page_icon="🔐",
    layout="wide",
)

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .metric-card {
        background: #1e2130; border-radius: 10px;
        padding: 1rem 1.5rem; margin-bottom: 0.5rem;
    }
    .stProgress > div > div { background-color: #4e8df5; }
    h1 { color: #4e8df5; }
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# Sidebar — Configuration
# ══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.image("https://img.icons8.com/color/96/iot-sensor.png", width=60)
    st.title("Configuration")

    st.subheader("🖥️ Device Pool")
    num_devices = st.slider("Number of devices", 10, 500, cfg.simulation.num_devices, 10)

    st.subheader("📊 Sessions")
    num_normal = st.slider("Normal sessions", 50, 2000, cfg.simulation.num_sessions_normal, 50)
    num_attack = st.slider("Attack sessions", 10, 1000, cfg.simulation.num_sessions_attack, 10)

    st.subheader("⚔️ Attack Distribution")
    replay_pct       = st.slider("Replay (%)",        0, 100, 35)
    impersonation_pct = st.slider("Impersonation (%)", 0, 100 - replay_pct, 35)
    dos_pct           = 100 - replay_pct - impersonation_pct
    st.info(f"DoS / Flooding: **{dos_pct}%** (auto)")

    st.subheader("⚙️ Options")
    seed        = st.number_input("Random seed", value=42, step=1)
    save_parquet = st.checkbox("Also export Parquet", value=False)
    out_name    = st.text_input("Output filename", value="iot_auth_dataset.csv")

    run_btn = st.button("▶  Run Simulation", type="primary", use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# Main area
# ══════════════════════════════════════════════════════════════════════════════

st.title("🔐 IoT Authentication Simulator")
st.markdown(
    "Simulate normal and malicious IoT authentication flows "
    "(Replay · Impersonation · DoS) and generate a labelled dataset "
    "for anomaly-detection ML models."
)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Device pool",      num_devices)
col2.metric("Normal sessions",  num_normal)
col3.metric("Attack sessions",  num_attack)
col4.metric("Total sessions",   num_normal + num_attack)

st.divider()


# ══════════════════════════════════════════════════════════════════════════════
# Simulation run
# ══════════════════════════════════════════════════════════════════════════════

if run_btn:
    # Apply config overrides
    cfg.simulation.num_devices          = num_devices
    cfg.simulation.num_sessions_normal  = num_normal
    cfg.simulation.num_sessions_attack  = num_attack
    cfg.simulation.random_seed          = int(seed)
    cfg.simulation.output_filename      = out_name
    total_r = replay_pct / 100
    total_i = impersonation_pct / 100
    total_d = dos_pct / 100
    cfg.simulation.attack_distribution  = {
        "replay":        round(total_r, 2),
        "impersonation": round(total_i, 2),
        "dos_flooding":  round(total_d, 2),
    }

    st.subheader("⏳ Running simulation…")
    progress_bar = st.progress(0)
    status_text  = st.empty()
    total_steps  = num_normal + num_attack

    # Lazy import to avoid circular issues at module level
    from simulator.runner import run_simulation
    from data.exporter import save

    def ui_progress(current, total, msg):
        progress_bar.progress(min(current / total, 1.0))
        status_text.text(msg)

    t0     = time.time()
    events = run_simulation(progress_callback=ui_progress)
    elapsed = time.time() - t0

    progress_bar.progress(1.0)
    status_text.text(f"✅ Completed in {elapsed:.1f}s")

    csv_path = save(events, filename=out_name, parquet=save_parquet)

    st.success(f"Dataset saved → `{csv_path}`")

    # Store in session state for the dashboard below
    st.session_state["events"]   = events
    st.session_state["csv_path"] = csv_path
    st.session_state["elapsed"]  = elapsed


# ══════════════════════════════════════════════════════════════════════════════
# Dashboard (shown after a run)
# ══════════════════════════════════════════════════════════════════════════════

if "events" in st.session_state:
    events   = st.session_state["events"]
    csv_path = Path(st.session_state["csv_path"])
    df       = pd.DataFrame(events)

    st.subheader("📋 Dataset Overview")

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total rows",    f"{len(df):,}")
    m2.metric("Features",      len(df.columns))
    normal_n = int((df["is_anomaly"] == 0).sum())
    attack_n = int((df["is_anomaly"] == 1).sum())
    m3.metric("Normal",        f"{normal_n:,}")
    m4.metric("Attacks",       f"{attack_n:,}")
    m5.metric("Time",          f"{st.session_state['elapsed']:.1f}s")

    st.divider()

    # ── Charts ────────────────────────────────────────────────────────────────
    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown("**Attack type distribution**")
        type_counts = df["attack_type"].value_counts()
        fig, ax = plt.subplots(figsize=(4, 3))
        colors  = ["#4e8df5", "#f56c6c", "#f5a623", "#7ed321", "#9b59b6"]
        ax.pie(type_counts.values, labels=type_counts.index,
               autopct="%1.1f%%", colors=colors[:len(type_counts)],
               textprops={"fontsize": 9})
        ax.set_facecolor("#0e1117")
        fig.patch.set_facecolor("#0e1117")
        st.pyplot(fig)
        plt.close()

    with c2:
        st.markdown("**Message rate: normal vs attack**")
        fig, ax = plt.subplots(figsize=(4, 3))
        for label, color in [("normal", "#4e8df5"), ("dos_flooding", "#f56c6c"),
                              ("replay", "#f5a623"), ("impersonation", "#7ed321")]:
            subset = df[df["attack_type"] == label]["message_rate"].dropna()
            if not subset.empty:
                subset.clip(upper=subset.quantile(0.99)).hist(
                    ax=ax, bins=30, alpha=0.6, label=label, color=color
                )
        ax.set_xlabel("Message rate (msg/s)", color="white", fontsize=8)
        ax.set_ylabel("Count", color="white", fontsize=8)
        ax.tick_params(colors="white", labelsize=7)
        ax.legend(fontsize=7, facecolor="#1e2130", labelcolor="white")
        ax.set_facecolor("#0e1117")
        fig.patch.set_facecolor("#0e1117")
        st.pyplot(fig)
        plt.close()

    with c3:
        st.markdown("**Trust score distribution**")
        fig, ax = plt.subplots(figsize=(4, 3))
        for label, color in [("normal", "#4e8df5"), ("impersonation", "#f56c6c"),
                              ("replay", "#f5a623"), ("dos_flooding", "#7ed321")]:
            subset = df[df["attack_type"] == label]["trust_score"].dropna()
            if not subset.empty:
                subset.hist(ax=ax, bins=20, alpha=0.6, label=label, color=color)
        ax.set_xlabel("Trust score", color="white", fontsize=8)
        ax.set_ylabel("Count", color="white", fontsize=8)
        ax.tick_params(colors="white", labelsize=7)
        ax.legend(fontsize=7, facecolor="#1e2130", labelcolor="white")
        ax.set_facecolor("#0e1117")
        fig.patch.set_facecolor("#0e1117")
        st.pyplot(fig)
        plt.close()

    # ── Feature table ─────────────────────────────────────────────────────────
    st.divider()
    st.subheader("🔍 Sample rows")
    filter_type = st.selectbox(
        "Filter by attack type",
        ["all"] + sorted(df["attack_type"].unique().tolist())
    )
    view_df = df if filter_type == "all" else df[df["attack_type"] == filter_type]
    st.dataframe(
        view_df.head(50),
        use_container_width=True,
        height=300,
    )

    # ── Correlation heatmap ───────────────────────────────────────────────────
    with st.expander("📊 Feature correlation heatmap (numeric features)"):
        num_cols = df.select_dtypes(include="number").columns.tolist()
        # Keep only columns with variance
        num_cols = [c for c in num_cols if df[c].std() > 0][:20]
        corr = df[num_cols].corr()
        fig, ax = plt.subplots(figsize=(10, 8))
        sns.heatmap(corr, ax=ax, cmap="coolwarm", center=0,
                    annot=False, linewidths=0.3, cbar_kws={"shrink": 0.8})
        ax.tick_params(labelsize=7, colors="white")
        ax.set_facecolor("#0e1117")
        fig.patch.set_facecolor("#0e1117")
        st.pyplot(fig)
        plt.close()

    # ── Attack phase breakdown ────────────────────────────────────────────────
    with st.expander("🎯 Attack phase breakdown"):
        phase_df = df[df["is_anomaly"] == 1].groupby(
            ["attack_type", "attack_phase"]
        ).size().reset_index(name="count")
        st.dataframe(phase_df, use_container_width=True)

    # ── Download ──────────────────────────────────────────────────────────────
    st.divider()
    st.subheader("⬇️ Download")
    with open(csv_path, "rb") as f:
        st.download_button(
            label="📥 Download CSV dataset",
            data=f,
            file_name=csv_path.name,
            mime="text/csv",
            use_container_width=True,
        )