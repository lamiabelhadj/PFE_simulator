"""Stage 4 — descriptive exploratory analysis.

Produces tables (CSV) and figures (PNG) that describe the dataset from the
outside in: composition → session structure → event vocabulary & grammar →
timing → nonces → tokens/access → device population. Every function returns
a dict of key numbers that the report quotes, so the narrative never drifts
from the data.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from scipy import stats

from . import plotting as P
from .config import EVENT_ORDER, KIND_ORDER, ROLE_ORDER, ROLE_SHORT, Paths

plt = P.plt


def _tbl(df: pd.DataFrame, paths: Paths, name: str, index=False) -> pd.DataFrame:
    df.to_csv(paths.tables / f"{name}.csv", index=index, lineterminator="\n")
    return df


def _role_labels(roles):
    return [ROLE_SHORT[r] for r in roles]


# --------------------------------------------------------------------------
def composition(paths, samples, events):
    g = samples.groupby("role")
    comp = pd.DataFrame({
        "role_kind": g["role_kind"].first(),
        "semantic_family": g["semantic_family"].first(),
        "detector_truth": g["detector_truth"].first(),
        "n_samples": g.size(),
        "n_devices": g["device"].nunique(),
        "events_mean": g["n_events"].mean().round(2),
        "events_min": g["n_events"].min(),
        "events_max": g["n_events"].max(),
    }).reindex(ROLE_ORDER)
    comp["share"] = (comp["n_samples"] / comp["n_samples"].sum()).round(4)
    _tbl(comp.reset_index(), paths, "composition_by_role")

    fig, ax = plt.subplots(figsize=(7.5, 3.2))
    y = np.arange(len(comp))[::-1]
    colors = [P.KIND_COLORS[k] for k in comp["role_kind"]]
    ax.barh(y, comp["n_samples"], color=colors, height=0.62, edgecolor=P.SURFACE, linewidth=1.5)
    for yi, n, sh in zip(y, comp["n_samples"], comp["share"]):
        ax.text(n + 1.5, yi, f"{n}  ({sh:.0%})", va="center", color=P.INK_2, fontsize=9)
    ax.set_yticks(y, _role_labels(comp.index))
    ax.set_xlabel("sessions")
    ax.set_xlim(0, comp["n_samples"].max() * 1.22)
    ax.grid(axis="y", visible=False)
    ax.set_title("Dataset composition by scientific role")
    handles = [plt.Rectangle((0, 0), 1, 1, color=P.KIND_COLORS[k]) for k in KIND_ORDER]
    ax.legend(handles, ["ordinary normal", "hard negative (label: normal)", "anomaly"],
              loc="lower right", fontsize=8.5)
    P.save(fig, paths.figures / "01_composition.png")

    truth = samples["detector_truth"].value_counts()
    return {
        "n_samples": len(samples), "n_events": len(events), "n_devices": samples["device"].nunique(),
        "n_normal": int(truth.get("normal", 0)), "n_anomaly": int(truth.get("anomaly", 0)),
        "n_hard_neg": int((samples["role_kind"] == "hard_negative").sum()),
        "n_ordinary": int((samples["role_kind"] == "ordinary_normal").sum()),
        "comp": comp,
    }


# --------------------------------------------------------------------------
def structure(paths, samples, feats):
    cols = {
        "structure.lifecycle": "lifecycle", "structure.recovery": "recovery",
        "structure.renewal": "renewal", "has_enrollment": "enrollment prelude",
    }
    df = samples.merge(feats[["sample_key", "has_enrollment"]], on="sample_key")
    df["has_enrollment"] = df["has_enrollment"].map({0: "no enrollment", 1: "enrollment"})
    tabs = []
    fig, axes = plt.subplots(1, 4, figsize=(13, 3.4), sharey=True)
    for ax, (col, title) in zip(axes, cols.items()):
        ct = pd.crosstab(df["role"], df[col]).reindex(ROLE_ORDER)
        tabs.append(ct.add_prefix(f"{title}=").reset_index(drop=True))
        share = ct.div(ct.sum(axis=1), axis=0)
        left = np.zeros(len(share))
        y = np.arange(len(share))[::-1]
        for i, c in enumerate(share.columns):
            ax.barh(y, share[c], left=left, color=P.SERIES[i], height=0.62,
                    edgecolor=P.SURFACE, linewidth=1.5, label=str(c))
            left += share[c].to_numpy()
        ax.set_title(title, fontsize=10)
        ax.set_xlim(0, 1)
        ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0%}"))
        ax.grid(axis="y", visible=False)
        ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=3, fontsize=7.5)
    axes[0].set_yticks(np.arange(len(ROLE_ORDER))[::-1], _role_labels(ROLE_ORDER))
    fig.suptitle("Session structure mix per role (share of sessions)", x=0.01, ha="left",
                 fontsize=11, fontweight="semibold", color=P.INK)
    P.save(fig, paths.figures / "02_structure_mix.png")
    out = pd.concat(tabs, axis=1)
    out.insert(0, "role", ROLE_ORDER)
    _tbl(out, paths, "structure_mix_by_role")

    # Chi-square: is structure independent of role? (it should be, by design matching)
    chi = []
    for col, title in cols.items():
        ct = pd.crosstab(df["role"], df[col])
        c2, p, dof, _ = stats.chi2_contingency(ct)
        v = np.sqrt(c2 / (ct.to_numpy().sum() * (min(ct.shape) - 1)))
        chi.append({"variable": title, "chi2": round(c2, 3), "dof": dof, "p_value": p, "cramers_v": round(v, 3)})
    chi = _tbl(pd.DataFrame(chi), paths, "structure_vs_role_chi2")
    return {"structure_chi2": chi, "structure_mix": out}


# --------------------------------------------------------------------------
def lengths(paths, feats):
    fig, axes = plt.subplots(1, 2, figsize=(12, 3.6), sharey=True)
    y_of = {r: i for i, r in enumerate(ROLE_ORDER[::-1])}
    rng = np.random.default_rng(0)
    for ax, col, title, log in [(axes[0], "n_events", "Events per session", False),
                                (axes[1], "duration_s", "Session duration (s, log scale)", True)]:
        for r in ROLE_ORDER:
            v = feats.loc[feats["role"] == r, col].to_numpy()
            kind = feats.loc[feats["role"] == r, "role_kind"].iloc[0]
            yy = y_of[r] + rng.uniform(-0.22, 0.22, len(v))
            ax.scatter(v, yy, s=14, color=P.KIND_COLORS[kind], alpha=0.65, linewidths=0)
            ax.plot([np.median(v)] * 2, [y_of[r] - 0.32, y_of[r] + 0.32], color=P.INK, lw=2)
        if log:
            ax.set_xscale("log")
        ax.set_title(title, fontsize=10)
        ax.grid(axis="y", visible=False)
    axes[0].set_yticks(list(y_of.values()), _role_labels(list(y_of.keys())))
    fig.text(0.99, 0.01, "dots = sessions · black bar = median", ha="right", color=P.MUTED, fontsize=8)
    P.save(fig, paths.figures / "03_session_length.png")
    desc = feats.groupby("role")[["n_events", "duration_s"]].describe().reindex(ROLE_ORDER).round(3)
    desc.columns = [f"{a}_{b}" for a, b in desc.columns]
    _tbl(desc.reset_index(), paths, "session_length_by_role")
    bimodal = feats["duration_s"]
    return {
        "events_min": int(feats["n_events"].min()), "events_max": int(feats["n_events"].max()),
        "events_median": float(feats["n_events"].median()),
        "dur_median": float(bimodal.median()), "dur_max": float(bimodal.max()),
        "share_long": float((bimodal > 60).mean()),
        "renewal_share": float(feats["has_renewal"].mean()),
    }


# --------------------------------------------------------------------------
def vocabulary(paths, events, feats):
    n_sess = events["sample_key"].nunique()
    vc = events["event_type"].value_counts().reindex(EVENT_ORDER)
    pres = events.groupby("event_type")["sample_key"].nunique().reindex(EVENT_ORDER)
    by_role = feats.groupby("role")[[f"count_{e}" for e in EVENT_ORDER]].mean().reindex(ROLE_ORDER).T
    by_role.index = EVENT_ORDER
    voc = pd.DataFrame({"total_events": vc, "sessions_with": pres,
                        "share_sessions_with": (pres / n_sess).round(4)})
    voc = pd.concat([voc, by_role.round(3).add_prefix("mean_per_session|")], axis=1)
    _tbl(voc.reset_index(names="event_type"), paths, "event_vocabulary")

    fig, ax = plt.subplots(figsize=(8.5, 7))
    im = ax.imshow(by_role.to_numpy(), cmap=P.SEQ_BLUE, aspect="auto")
    ax.set_xticks(range(len(ROLE_ORDER)), _role_labels(ROLE_ORDER), rotation=25, ha="right")
    ax.set_yticks(range(len(EVENT_ORDER)), EVENT_ORDER)
    vmax = by_role.to_numpy().max()
    for i in range(by_role.shape[0]):
        for j in range(by_role.shape[1]):
            v = by_role.iat[i, j]
            ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=7.5,
                    color="white" if v > vmax * 0.55 else P.INK_2)
    ax.grid(False)
    ax.set_title("Mean occurrences of each event type per session")
    fig.colorbar(im, ax=ax, shrink=0.6, label="events / session")
    P.save(fig, paths.figures / "04_event_vocabulary.png")

    # Transition (bigram) matrix across all sessions.
    ev = events.sort_values(["sample_key", "event_index"])
    nxt = ev.groupby("sample_key")["event_type"].shift(-1)
    tm = pd.crosstab(ev["event_type"], nxt).reindex(index=EVENT_ORDER, columns=EVENT_ORDER, fill_value=0)
    _tbl(tm.reset_index(names="from_event"), paths, "transition_matrix")
    prob = tm.div(tm.sum(axis=1).replace(0, np.nan), axis=0)
    fig, ax = plt.subplots(figsize=(9, 8))
    im = ax.imshow(prob.to_numpy(), cmap=P.SEQ_BLUE, vmin=0, vmax=1)
    ax.set_xticks(range(len(EVENT_ORDER)), EVENT_ORDER, rotation=60, ha="right", fontsize=8)
    ax.set_yticks(range(len(EVENT_ORDER)), EVENT_ORDER, fontsize=8)
    for i in range(prob.shape[0]):
        for j in range(prob.shape[1]):
            v = prob.iat[i, j]
            if v > 0:
                ax.text(j, i, f"{v:.2f}".lstrip("0"), ha="center", va="center", fontsize=6.5,
                        color="white" if v > 0.55 else P.INK_2)
    ax.grid(False)
    ax.set_xlabel("next event")
    ax.set_ylabel("current event")
    ax.set_title("Protocol grammar: P(next event | current event)")
    fig.colorbar(im, ax=ax, shrink=0.6, label="transition probability")
    P.save(fig, paths.figures / "05_transition_matrix.png")
    deterministic = int((prob.max(axis=1) == 1).sum())
    branching = prob.index[(prob.gt(0).sum(axis=1) > 1)].tolist()
    return {"n_event_types": int(events["event_type"].nunique()), "vocab": voc,
            "n_deterministic_transitions": deterministic, "branching_events": branching,
            "n_bigrams": int((tm > 0).to_numpy().sum())}


# --------------------------------------------------------------------------
def timing(paths, events, feats):
    ev = events.loc[events["event_index"] > 0]
    d = ev["observed_delay_since_previous_event"]
    q = ev.groupby("event_type")["observed_delay_since_previous_event"]
    tab = pd.DataFrame({
        "n": q.size(), "min": q.min(), "p05": q.quantile(0.05), "median": q.median(),
        "mean": q.mean(), "p95": q.quantile(0.95), "max": q.max(),
        "n_at_floor": q.apply(lambda s: int(((s >= 0) & (s <= 1.5e-6)).sum())),
        "n_negative": q.apply(lambda s: int((s < 0).sum())),
    }).reindex([e for e in EVENT_ORDER if e in q.groups]).round(6)
    _tbl(tab.reset_index(names="event_type"), paths, "delay_by_event_type")

    # Fig 6: delay distribution per event type (normal sessions, positive delays, log x).
    nm = ev.loc[(ev["label_detector_truth"] == "normal") & (d > 0)]
    order = [e for e in EVENT_ORDER if e in nm["event_type"].unique()]
    fig, ax = plt.subplots(figsize=(9, 6.5))
    data = [nm.loc[nm["event_type"] == e, "observed_delay_since_previous_event"].to_numpy() for e in order]
    bp = ax.boxplot(data, vert=False, widths=0.55, patch_artist=True, showfliers=True,
                    flierprops=dict(marker="o", markersize=2.5, markerfacecolor=P.MUTED, markeredgewidth=0, alpha=0.5),
                    medianprops=dict(color=P.INK, linewidth=1.6),
                    whiskerprops=dict(color=P.AXIS), capprops=dict(color=P.AXIS))
    for b in bp["boxes"]:
        b.set(facecolor="#cde2fb", edgecolor=P.SERIES[0], linewidth=1)
    ax.set_yticks(range(1, len(order) + 1), order)
    ax.invert_yaxis()
    ax.set_xscale("log")
    ax.set_xlabel("delay since previous event (s, log scale)")
    ax.grid(axis="y", visible=False)
    ax.set_title("Inter-event delay by event type (normal sessions)")
    P.save(fig, paths.figures / "06_delay_by_event_type.png")

    # Fig 7: the timing anomaly mechanism — smallest nonce_received→response gap.
    fig, ax = plt.subplots(figsize=(9, 3.6))
    rng = np.random.default_rng(1)
    y_of = {r: i for i, r in enumerate(ROLE_ORDER[::-1])}
    for r in ROLE_ORDER:
        sub = feats.loc[feats["role"] == r]
        yy = y_of[r] + rng.uniform(-0.22, 0.22, len(sub))
        ax.scatter(sub["response_delay_min"], yy, s=16, color=P.KIND_COLORS[sub["role_kind"].iloc[0]],
                   alpha=0.7, linewidths=0)
    ax.set_xscale("symlog", linthresh=1e-3)
    ax.axvline(0, color=P.INK, lw=1, ls="--")
    ax.text(0, len(ROLE_ORDER) - 0.35, " causal boundary (Δt = 0)", color=P.INK_2, fontsize=8, va="bottom")
    ax.set_yticks(list(y_of.values()), _role_labels(list(y_of.keys())))
    ax.set_ylim(-0.6, len(ROLE_ORDER) - 0.1)
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("min delay nonce_received → response_sent (s, symlog; linear within ±1 ms)")
    ax.set_title("Timing mechanism: the causal margin of the challenge response")
    P.save(fig, paths.figures / "07_causal_margin.png")

    ts = feats.loc[feats["role"] == "anomaly:timestamp_inconsistency", "response_delay_min"]
    hn = feats.loc[feats["role"] == "hard_negative:small_positive_causal_margin", "response_delay_min"]
    other = feats.loc[~feats["role"].isin(["anomaly:timestamp_inconsistency",
                                           "hard_negative:small_positive_causal_margin"]), "response_delay_min"]
    return {
        "n_gaps": int(len(d)), "n_floor": int(((d >= 0) & (d <= 1.5e-6)).sum()),
        "n_negative": int((d < 0).sum()),
        "delay_median": float(d.median()), "delay_p95": float(d.quantile(0.95)), "delay_max": float(d.max()),
        "ts_margin_min": float(ts.min()), "ts_margin_max": float(ts.max()),
        "hn_margin_min": float(hn.min()), "hn_margin_max": float(hn.max()),
        "other_margin_min": float(other.min()),
        "delay_table": tab,
        "floor_by_event": tab["n_at_floor"].loc[tab["n_at_floor"] > 0].to_dict(),
    }


# --------------------------------------------------------------------------
def nonces(paths, feats):
    g = feats.groupby("role")
    tab = pd.DataFrame({
        "n_sessions": g.size(),
        "attempts_mean": g["n_attempts"].mean().round(3),
        "share_multi_attempt": g["n_attempts"].apply(lambda s: (s > 1).mean()).round(3),
        "share_cross_attempt_reuse": g["n_nonces_reused_across_attempts"].apply(lambda s: (s > 0).mean()).round(3),
        "max_nonce_multiplicity_mean": g["max_nonce_multiplicity"].mean().round(3),
        "unique_nonces_mean": g["n_unique_nonces"].mean().round(3),
    }).reindex(ROLE_ORDER)
    _tbl(tab.reset_index(), paths, "nonce_usage_by_role")

    fig, axes = plt.subplots(1, 2, figsize=(12, 3.4), sharey=True)
    y = np.arange(len(ROLE_ORDER))[::-1]
    colors = [P.KIND_COLORS[k] for k in feats.groupby("role")["role_kind"].first().reindex(ROLE_ORDER)]
    for ax, col, title in [(axes[0], "share_multi_attempt", "Sessions with ≥ 2 handshakes"),
                           (axes[1], "share_cross_attempt_reuse", "Sessions where a nonce is reused across handshakes")]:
        ax.barh(y, tab[col], color=colors, height=0.6, edgecolor=P.SURFACE, linewidth=1.5)
        for yi, v in zip(y, tab[col]):
            ax.text(v + 0.02, yi, f"{v:.0%}", va="center", fontsize=8.5, color=P.INK_2)
        ax.set_xlim(0, 1.15)
        ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0%}"))
        ax.set_title(title, fontsize=10)
        ax.grid(axis="y", visible=False)
    axes[0].set_yticks(y, _role_labels(ROLE_ORDER))
    P.save(fig, paths.figures / "08_nonce_mechanism.png")
    return {"nonce_table": tab}


# --------------------------------------------------------------------------
def tokens(paths, events, feats):
    tok = events.dropna(subset=["token_id"])
    per_tok = tok.groupby("token_id").agg(n_events=("event_index", "size"), n_sessions=("sample_key", "nunique"))
    acc = events.loc[events["event_type"] == "access_request"]
    res = acc.groupby("resource_id").agg(n=("event_index", "size"), n_sessions=("sample_key", "nunique"),
                                         n_devices=("device", "nunique"))
    dev_res = acc.groupby("device")["resource_id"].nunique()
    topic_dev = events.dropna(subset=["topic"]).groupby("topic")["device"].nunique()
    out = {
        "n_tokens": int(per_tok.shape[0]), "tokens_multi_session": int((per_tok["n_sessions"] > 1).sum()),
        "token_events_median": float(per_tok["n_events"].median()),
        "n_resources": int(res.shape[0]), "resources_multi_device": int((res["n_devices"] > 1).sum()),
        "resources_per_device_max": int(dev_res.max()) if len(dev_res) else 0,
        "n_topics": int(topic_dev.shape[0]), "topics_multi_device": int((topic_dev > 1).sum()),
        "action_counts": acc["requested_action"].value_counts().to_dict(),
        "topic_event_types": events.dropna(subset=["topic"])["event_type"].value_counts().to_dict(),
    }
    _tbl(pd.DataFrame([{k: v for k, v in out.items() if not isinstance(v, dict)}]), paths, "token_resource_summary")
    return out


# --------------------------------------------------------------------------
def devices(paths, samples, feats):
    ct = pd.crosstab(samples["device"], samples["role"]).reindex(columns=ROLE_ORDER, fill_value=0)
    per_dev = ct.sum(axis=1)
    _tbl(ct.assign(total=per_dev).reset_index(), paths, "device_by_role")
    n_dev_anom = int((ct[[r for r in ROLE_ORDER if r.startswith("anomaly")]].sum(axis=1) > 0).sum())

    fig, ax = plt.subplots(figsize=(12, 3.2))
    im = ax.imshow(ct.T.to_numpy(), cmap=P.SEQ_BLUE, aspect="auto", vmin=0)
    ax.set_yticks(range(len(ROLE_ORDER)), _role_labels(ROLE_ORDER))
    ax.set_xticks(range(len(ct)), [d.split("-")[-1][-2:] for d in ct.index], fontsize=6.5)
    ax.set_xlabel("population device (last two digits of key)")
    ax.grid(False)
    ax.set_title("Sessions per device and role — devices contribute to many roles")
    fig.colorbar(im, ax=ax, shrink=0.8, label="sessions")
    P.save(fig, paths.figures / "09_device_by_role.png")

    # Latent behavioural profile vs observed behaviour (device level, normal sessions only).
    lat_cols = [c for c in samples.columns if c.startswith("device_profile.latent_tendencies.")]
    lat = samples.groupby("device")[lat_cols].first()
    lat.columns = [c.replace("device_profile.latent_tendencies.", "") for c in lat_cols]
    obs_cols = ["challenge_sent_delay_mean", "nonce_received_delay_mean", "response_sent_delay_mean",
                "authentication_success_delay_mean", "token_issued_delay_mean", "access_granted_delay_mean",
                "active_delay_mean", "n_attempts", "has_renewal", "has_enrollment", "n_events",
                "count_access_request", "n_writes"]
    obs = feats.loc[feats["y"] == 0].groupby("device")[obs_cols].mean()
    j = lat.join(obs, how="inner")
    rho = pd.DataFrame(index=lat.columns, columns=obs_cols, dtype=float)
    pval = rho.copy()
    for a in lat.columns:
        for b in obs_cols:
            r, p = stats.spearmanr(j[a], j[b], nan_policy="omit")
            rho.loc[a, b], pval.loc[a, b] = r, p
    _tbl(rho.round(3).reset_index(names="latent"), paths, "latent_vs_observed_spearman")
    _tbl(pval.reset_index(names="latent"), paths, "latent_vs_observed_pvalues")

    fig, ax = plt.subplots(figsize=(11, 6))
    im = ax.imshow(rho.to_numpy(dtype=float), cmap=P.DIVERGING, vmin=-1, vmax=1, aspect="auto")
    ax.set_xticks(range(len(obs_cols)), obs_cols, rotation=40, ha="right", fontsize=8)
    ax.set_yticks(range(len(rho)), rho.index, fontsize=8)
    for i in range(rho.shape[0]):
        for k in range(rho.shape[1]):
            v, p = rho.iat[i, k], pval.iat[i, k]
            if abs(v) >= 0.3:
                ax.text(k, i, f"{v:.2f}" + ("*" if p < 0.001 else ""), ha="center", va="center", fontsize=7,
                        color="white" if abs(v) > 0.6 else P.INK)
    ax.grid(False)
    ax.set_title("Device latent tendencies vs observed behaviour (Spearman ρ, 64 devices; * p<0.001)")
    fig.colorbar(im, ax=ax, shrink=0.7, label="ρ")
    P.save(fig, paths.figures / "10_latent_vs_observed.png")

    flat = rho.stack().sort_values(key=np.abs, ascending=False)
    top = [(a, b, float(v), float(pval.loc[a, b])) for (a, b), v in flat.head(8).items()]
    return {"per_device_min": int(per_dev.min()), "per_device_max": int(per_dev.max()),
            "per_device_median": float(per_dev.median()), "n_dev_with_anomaly": n_dev_anom,
            "roles_per_device_median": float((ct > 0).sum(axis=1).median()),
            "latent_top": top, "n_lifecycle_cells": int(samples["device_profile.lifecycle_cell"].nunique())}


# --------------------------------------------------------------------------
def correlations(paths, feats, num_cols):
    use = [c for c in num_cols if feats[c].nunique() > 1]
    corr = feats[use].corr(method="spearman")
    _tbl(corr.round(3).reset_index(names="feature"), paths, "feature_correlation_spearman")
    pairs = (corr.where(np.triu(np.ones(corr.shape, bool), 1)).stack()
             .sort_values(key=np.abs, ascending=False))
    redundant = pairs[pairs.abs() >= 0.95]
    _tbl(redundant.rename("rho").reset_index().rename(columns={"level_0": "a", "level_1": "b"}),
         paths, "redundant_feature_pairs")

    show = [c for c in use if not c.startswith("count_")] + ["count_access_request", "count_retry"]
    c2 = feats[show].corr(method="spearman")
    fig, ax = plt.subplots(figsize=(11, 10))
    im = ax.imshow(c2.to_numpy(), cmap=P.DIVERGING, vmin=-1, vmax=1)
    ax.set_xticks(range(len(show)), show, rotation=70, ha="right", fontsize=7)
    ax.set_yticks(range(len(show)), show, fontsize=7)
    ax.grid(False)
    ax.set_title("Spearman correlation between session features")
    fig.colorbar(im, ax=ax, shrink=0.6, label="ρ")
    P.save(fig, paths.figures / "11_feature_correlation.png")
    constant = [c for c in num_cols if feats[c].nunique() <= 1]
    return {"n_redundant_pairs": int(len(redundant)), "constant_features": constant}


def example_sessions(paths, events, samples):
    """One representative session per role, for the report's worked examples."""
    rows = []
    for r in ROLE_ORDER:
        key = samples.loc[samples["role"] == r].sort_values("n_events")["sample_key"].iloc[len(samples.loc[samples["role"] == r]) // 2]
        s = events.loc[events["sample_key"] == key].sort_values("event_index")
        for _, e in s.iterrows():
            rows.append({"role": r, "sample_key": key, "i": e["event_index"], "event_type": e["event_type"],
                         "delay_s": e["observed_delay_since_previous_event"], "attempt": e["attempt_index"],
                         "nonce8": (e["nonce"][7:15] if isinstance(e["nonce"], str) else ""),
                         "token6": (e["token_id"][7:13] if isinstance(e["token_id"], str) else ""),
                         "retry": e["retry_count"]})
    return _tbl(pd.DataFrame(rows), paths, "example_sessions")


def run(paths, events, samples, feats, num_cols) -> dict:
    facts = {}
    facts["composition"] = composition(paths, samples, events)
    facts["structure"] = structure(paths, samples, feats)
    facts["lengths"] = lengths(paths, feats)
    facts["vocabulary"] = vocabulary(paths, events, feats)
    facts["timing"] = timing(paths, events, feats)
    facts["nonces"] = nonces(paths, feats)
    facts["tokens"] = tokens(paths, events, feats)
    facts["devices"] = devices(paths, samples, feats)
    facts["correlations"] = correlations(paths, feats, num_cols)
    facts["examples"] = example_sessions(paths, events, samples)
    miss = events.isna().mean().round(4).rename("missing_share").rename_axis("column").reset_index()
    facts["missingness"] = _tbl(miss, paths, "events_missingness")
    return facts
