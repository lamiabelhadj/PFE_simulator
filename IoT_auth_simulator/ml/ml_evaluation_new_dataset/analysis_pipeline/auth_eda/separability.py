"""Stage 5 — how separable are the classes, and through which signals?

Three questions:
  1. Univariate: which observable features distinguish anomalies from normals,
     and does the answer change when the comparison is restricted to the
     *hard negatives* designed to look anomalous?
  2. Rules: do two transparent, protocol-level rules already recover the label?
  3. Leakage: which privileged metadata columns encode the label (and must
     therefore never reach a model)?
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.feature_selection import mutual_info_classif
from sklearn.metrics import roc_auc_score

from . import plotting as P
from .config import ROLE_ORDER, ROLE_SHORT, SEED, Paths

plt = P.plt

COMPARISONS = {
    # name: (positive roles, negative roles)
    "anomaly_vs_all_normal": (["anomaly:timestamp_inconsistency", "anomaly:nonce_reuse"], None),
    "anomaly_vs_hard_negatives": (["anomaly:timestamp_inconsistency", "anomaly:nonce_reuse"],
                                  [r for r in ROLE_ORDER if r.startswith("hard_negative")]),
    "timing_anom_vs_timing_hn": (["anomaly:timestamp_inconsistency"],
                                 ["hard_negative:small_positive_causal_margin"]),
    "nonce_anom_vs_nonce_hn": (["anomaly:nonce_reuse"],
                               ["hard_negative:fresh_nonce_cross_attempt",
                                "hard_negative:legitimate_same_attempt_nonce_recurrence"]),
}


def _auc(y, x):
    if np.unique(x[~np.isnan(x)]).size < 2:
        return 0.5
    m = ~np.isnan(x)
    return roc_auc_score(y[m], x[m])


def univariate(paths, feats, num_cols, info):
    rows = []
    for c in num_cols:
        row = {"feature": c, "group": info[c][0]}
        for name, (pos, neg) in COMPARISONS.items():
            sub = feats if neg is None else feats.loc[feats["role"].isin(pos + neg)]
            y = sub["role"].isin(pos).to_numpy().astype(int)
            x = sub[c].to_numpy(dtype=float)
            a = _auc(y, x)
            row[f"auc|{name}"] = round(a, 4)
            row[f"sep|{name}"] = round(max(a, 1 - a), 4)
        y = feats["y"].to_numpy()
        x = feats[c].to_numpy(dtype=float)
        row["direction"] = "higher in anomalies" if row["auc|anomaly_vs_all_normal"] > 0.5 else (
            "lower in anomalies" if row["auc|anomaly_vs_all_normal"] < 0.5 else "none")
        xa, xn = x[y == 1], x[y == 0]
        row["mannwhitney_p"] = (stats.mannwhitneyu(xa[~np.isnan(xa)], xn[~np.isnan(xn)]).pvalue
                                if np.unique(x[~np.isnan(x)]).size > 1 else 1.0)
        rows.append(row)
    tab = pd.DataFrame(rows)
    X = feats[num_cols].fillna(feats[num_cols].median()).to_numpy()
    tab["mutual_info"] = np.round(mutual_info_classif(X, feats["y"], random_state=SEED), 4)
    # Benjamini–Hochberg correction across features.
    p = tab["mannwhitney_p"].to_numpy()
    order = np.argsort(p)
    q = np.empty_like(p)
    q[order] = np.minimum.accumulate((p[order] * len(p) / np.arange(1, len(p) + 1))[::-1])[::-1]
    tab["bh_q"] = np.minimum(q, 1)
    tab = tab.sort_values("sep|anomaly_vs_all_normal", ascending=False)
    tab.to_csv(paths.tables / "univariate_separability.csv", index=False, lineterminator="\n")

    top = tab.head(22).iloc[::-1]
    fig, ax = plt.subplots(figsize=(9, 7))
    y = np.arange(len(top))
    a1, a2 = top["sep|anomaly_vs_all_normal"], top["sep|anomaly_vs_hard_negatives"]
    ax.hlines(y, np.minimum(a1, a2), np.maximum(a1, a2), color=P.AXIS, lw=1.5)
    ax.scatter(a1, y, s=80, color=P.SERIES[0], zorder=3, label="anomaly vs ALL normal sessions",
               edgecolor=P.SURFACE, linewidth=1.5)
    ax.scatter(a2, y, s=30, color=P.SERIES[1], zorder=3, label="anomaly vs HARD NEGATIVES only",
               edgecolor=P.SURFACE, linewidth=1.5)
    ax.set_yticks(y, top["feature"], fontsize=8)
    ax.axvline(0.5, color=P.MUTED, lw=1, ls=":")
    ax.set_xlim(0.45, 1.02)
    ax.set_xlabel("univariate separability  max(AUC, 1 − AUC)   (0.5 = no signal)")
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower right", fontsize=8.5)
    ax.set_title("Most separating single features — and what hard negatives do to them")
    P.save(fig, paths.figures / "12_univariate_separability.png")
    return tab


def rules(paths, feats):
    r_time = feats["n_negative_delays"] > 0
    r_nonce = feats["n_nonces_reused_across_attempts"] > 0
    flags = {"R1_negative_delay": r_time, "R2_cross_attempt_nonce_reuse": r_nonce, "R1_or_R2": r_time | r_nonce}
    by_role = pd.DataFrame({k: v.groupby(feats["role"]).mean() for k, v in flags.items()}).reindex(ROLE_ORDER)
    by_role.insert(0, "n", feats["role"].value_counts().reindex(ROLE_ORDER))
    by_role.to_csv(paths.tables / "rule_flag_rate_by_role.csv", lineterminator="\n")
    y = feats["y"].astype(bool)
    summ = []
    for k, v in flags.items():
        tp, fp = int((v & y).sum()), int((v & ~y).sum())
        fn, tn = int((~v & y).sum()), int((~v & ~y).sum())
        summ.append({"rule": k, "TP": tp, "FP": fp, "FN": fn, "TN": tn,
                     "precision": tp / max(tp + fp, 1), "recall": tp / max(tp + fn, 1),
                     "false_positive_rate": fp / max(fp + tn, 1)})
    summ = pd.DataFrame(summ)
    summ.to_csv(paths.tables / "rule_detector_confusion.csv", index=False, lineterminator="\n")
    return {"by_role": by_role, "summary": summ}


def _as_cat(s: pd.Series) -> pd.Series:
    """Missing values become their own category (pandas 3 keeps NaN through astype(str))."""
    return s.astype(object).where(s.notna(), "<missing>").astype(str)


def _cramers_v(a, b):
    ct = pd.crosstab(_as_cat(a), b)
    if min(ct.shape) < 2:
        return 0.0
    c2 = stats.chi2_contingency(ct, correction=False)[0]
    return float(np.sqrt(c2 / (ct.to_numpy().sum() * (min(ct.shape) - 1))))


def _gini(y, x):
    """|2·AUC − 1|: 0 = no ranking signal, 1 = perfect separation (same scale as Cramér V)."""
    if np.unique(x).size < 2 or np.unique(y).size < 2:
        return 0.0
    return abs(2 * roc_auc_score(y, x) - 1)


def metadata_leakage(paths, samples):
    """Score every privileged column by how much it tells about detector_truth.

    Association is on a common 0–1 scale: Cramér V for categorical columns,
    |2·AUC − 1| for numeric ones. Numeric columns that are only defined for
    some samples are also scored on their non-missing rows, because "present
    and negative" can encode the label even when the overall AUC looks weak.
    """
    y = (samples["detector_truth"] == "anomaly").astype(int).to_numpy()
    skip = {"detector_truth", "role", "role_kind", "sample_key", "sample_id"}
    rows = []
    for c in samples.columns:
        if c in skip:
            continue
        s = samples[c]
        nun = s.nunique(dropna=False)
        numeric = pd.api.types.is_numeric_dtype(s)
        assoc_nonnull, purity = np.nan, np.nan
        if nun <= 1:
            kind, score, metric = "constant", 0.0, "-"
        elif nun > len(s) / 4 and not numeric:
            kind, score, metric = "identifier/hash", 0.0, "-"
        elif nun > 20 and not numeric:
            # e.g. device key: ~5 rows per value, so V would be inflated by chance.
            kind, score, metric = "high-cardinality", _cramers_v(s, y), "Cramér V (inflated)"
        elif numeric and nun > 12:
            x = s.to_numpy(dtype=float)
            miss = np.isnan(x)
            filled = np.where(miss, np.nanmin(x) - 1, x)
            kind, score, metric = "numeric", _gini(y, filled), "|2AUC-1|"
            if miss.any() and (~miss).sum() >= 20:
                assoc_nonnull = _gini(y[~miss], x[~miss])
        else:
            kind, score, metric = "categorical", _cramers_v(s, y), "Cramér V"
            # Purity: accuracy of predicting the label from this column's value alone.
            purity = (pd.Series(y).groupby(_as_cat(s).to_numpy())
                      .agg(lambda v: max(v.sum(), len(v) - v.sum())).sum() / len(s))
        rows.append({"column": c, "kind": kind, "n_unique": nun, "metric": metric,
                     "label_association": round(score, 4),
                     "association_non_missing_rows": round(assoc_nonnull, 4) if assoc_nonnull == assoc_nonnull else np.nan,
                     "majority_purity": round(purity, 4) if purity == purity else np.nan})
    tab = pd.DataFrame(rows)
    best = tab[["label_association", "association_non_missing_rows"]].max(axis=1)
    tab["verdict"] = np.select(
        [tab["kind"].isin(["constant", "identifier/hash", "high-cardinality"]),
         (best >= 0.9) | (tab["majority_purity"] >= 0.99),
         best >= 0.3],
        ["no information / not interpretable", "LEAKS LABEL", "label-correlated (design variable)"],
        "not associated")
    order = {"LEAKS LABEL": 0, "label-correlated (design variable)": 1, "not associated": 2,
             "no information / not interpretable": 3}
    tab = (tab.assign(_o=tab["verdict"].map(order), _b=-best)
              .sort_values(["_o", "_b", "column"]).drop(columns=["_o", "_b"]))
    tab.to_csv(paths.tables / "metadata_leakage_audit.csv", index=False, lineterminator="\n")
    return tab


def run(paths, feats, samples, num_cols, info) -> dict:
    return {
        "univariate": univariate(paths, feats, num_cols, info),
        "rules": rules(paths, feats),
        "leakage": metadata_leakage(paths, samples),
    }
