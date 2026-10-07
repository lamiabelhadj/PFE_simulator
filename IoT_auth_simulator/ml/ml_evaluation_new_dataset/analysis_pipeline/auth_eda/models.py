"""Stage 6 — baseline classifiers as a *probe* of the data, not as a product.

Design choices (all to avoid optimistic estimates):
  * Splits are StratifiedGroupKFold grouped by device, so no device appears in
    both train and test of a fold (64 devices, 3–8 sessions each).
  * 5 folds × 5 repetitions with different seeds → mean ± std.
  * Three feature sets: all observable features, the 6 mechanism features
    only, and everything EXCEPT the mechanism features ("context"). The last
    one answers: can a model detect anomalies without looking at the actual
    anomaly signal? If yes, the dataset has a shortcut.
  * Imputation/scaling is fitted inside each training fold (Pipeline).
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, balanced_accuracy_score, f1_score, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier, export_text

from . import plotting as P
from .config import ROLE_ORDER, ROLE_SHORT, SEED, Paths
from .features import MECHANISM_FEATURES

plt = P.plt
N_SPLITS, N_REPEATS = 5, 5


def _models(seed):
    return {
        "logistic_regression": make_pipeline(SimpleImputer(strategy="median"), StandardScaler(),
                                             LogisticRegression(C=1.0, max_iter=5000)),
        "random_forest": make_pipeline(SimpleImputer(strategy="median"),
                                       RandomForestClassifier(n_estimators=300, min_samples_leaf=2,
                                                              random_state=seed, n_jobs=1)),
        "decision_tree_d3": make_pipeline(SimpleImputer(strategy="median"),
                                          DecisionTreeClassifier(max_depth=3, random_state=seed)),
    }


def run(paths: Paths, feats: pd.DataFrame, num_cols: list[str]) -> dict:
    usable = [c for c in num_cols if feats[c].nunique() > 1]
    sets = {
        "all_observable": usable,
        "mechanism_only": [c for c in MECHANISM_FEATURES if c in usable],
        "context_only": [c for c in usable if c not in MECHANISM_FEATURES],
    }
    y = feats["y"].to_numpy()
    groups = feats["device"].to_numpy()
    metrics, oof_rows, imp_rows = [], [], []

    for rep in range(N_REPEATS):
        cv = StratifiedGroupKFold(n_splits=N_SPLITS, shuffle=True, random_state=SEED + rep)
        splits = list(cv.split(feats, y, groups))
        for set_name, cols in sets.items():
            X = feats[cols].to_numpy(dtype=float)
            for model_name in _models(SEED):
                oof = np.zeros(len(y))
                for fold, (tr, te) in enumerate(splits):
                    m = _models(SEED + rep * 100 + fold)[model_name]
                    m.fit(X[tr], y[tr])
                    oof[te] = m.predict_proba(X[te])[:, 1]
                    if rep == 0 and model_name == "random_forest" and set_name != "mechanism_only":
                        pi = permutation_importance(m, X[te], y[te], scoring="roc_auc", n_repeats=10,
                                                    random_state=SEED + fold)
                        imp_rows += [{"feature_set": set_name, "fold": fold, "feature": c, "importance": v}
                                     for c, v in zip(cols, pi.importances_mean)]
                pred = (oof >= 0.5).astype(int)
                metrics.append({"repeat": rep, "feature_set": set_name, "model": model_name,
                                "roc_auc": roc_auc_score(y, oof), "pr_auc": average_precision_score(y, oof),
                                "balanced_acc": balanced_accuracy_score(y, pred), "f1": f1_score(y, pred)})
                if rep == 0:
                    oof_rows.append(pd.DataFrame({"sample_key": feats["sample_key"], "role": feats["role"],
                                                  "feature_set": set_name, "model": model_name,
                                                  "p_anomaly": oof, "flagged": pred}))

    met = pd.DataFrame(metrics)
    met.to_csv(paths.tables / "cv_metrics_per_repeat.csv", index=False, lineterminator="\n")
    summ = (met.groupby(["feature_set", "model"])[["roc_auc", "pr_auc", "balanced_acc", "f1"]]
            .agg(["mean", "std"]).round(4))
    summ.columns = [f"{a}_{b}" for a, b in summ.columns]
    summ = summ.reset_index()
    summ.to_csv(paths.tables / "cv_metrics_summary.csv", index=False, lineterminator="\n")

    oof = pd.concat(oof_rows, ignore_index=True)
    oof.to_csv(paths.tables / "cv_out_of_fold_predictions.csv", index=False, lineterminator="\n")
    role_rate = (oof.groupby(["feature_set", "model", "role"])["flagged"].mean()
                 .unstack("role").reindex(columns=ROLE_ORDER))
    role_rate.round(4).reset_index().to_csv(paths.tables / "cv_flag_rate_by_role.csv", index=False, lineterminator="\n")

    imp = (pd.DataFrame(imp_rows).groupby(["feature_set", "feature"])["importance"]
           .agg(["mean", "std"]).reset_index().sort_values(["feature_set", "mean"], ascending=[True, False]))
    imp.to_csv(paths.tables / "rf_permutation_importance.csv", index=False, lineterminator="\n")

    # Interpretable reference: a depth-3 tree fitted on all data.
    tree = DecisionTreeClassifier(max_depth=3, random_state=SEED)
    Xa = feats[sets["all_observable"]].fillna(feats[sets["all_observable"]].median())
    tree.fit(Xa, y)
    rules_txt = export_text(tree, feature_names=sets["all_observable"], decimals=6)
    (paths.tables / "decision_tree_rules.txt").write_text(rules_txt, encoding="utf-8")
    tree_c = DecisionTreeClassifier(max_depth=3, random_state=SEED)
    Xc = feats[sets["context_only"]].fillna(feats[sets["context_only"]].median())
    tree_c.fit(Xc, y)
    rules_ctx = export_text(tree_c, feature_names=sets["context_only"], decimals=6)
    (paths.tables / "decision_tree_rules_context_only.txt").write_text(rules_ctx, encoding="utf-8")

    _plot_metrics(paths, summ)
    _plot_role_rates(paths, role_rate)
    return {"summary": summ, "role_rate": role_rate, "importance": imp, "tree_rules": rules_txt,
            "tree_rules_context": rules_ctx, "sets": {k: len(v) for k, v in sets.items()}}


def _plot_metrics(paths, summ):
    order_sets = ["all_observable", "mechanism_only", "context_only"]
    models = ["logistic_regression", "random_forest", "decision_tree_d3"]
    fig, ax = plt.subplots(figsize=(9, 3.4))
    y0 = np.arange(len(order_sets))[::-1]
    for k, m in enumerate(models):
        sub = summ.set_index(["feature_set", "model"])
        mu = [sub.loc[(s, m), "roc_auc_mean"] for s in order_sets]
        sd = [sub.loc[(s, m), "roc_auc_std"] for s in order_sets]
        yy = y0 + (k - 1) * 0.22
        ax.errorbar(mu, yy, xerr=sd, fmt="o", color=P.SERIES[k], ms=7, capsize=0, elinewidth=1.5,
                    mec=P.SURFACE, mew=1.5, label=m.replace("_", " "))
    ax.set_yticks(y0, ["all observable features", "mechanism features only", "context features only\n(mechanism removed)"])
    ax.axvline(0.5, color=P.MUTED, lw=1, ls=":")
    ax.set_xlim(0.4, 1.02)
    ax.set_xlabel("ROC-AUC (device-grouped 5-fold CV, mean ± sd over 5 repeats)")
    ax.grid(axis="y", visible=False)
    ax.legend(loc="upper left", fontsize=8.5, ncol=1)
    ax.set_title("Baseline detectors under device-grouped cross-validation")
    P.save(fig, paths.figures / "13_cv_auc.png")


def _plot_role_rates(paths, rr):
    rr = rr.copy()
    rr.index = [f"{s.replace('_', ' ')} · {m.replace('_', ' ')}" for s, m in rr.index]
    fig, ax = plt.subplots(figsize=(10, 5.2))
    im = ax.imshow(rr.to_numpy(dtype=float), cmap=P.SEQ_BLUE, vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(rr.shape[1]), [ROLE_SHORT[r] for r in rr.columns], rotation=25, ha="right")
    ax.set_yticks(range(rr.shape[0]), rr.index, fontsize=8)
    for i in range(rr.shape[0]):
        for j in range(rr.shape[1]):
            v = rr.iat[i, j]
            ax.text(j, i, f"{v:.0%}", ha="center", va="center", fontsize=7.5, color="white" if v > 0.55 else P.INK_2)
    ax.grid(False)
    ax.set_title("Share of sessions flagged as anomalous, per role (out-of-fold, repeat 0)")
    fig.colorbar(im, ax=ax, shrink=0.7, label="flag rate (recall for anomalies, FPR for others)")
    P.save(fig, paths.figures / "14_flag_rate_by_role.png")
