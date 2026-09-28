"""
ml/evaluation/plots.py
───────────────────────
Matplotlib figures for EvalReports. Every function accepts an optional `ax`
(or `axes`) so it composes into a notebook's own subplot grid, and returns the
Figure so callers can save it.

Colour
──────
Models / series take categorical slots IN ORDER (never cycled) from a palette
validated for colour-vision deficiency: slots 1-3 stay distinguishable in any
combination, which covers the usual three-model overlay. Magnitude (confusion
matrices) uses a single-hue blue ramp. Identity is never colour-only — every
multi-series chart has a legend and bar charts carry value labels.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence, Union

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)

from ml.evaluation.report import EvalReport

# Categorical slots, fixed order (blue, orange, aqua, yellow, magenta, green, violet, red).
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"]
INK, INK_2, MUTED = "#0b0b0b", "#52514e", "#898781"
GRID, AXIS = "#e1e0d9", "#c3c2b7"
SEQ_CMAP = "Blues"


def _series(n: int) -> List[str]:
    if n > len(SERIES):
        raise ValueError(f"{n} series exceed the {len(SERIES)} categorical slots; "
                         "split into small multiples instead of inventing colours")
    return SERIES[:n]


def _style(ax, grid: Optional[str] = "y") -> None:
    """Recessive chrome: no top/right spines, hairline grid behind the data."""
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(AXIS)
    ax.tick_params(colors=INK_2, labelsize=8)
    ax.xaxis.label.set_color(INK_2)
    ax.yaxis.label.set_color(INK_2)
    ax.title.set_color(INK)
    if grid:
        ax.grid(axis=grid, color=GRID, lw=0.8)
        ax.set_axisbelow(True)


def _axes(ax, figsize):
    if ax is None:
        fig, ax = plt.subplots(figsize=figsize)
    return ax.figure, ax


def _as_list(reports) -> List[EvalReport]:
    return [reports] if isinstance(reports, EvalReport) else list(reports)


# ══════════════════════════════════════════════════════════════════════════════
# Single-model views
# ══════════════════════════════════════════════════════════════════════════════

def plot_confusion(report: EvalReport, ax=None, normalize: Optional[str] = None):
    """
    Confusion matrix heatmap. Cell shade is always the row share (per-class
    recall), so the large normal class doesn't wash out the attack rows; the
    cell text shows counts, or the `normalize`d values when given.
    """
    cm = report.confusion_matrix(normalize)
    n  = len(cm)
    fig, ax = _axes(ax, (4.2, 3.6) if n <= 2 else (8.5, 7))

    vals  = cm.to_numpy(dtype=float)
    shade = report.confusion_matrix("true").to_numpy(dtype=float)
    ax.imshow(shade, cmap=SEQ_CMAP, vmin=0, vmax=1)
    fmt = "{:.2f}" if normalize else "{:.0f}"
    for i in range(n):
        for j in range(n):
            ax.text(j, i, fmt.format(vals[i, j]), ha="center", va="center", fontsize=8 if n > 2 else 10,
                    color="white" if shade[i, j] > 0.5 else INK)

    ax.set_xticks(range(n), cm.columns, rotation=45 if n > 2 else 0, ha="right" if n > 2 else "center")
    ax.set_yticks(range(n), cm.index)
    ax.set_xlabel("predicted"); ax.set_ylabel("true")
    ax.set_title(f"Confusion matrix — {report.name}", fontsize=10)
    _style(ax, grid=None)
    return fig


def plot_per_attack_type(report: EvalReport, ax=None):
    """Horizontal bars of detection rate per attack type (weakest at the top).
    Multiclass adds a second bar: the attack was also named correctly."""
    tab = report.per_attack_type().iloc[::-1]
    fig, ax = _axes(ax, (8, 0.45 * len(tab) + 1.2))
    y = np.arange(len(tab))

    cols = [("detection_rate", "detected as an attack")]
    if "named_rate" in tab:
        cols.append(("named_rate", "named correctly"))
    h = 0.8 / len(cols)
    for k, ((col, label), colour) in enumerate(zip(cols, _series(len(cols)))):
        pos = y + (k - (len(cols) - 1) / 2) * h
        ax.barh(pos, tab[col], height=h * 0.9, color=colour, label=label)
        for p, v in zip(pos, tab[col]):
            ax.text(v + 0.01, p, f"{v:.2f}", va="center", fontsize=7, color=INK_2)

    ax.set_yticks(y, tab.index)
    ax.set_xlim(0, 1.1); ax.set_xlabel("recall")
    ax.set_title(f"Per-attack-type recall — {report.name}", fontsize=10)
    if len(cols) > 1:
        # Reverse so the legend reads in the same top-to-bottom order as each bar pair.
        handles, labels = ax.get_legend_handles_labels()
        ax.legend(handles[::-1], labels[::-1], fontsize=8, frameon=False, ncol=len(cols),
                  loc="lower center", bbox_to_anchor=(0.5, 1.02))
        ax.set_title(f"Per-attack-type recall — {report.name}", fontsize=10, pad=24)
    _style(ax, grid="x")
    return fig


def plot_thresholds(report: EvalReport, ax=None, min_precision: float = 0.90):
    """Binary only: precision / recall / F1 vs decision threshold on the test
    set, with the operating points from report.operating_points() marked."""
    y, s = report.y_true.astype(int), report.score
    if s is None:
        raise ValueError("plot_thresholds() needs a binary model with predict_proba")
    prec, rec, thr = precision_recall_curve(y, s)
    prec, rec = prec[:-1], rec[:-1]
    f1 = np.divide(2 * prec * rec, prec + rec, out=np.zeros_like(prec), where=(prec + rec) > 0)

    fig, ax = _axes(ax, (8, 4.2))
    for vals, label, colour in zip((prec, rec, f1), ("precision", "recall", "F1"), _series(3)):
        ax.plot(thr, vals, lw=2, color=colour, label=label)
    for (name, row), ls in zip(report.operating_points(min_precision).iterrows(), (":", "--", "-.")):
        if not np.isnan(row["threshold"]):
            ax.axvline(row["threshold"], ls=ls, lw=1, color=MUTED, label=f"{name} ({row['threshold']:.2f})")

    ax.set_xlim(0, 1); ax.set_ylim(0, 1.02)
    ax.set_xlabel("decision threshold on P(anomaly)"); ax.set_ylabel("score")
    ax.set_title(f"Operating points — {report.name}", fontsize=10)
    ax.legend(fontsize=7, frameon=False, loc="lower left")
    _style(ax)
    return fig


def plot_importance(importance: pd.DataFrame, top: int = 15, ax=None, title: str = "Feature importance"):
    """Horizontal bars from feature_importance() output (error bars if std present)."""
    imp = importance.head(top).iloc[::-1]
    fig, ax = _axes(ax, (8, 0.35 * len(imp) + 1.2))
    xerr = imp["std"].to_numpy() if "std" in imp and imp["std"].notna().any() else None
    ax.barh(imp.index, imp["importance"], xerr=xerr, color=SERIES[0],
            error_kw={"lw": 0.8, "ecolor": MUTED})
    ax.set_xlabel("importance")
    ax.set_title(title, fontsize=10)
    _style(ax, grid="x")
    return fig


# ══════════════════════════════════════════════════════════════════════════════
# Binary curves (one or many models)
# ══════════════════════════════════════════════════════════════════════════════

def plot_roc_pr(reports: Union[EvalReport, Iterable[EvalReport]], axes: Optional[Sequence] = None):
    """ROC and precision-recall curves, one line per model, same test set."""
    reports = [r for r in _as_list(reports) if r.score is not None]
    if not reports:
        raise ValueError("plot_roc_pr() needs binary reports with predict_proba")
    if axes is None:
        fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))
    fig = axes[0].figure

    for r, colour in zip(reports, _series(len(reports))):
        y, s = r.y_true.astype(int), r.score
        fpr, tpr, _ = roc_curve(y, s)
        axes[0].plot(fpr, tpr, lw=2, color=colour, label=f"{r.name}  AUC {roc_auc_score(y, s):.3f}")
        p, rc, _ = precision_recall_curve(y, s)
        axes[1].step(rc, p, where="post", lw=2, color=colour,
                     label=f"{r.name}  AP {average_precision_score(y, s):.3f}")

    axes[0].plot([0, 1], [0, 1], "--", lw=1, color=MUTED, label="chance")
    axes[0].set_xlabel("false positive rate"); axes[0].set_ylabel("true positive rate")
    axes[0].set_title("ROC curve", fontsize=10)
    prevalence = reports[0].y_true.astype(int).mean()
    axes[1].axhline(prevalence, ls="--", lw=1, color=MUTED, label=f"prevalence {prevalence:.2f}")
    axes[1].set_xlabel("recall"); axes[1].set_ylabel("precision")
    axes[1].set_title("Precision-recall curve", fontsize=10)
    for ax, loc in zip(axes, ("lower right", "lower left")):
        ax.set_xlim(-0.01, 1.01); ax.set_ylim(0, 1.02)
        ax.legend(fontsize=7, frameon=False, loc=loc)
        _style(ax, grid="both")
    return fig


def plot_binary_panel(report: EvalReport):
    """The notebooks' standard binary panel: confusion matrix | ROC | PR."""
    fig, axes = plt.subplots(1, 3, figsize=(16, 4.4))
    plot_confusion(report, ax=axes[0])
    plot_roc_pr(report, axes=axes[1:])
    fig.tight_layout()
    return fig


def plot_comparison(reports: Iterable[EvalReport], metrics: Optional[Sequence[str]] = None, ax=None):
    """Grouped bars: one group per metric, one bar per model (legend + value labels)."""
    reports = _as_list(reports)
    task = reports[0].task
    metrics = list(metrics or (["precision", "recall", "f1", "roc_auc", "avg_precision"] if task == "binary"
                               else ["balanced_accuracy", "f1_macro", "roc_auc_ovr_macro", "detection_recall"]))
    fig, ax = _axes(ax, (max(7, 1.9 * len(metrics)), 4.2))
    x = np.arange(len(metrics))
    w = 0.8 / len(reports)
    for k, (r, colour) in enumerate(zip(reports, _series(len(reports)))):
        vals = [r.metrics.get(m, np.nan) for m in metrics]
        pos  = x + (k - (len(reports) - 1) / 2) * w
        ax.bar(pos, vals, width=w * 0.9, color=colour, label=r.name)
        for p, v in zip(pos, vals):
            if not np.isnan(v):
                ax.text(p, v + 0.01, f"{v:.2f}", ha="center", fontsize=6.5, color=INK_2)
    ax.set_xticks(x, metrics)
    ax.set_ylim(0, 1.08); ax.set_ylabel("score")
    ax.set_title("Model comparison — same split, same features", fontsize=10)
    ax.legend(fontsize=8, frameon=False, ncol=len(reports), loc="upper center", bbox_to_anchor=(0.5, -0.1))
    _style(ax)
    return fig
