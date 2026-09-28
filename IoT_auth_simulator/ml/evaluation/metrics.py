"""
ml/evaluation/metrics.py
─────────────────────────
Pure metric functions — arrays in, numbers / tables out. No models, no plots.

Metric choices
──────────────
  binary     : precision / recall / F1 are for the ANOMALY class (label 1), not
               weighted. With ~2:1 or 10:1 class ratios a weighted F1 is carried
               by the easy normal majority and hides missed attacks.
               PR-AUC (average precision) and MCC are reported for the same reason.
  multiclass : macro averages (every attack type counts equally), plus the
               attack-level view — was the session flagged as *some* attack?
"""

from __future__ import annotations

from typing import Dict, Optional, Sequence

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)

from ml.evaluation.data import NORMAL_LABEL

NAN = float("nan")


def _safe(fn, *args, **kwargs) -> float:
    """Score that is undefined for this input (e.g. one class present) → NaN."""
    try:
        return float(fn(*args, **kwargs))
    except ValueError:
        return NAN


# ══════════════════════════════════════════════════════════════════════════════
# Headline metrics
# ══════════════════════════════════════════════════════════════════════════════

def binary_metrics(y_true, y_pred, y_score=None) -> Dict[str, float]:
    """Metrics for the is_anomaly target. `y_score` = P(anomaly), optional."""
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    return {
        "accuracy":          accuracy_score(y_true, y_pred),
        "balanced_accuracy": balanced_accuracy_score(y_true, y_pred),
        "precision":         precision_score(y_true, y_pred, zero_division=0),
        "recall":            recall_score(y_true, y_pred, zero_division=0),
        "f1":                f1_score(y_true, y_pred, zero_division=0),
        "f1_macro":          f1_score(y_true, y_pred, average="macro", zero_division=0),
        "mcc":               matthews_corrcoef(y_true, y_pred),
        "roc_auc":           _safe(roc_auc_score, y_true, y_score) if y_score is not None else NAN,
        "avg_precision":     _safe(average_precision_score, y_true, y_score) if y_score is not None else NAN,
        "false_alarm_rate":  fp / (fp + tn) if fp + tn else NAN,
        "missed":            int(fn),
        "false_alarms":      int(fp),
    }


def multiclass_metrics(
    y_true,
    y_pred,
    proba:        Optional[np.ndarray] = None,
    classes:      Optional[Sequence] = None,
    normal_label: str = NORMAL_LABEL,
) -> Dict[str, float]:
    """Metrics for the attack_type target. `proba` columns must follow `classes`."""
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)

    m = {
        "accuracy":          accuracy_score(y_true, y_pred),
        "balanced_accuracy": balanced_accuracy_score(y_true, y_pred),
        "precision_macro":   precision_score(y_true, y_pred, average="macro", zero_division=0),
        "recall_macro":      recall_score(y_true, y_pred, average="macro", zero_division=0),
        "f1_macro":          f1_score(y_true, y_pred, average="macro", zero_division=0),
        "f1_weighted":       f1_score(y_true, y_pred, average="weighted", zero_division=0),
        "mcc":               matthews_corrcoef(y_true, y_pred),
        "roc_auc_ovr_macro": (
            _safe(roc_auc_score, y_true, proba, multi_class="ovr", average="macro", labels=classes)
            if proba is not None else NAN
        ),
    }

    # Attack-level view: a wrong attack name still raises the alarm; a session
    # predicted "normal" is the silent failure that matters operationally.
    if normal_label in set(y_true):
        is_attack = y_true != normal_label
        flagged   = y_pred != normal_label
        m["detection_recall"] = float(flagged[is_attack].mean()) if is_attack.any() else NAN
        m["false_alarm_rate"] = float(flagged[~is_attack].mean()) if (~is_attack).any() else NAN
        m["missed"]           = int((is_attack & ~flagged).sum())
        m["mislabelled"]      = int((is_attack & flagged & (y_pred != y_true)).sum())
    return m


# ══════════════════════════════════════════════════════════════════════════════
# Breakdown tables
# ══════════════════════════════════════════════════════════════════════════════

def attack_type_table(
    attack_type,
    detected,
    named=None,
    normal_label: str = NORMAL_LABEL,
) -> pd.DataFrame:
    """
    Per-attack-type detection table (attack rows only), weakest first.

    attack_type : true attack_type of each row
    detected    : bool per row — the model raised an alarm
    named       : bool per row — the model also named the right attack
                  (multiclass only)
    """
    df = pd.DataFrame({"attack_type": np.asarray(attack_type),
                       "detected":    np.asarray(detected, dtype=bool)})
    if named is not None:
        df["named"] = np.asarray(named, dtype=bool)
    df = df[df["attack_type"] != normal_label]

    g   = df.groupby("attack_type")
    out = pd.DataFrame({"attacks": g.size(), "detected": g["detected"].sum()})
    out["detection_rate"] = out["detected"] / out["attacks"]
    sort_by = "detection_rate"
    if named is not None:
        out["named"]      = g["named"].sum()
        out["named_rate"] = out["named"] / out["attacks"]
        sort_by = "named_rate"
    return out.sort_values([sort_by, "attacks"])


def operating_points(
    y_true,
    y_score,
    min_precision: float = 0.90,
    tune_true=None,
    tune_score=None,
) -> pd.DataFrame:
    """
    Compare the default 0.5 threshold with two tuned ones, scored on (y_true, y_score).

      F1-optimal  : threshold maximising anomaly-class F1
      high-recall : lowest threshold whose precision stays >= min_precision

    Thresholds are CHOSEN on (tune_true, tune_score) when given — pass
    out-of-fold training scores for an honest estimate. Without them they are
    chosen on the evaluation data itself, which is optimistic; the `chosen_on`
    column says which happened.
    """
    y_true  = np.asarray(y_true).astype(int)
    y_score = np.asarray(y_score, dtype=float)
    honest  = tune_true is not None and tune_score is not None
    t_true  = np.asarray(tune_true).astype(int) if honest else y_true
    t_score = np.asarray(tune_score, dtype=float) if honest else y_score

    prec, rec, thr = precision_recall_curve(t_true, t_score)
    prec, rec = prec[:-1], rec[:-1]            # last point has no threshold
    f1 = np.divide(2 * prec * rec, prec + rec, out=np.zeros_like(prec), where=(prec + rec) > 0)
    f1_thr = float(thr[int(np.argmax(f1))])
    ok = np.flatnonzero(prec >= min_precision)
    hr_thr = float(thr[ok[int(np.argmax(rec[ok]))]]) if ok.size else NAN

    source = "train out-of-fold" if honest else "test (optimistic)"
    rows = []
    for label, t, chosen in [("default", 0.5, "fixed"),
                             ("F1-optimal", f1_thr, source),
                             (f"high-recall (precision>={min_precision:g})", hr_thr, source)]:
        if np.isnan(t):
            rows.append({"operating_point": label, "threshold": t, "chosen_on": "unreachable"})
            continue
        p = (y_score >= t).astype(int)
        rows.append({
            "operating_point": label,
            "threshold":       t,
            "chosen_on":       chosen,
            "precision":       precision_score(y_true, p, zero_division=0),
            "recall":          recall_score(y_true, p, zero_division=0),
            "f1":              f1_score(y_true, p, zero_division=0),
            "missed":          int(((y_true == 1) & (p == 0)).sum()),
            "false_alarms":    int(((y_true == 0) & (p == 1)).sum()),
        })
    return pd.DataFrame(rows).set_index("operating_point")
