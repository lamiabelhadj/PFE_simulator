"""
ml/evaluator.py
────────────────
Computes and formats evaluation metrics for trained classifiers.

Metrics computed
────────────────
  Accuracy, Precision, Recall, F1 (weighted), ROC-AUC,
  Confusion Matrix, per-class breakdown, top feature importances.

Usage
─────
    from ml.evaluator import evaluate, compare_models

    result = evaluate(model, X_test, y_test, feature_names)
    df     = compare_models([result1, result2, result3])
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


# ══════════════════════════════════════════════════════════════════════════════
# Result container
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class EvalResult:
    model_name:        str
    accuracy:          float
    precision:         float
    recall:            float
    f1:                float
    roc_auc:           float
    confusion_matrix:  List[List[int]]
    fit_time_s:        float
    predict_time_s:    float
    n_train:           int
    n_test:            int
    classes:           List[Any]
    class_report:      str          # sklearn classification_report string
    feature_importance: Optional[pd.Series] = field(default=None)

    def to_dict(self) -> Dict:
        return {
            "model":          self.model_name,
            "accuracy":       round(self.accuracy,  4),
            "precision":      round(self.precision, 4),
            "recall":         round(self.recall,    4),
            "f1":             round(self.f1,        4),
            "roc_auc":        round(self.roc_auc,   4),
            "fit_time_s":     round(self.fit_time_s,     3),
            "predict_time_s": round(self.predict_time_s, 3),
            "n_train":        self.n_train,
            "n_test":         self.n_test,
        }


# ══════════════════════════════════════════════════════════════════════════════
# Core evaluation function
# ══════════════════════════════════════════════════════════════════════════════

def evaluate(
    model,
    X_train:       np.ndarray,
    y_train:       np.ndarray,
    X_test:        np.ndarray,
    y_test:        np.ndarray,
    feature_names: Optional[List[str]] = None,
) -> EvalResult:
    """
    Fit model on train, evaluate on test, return EvalResult.

    Parameters
    ----------
    model         : any object with .fit() / .predict() / .predict_proba()
    X_train       : training features
    y_train       : training labels
    X_test        : test features
    y_test        : test labels
    feature_names : column names (used for feature importance)
    """
    # ── Fit ───────────────────────────────────────────────────────────────────
    t0 = time.perf_counter()
    model.fit(X_train, y_train)
    fit_time = time.perf_counter() - t0

    # ── Predict ───────────────────────────────────────────────────────────────
    t0 = time.perf_counter()
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)
    predict_time = time.perf_counter() - t0

    classes   = list(model.classes_())
    n_classes = len(classes)

    # ── Metrics ───────────────────────────────────────────────────────────────
    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    rec  = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1   = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    # ROC-AUC: binary → standard; multiclass → one-vs-rest weighted
    try:
        if n_classes == 2:
            roc = roc_auc_score(y_test, y_proba[:, 1])
        else:
            roc = roc_auc_score(
                y_test, y_proba,
                multi_class="ovr",
                average="weighted",
                labels=classes,
            )
    except ValueError:
        roc = float("nan")

    cm   = confusion_matrix(y_test, y_pred, labels=classes).tolist()
    rep  = classification_report(y_test, y_pred, labels=classes, zero_division=0)

    # ── Feature importance (optional) ─────────────────────────────────────────
    fi = None
    if feature_names and hasattr(model, "feature_importances"):
        try:
            fi = model.feature_importances(feature_names)
        except Exception:
            pass

    return EvalResult(
        model_name       = model.name,
        accuracy         = acc,
        precision        = prec,
        recall           = rec,
        f1               = f1,
        roc_auc          = roc,
        confusion_matrix = cm,
        fit_time_s       = fit_time,
        predict_time_s   = predict_time,
        n_train          = len(y_train),
        n_test           = len(y_test),
        classes          = classes,
        class_report     = rep,
        feature_importance = fi,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Comparison table
# ══════════════════════════════════════════════════════════════════════════════

def compare_models(results: List[EvalResult]) -> pd.DataFrame:
    """
    Return a tidy DataFrame with one row per model, sorted by F1 descending.

    Columns: model, accuracy, precision, recall, f1, roc_auc,
             fit_time_s, predict_time_s, n_train, n_test
    """
    rows = [r.to_dict() for r in results]
    df   = pd.DataFrame(rows).sort_values("f1", ascending=False).reset_index(drop=True)
    df.index += 1   # rank starts at 1
    return df


# ══════════════════════════════════════════════════════════════════════════════
# Console report
# ══════════════════════════════════════════════════════════════════════════════

def print_report(result: EvalResult) -> None:
    """Print a human-readable evaluation report for one model."""
    sep = "─" * 55
    print(f"\n{sep}")
    print(f"  {result.model_name}")
    print(sep)
    print(f"  Accuracy  : {result.accuracy:.4f}")
    print(f"  Precision : {result.precision:.4f}  (weighted)")
    print(f"  Recall    : {result.recall:.4f}  (weighted)")
    print(f"  F1        : {result.f1:.4f}  (weighted)")
    print(f"  ROC-AUC   : {result.roc_auc:.4f}")
    print(f"  Fit time  : {result.fit_time_s:.3f}s")
    print(f"  Pred time : {result.predict_time_s:.3f}s")
    print(f"  Train / Test : {result.n_train} / {result.n_test}")
    print(f"\n  Confusion matrix (classes: {result.classes}):")
    for row in result.confusion_matrix:
        print(f"    {row}")
    print(f"\n  Per-class breakdown:\n{result.class_report}")
    if result.feature_importance is not None:
        print(f"  Top 10 features:")
        for feat, imp in result.feature_importance.head(10).items():
            print(f"    {feat:<40} {imp:.4f}")
    print(sep)
