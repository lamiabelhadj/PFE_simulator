"""
ml/evaluation/report.py
────────────────────────
Fit → predict → score one model, and the comparisons built on top of that.

  evaluate()           one fitted model on one Split  → EvalReport
  compare()            several EvalReports            → ranked DataFrame
  benchmark()          several model factories        → (Split, {name: EvalReport})
  cross_validate()     k-fold mean ± std for one model (stability of the score)
  leakage_check()      same model, all vs structure-free features
  feature_importance() model-based or permutation importance

Works with any sklearn-compatible classifier (Pipeline, GridSearchCV, …) that
exposes predict / predict_proba / classes_.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.inspection import permutation_importance
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.model_selection import cross_validate as _sk_cross_validate
from sklearn.pipeline import Pipeline

from ml.evaluation.data import NORMAL_LABEL, Dataset, Split, structural_leak_columns
from ml.evaluation.estimators import ModelFactory
from ml.evaluation.metrics import (
    attack_type_table,
    binary_metrics,
    multiclass_metrics,
    operating_points,
)

# The metric each task is ranked by, and the one the train/test gap is measured on.
HEADLINE = {"binary": "f1", "multiclass": "f1_macro"}

_CV_SCORING = {
    "binary":     ["accuracy", "precision", "recall", "f1", "roc_auc", "average_precision"],
    "multiclass": ["accuracy", "balanced_accuracy", "f1_macro", "f1_weighted", "roc_auc_ovr"],
}


def _cv(cv: Union[int, Any], seed: int):
    return StratifiedKFold(cv, shuffle=True, random_state=seed) if isinstance(cv, int) else cv


# ══════════════════════════════════════════════════════════════════════════════
# Result container
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class EvalReport:
    name:           str
    task:           str                     # "binary" | "multiclass"
    classes:        List[Any]
    y_true:         np.ndarray
    y_pred:         np.ndarray
    proba:          Optional[np.ndarray]    # (n_test, n_classes), columns follow `classes`
    metrics:        Dict[str, float]
    train_score:    float                   # headline metric on the training rows
    fit_time_s:     float
    predict_time_s: float
    n_train:        int
    n_test:         int
    n_features:     int                     # raw input columns
    estimator:      Any = field(repr=False)
    attack_type:    Optional[np.ndarray] = field(default=None, repr=False)
    # Out-of-fold P(anomaly) on the training rows — honest threshold tuning.
    oof_true:       Optional[np.ndarray] = field(default=None, repr=False)
    oof_score:      Optional[np.ndarray] = field(default=None, repr=False)

    # ── Derived views ──────────────────────────────────────────────────────────
    @property
    def headline(self) -> str:
        return HEADLINE[self.task]

    @property
    def score(self) -> Optional[np.ndarray]:
        """Binary only: P(anomaly) per test row."""
        if self.task != "binary" or self.proba is None:
            return None
        return self.proba[:, self.classes.index(1)]

    @property
    def display_labels(self) -> List[str]:
        return ["normal", "anomaly"] if self.task == "binary" else [str(c) for c in self.classes]

    def _summary_dict(self) -> Dict[str, Any]:
        return {
            **self.metrics,
            f"train_{self.headline}": self.train_score,
            "overfit_gap":            self.train_score - self.metrics[self.headline],
            "fit_time_s":             self.fit_time_s,
            "predict_time_s":         self.predict_time_s,
            "n_train":                self.n_train,
            "n_test":                 self.n_test,
            "n_features":             self.n_features,
        }

    def summary(self) -> pd.Series:
        """One row of the comparison table."""
        return pd.Series(self._summary_dict(), name=self.name)

    def classification_report(self, digits: int = 4) -> str:
        return classification_report(self.y_true, self.y_pred, labels=self.classes,
                                     target_names=self.display_labels,
                                     digits=digits, zero_division=0)

    def confusion_matrix(self, normalize: Optional[str] = None) -> pd.DataFrame:
        """normalize: None (counts) | "true" (row = recall) | "pred" | "all"."""
        cm = confusion_matrix(self.y_true, self.y_pred, labels=self.classes, normalize=normalize)
        return pd.DataFrame(cm,
                            index=pd.Index(self.display_labels, name="true"),
                            columns=pd.Index(self.display_labels, name="predicted"))

    def per_attack_type(self) -> pd.DataFrame:
        """Detection rate per attack type (and naming rate for multiclass)."""
        if self.task == "binary":
            if self.attack_type is None:
                raise ValueError("per_attack_type() needs attack_type on the Split")
            return attack_type_table(self.attack_type, self.y_pred == 1)
        return attack_type_table(self.y_true, self.y_pred != NORMAL_LABEL,
                                 named=self.y_pred == self.y_true)

    def operating_points(self, min_precision: float = 0.90) -> pd.DataFrame:
        """Binary only. Uses out-of-fold train scores for threshold choice when
        evaluate(..., oof_cv=k) was run; otherwise flags the choice as optimistic."""
        if self.score is None:
            raise ValueError("operating_points() needs a binary model with predict_proba")
        return operating_points(self.y_true, self.score, min_precision,
                                tune_true=self.oof_true, tune_score=self.oof_score)

    def print(self) -> None:
        """Human-readable console report."""
        sep = "-" * 60
        print(f"\n{sep}\n  {self.name}   [{self.task}]\n{sep}")
        for k, v in self._summary_dict().items():
            print(f"  {k:<22} {v:.4f}" if isinstance(v, float) else f"  {k:<22} {v}")
        print(f"\n{self.classification_report()}")
        print(self.confusion_matrix().to_string())
        print(sep)


# ══════════════════════════════════════════════════════════════════════════════
# Core evaluation
# ══════════════════════════════════════════════════════════════════════════════

def evaluate(
    estimator,
    split:  Split,
    name:   Optional[str] = None,
    fit:    bool = True,
    oof_cv: Optional[Union[int, Any]] = None,
    seed:   int = 42,
) -> EvalReport:
    """
    Fit `estimator` on split's train rows (unless fit=False), score it on test.

    oof_cv : binary only — also compute out-of-fold P(anomaly) on the training
             rows with this many folds (or a CV splitter), so operating_points()
             can pick thresholds without looking at the test set. Costs k extra
             fits (nested if the estimator is itself a GridSearchCV).
    """
    if name is None:
        final = estimator.steps[-1][1] if isinstance(estimator, Pipeline) else estimator
        name  = type(final).__name__

    fit_time = 0.0
    if fit:
        t0 = time.perf_counter()
        estimator.fit(split.X_train, split.y_train)
        fit_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    y_pred = np.asarray(estimator.predict(split.X_test))
    proba  = estimator.predict_proba(split.X_test) if hasattr(estimator, "predict_proba") else None
    predict_time = time.perf_counter() - t0

    classes = list(estimator.classes_)
    y_true  = np.asarray(split.y_test)
    y_train_pred = estimator.predict(split.X_train)

    oof_true = oof_score = None
    if split.task == "binary":
        score   = proba[:, classes.index(1)] if proba is not None else None
        metrics = binary_metrics(y_true, y_pred, score)
        train   = f1_score(split.y_train, y_train_pred, zero_division=0)
        if oof_cv and proba is not None:
            oof_true  = np.asarray(split.y_train)
            oof_score = cross_val_predict(clone(estimator), split.X_train, split.y_train,
                                          cv=_cv(oof_cv, seed), method="predict_proba")[:, classes.index(1)]
    else:
        metrics = multiclass_metrics(y_true, y_pred, proba, classes)
        train   = f1_score(split.y_train, y_train_pred, average="macro", zero_division=0)

    return EvalReport(
        name           = name,
        task           = split.task,
        classes        = classes,
        y_true         = y_true,
        y_pred         = y_pred,
        proba          = proba,
        metrics        = metrics,
        train_score    = float(train),
        fit_time_s     = fit_time,
        predict_time_s = predict_time,
        n_train        = len(split.y_train),
        n_test         = len(split.y_test),
        n_features     = split.X_train.shape[1],
        estimator      = estimator,
        attack_type    = None if split.attack_type_test is None else np.asarray(split.attack_type_test),
        oof_true       = oof_true,
        oof_score      = oof_score,
    )


def compare(reports: Iterable[EvalReport], sort: bool = True) -> pd.DataFrame:
    """One row per model, ranked by the task's headline metric (rank starts at 1)."""
    reports = list(reports)
    if not reports:
        return pd.DataFrame()
    df = pd.DataFrame([r.summary() for r in reports])
    df.index.name = "model"
    headline = reports[0].headline
    if sort:
        df = df.sort_values(headline, ascending=False)
    return df


def benchmark(
    data:      Dataset,
    models:    Mapping[str, Union[ModelFactory, Tuple[str, ModelFactory]]],
    test_size: float = 0.20,
    seed:      int = 42,
    oof_cv:    Optional[int] = None,
    verbose:   bool = False,
) -> Tuple[Split, Dict[str, EvalReport]]:
    """
    Evaluate every model on the SAME split of `data`.

    models : {key: factory} or {key: (display name, factory)} — the shape
             default_models() returns.
    """
    split = data.split(test_size, seed)
    reports: Dict[str, EvalReport] = {}
    for key, spec in models.items():
        label, factory = spec if isinstance(spec, tuple) else (key, spec)
        if verbose:
            print(f"  Training {label} …")
        reports[key] = evaluate(factory(split), split, name=label, oof_cv=oof_cv, seed=seed)
    return split, reports


# ══════════════════════════════════════════════════════════════════════════════
# Robustness
# ══════════════════════════════════════════════════════════════════════════════

def cross_validate(
    factory: ModelFactory,
    data:    Dataset,
    cv:      Union[int, Any] = 5,
    seed:    int = 42,
    n_jobs:  Optional[int] = None,
) -> pd.DataFrame:
    """
    Stratified k-fold on all of `data`: mean ± std per metric.

    A single 20% hold-out has only a couple of hundred attacks, so a one-point
    difference between models can be noise. Use this to see the spread.
    """
    res = _sk_cross_validate(factory(data), data.X, data.y, cv=_cv(cv, seed),
                             scoring=_CV_SCORING[data.task], n_jobs=n_jobs)
    rows = {k[len("test_"):]: v for k, v in res.items() if k.startswith("test_")}
    return pd.DataFrame({"mean": {k: v.mean() for k, v in rows.items()},
                         "std":  {k: v.std()  for k, v in rows.items()}})


def leakage_check(
    factory:    ModelFactory,
    data:       Dataset,
    test_size:  float = 0.20,
    seed:       int = 42,
    extra_drop: Iterable[str] = (),
) -> pd.DataFrame:
    """
    Train the same model with all features and with the structural-leak
    features removed, on the identical test rows.

    A large drop means the full-feature score is carried by session-length
    artefacts rather than attack signatures. The dropped columns are in
    `result.attrs["dropped"]`.
    """
    cols = structural_leak_columns(data.X.columns) + [c for c in extra_drop if c in data.X.columns]
    rows = {}
    for label, d in [("all features", data), ("structure-free", data.without(cols))]:
        split = d.split(test_size, seed)
        rows[label] = evaluate(factory(split), split, name=label, seed=seed).summary()

    df = pd.DataFrame(rows).T
    keep = [c for c in df.columns if c not in ("n_train", "n_test", "predict_time_s")]
    df = df[keep].astype(float)
    df.loc["change"] = df.loc["structure-free"] - df.loc["all features"]
    df.attrs["dropped"] = cols
    return df


# ══════════════════════════════════════════════════════════════════════════════
# Interpretation
# ══════════════════════════════════════════════════════════════════════════════

def _strip(name: str) -> str:
    return name.replace("num__", "").replace("cat__", "")


def feature_importance(
    report:    EvalReport,
    split:     Optional[Split] = None,
    method:    str = "model",
    n_repeats: int = 10,
    seed:      int = 42,
) -> pd.DataFrame:
    """
    Feature importance, highest first, as columns [importance, std].

    method="model"       : feature_importances_ (trees) or mean |coef_| (linear),
                           on the ENCODED features. Fast, but impurity importance
                           is computed on training data and favours
                           high-cardinality features.
    method="permutation" : drop in the headline metric when a RAW column is
                           shuffled on the test set (needs `split`). Slower,
                           honest, and one-hot children move together.
    """
    est = getattr(report.estimator, "best_estimator_", report.estimator)

    if method == "permutation":
        if split is None:
            raise ValueError("method='permutation' needs the Split the report was scored on")
        scoring = "f1" if report.task == "binary" else "f1_macro"
        res = permutation_importance(est, split.X_test, split.y_test, scoring=scoring,
                                     n_repeats=n_repeats, random_state=seed, n_jobs=-1)
        out = pd.DataFrame({"importance": res.importances_mean, "std": res.importances_std},
                           index=split.X_test.columns)
        return out.sort_values("importance", ascending=False)

    if method != "model":
        raise ValueError("method must be 'model' or 'permutation'")
    if isinstance(est, Pipeline):
        final = est.steps[-1][1]
        names = list(est[:-1].get_feature_names_out())
    else:
        final = est
        names = list(getattr(est, "feature_names_in_", range(est.n_features_in_)))

    if hasattr(final, "feature_importances_"):
        values = final.feature_importances_
    elif hasattr(final, "coef_"):
        coef = np.abs(np.atleast_2d(final.coef_))
        values = coef.mean(axis=0)
    else:
        raise ValueError(f"{type(final).__name__} exposes no feature_importances_ or coef_; "
                         "use method='permutation'")

    out = pd.DataFrame({"importance": values, "std": np.nan}, index=[_strip(str(n)) for n in names])
    return out.sort_values("importance", ascending=False)
