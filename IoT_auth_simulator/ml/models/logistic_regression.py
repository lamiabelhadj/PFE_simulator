"""
ml/models/logistic_regression.py
──────────────────────────────────
Logistic Regression wrapper with honest, imbalance-aware enhancements.

Why more than a thin wrapper
────────────────────────────
The de-leaked dataset is realistic: ~9% of sessions are attacks and a fraction
of those are deliberately stealthy (indistinguishable from normal). A plain
LogisticRegression(C=1.0) at the default 0.5 threshold under-predicts the
minority class, so it reports high precision but mediocre recall. Three standard,
leakage-free techniques recover the honest headroom:

  1. class_weight="balanced"  — reweights the rare attack class so the loss
                                stops being dominated by the 91% normals.
  2. Cross-validated C        — LogisticRegressionCV picks the regularisation
                                strength by k-fold CV on the TRAINING data only.
  3. Decision-threshold tuning — the operating threshold is chosen to maximise
                                positive-class F1 using out-of-fold predictions
                                on the TRAINING data (never the test set), then
                                applied in predict().

All tuning uses training data only, so no test information leaks in.

NOTE — defaults are the plain baseline (C=1.0, no weighting, 0.5 threshold).
On the current de-leaked dataset a 5-fold CV showed the baseline is already the
best LR (F1 ~0.87, precision 1.0, recall ~0.78): recall is capped by the stealth
(evasive) attacks that no model can recover, and precision is already perfect, so
class-weighting only trades precision away for recall it cannot gain. The
enhancements are kept as opt-in — enable class_weight="balanced",
tune_threshold=True and/or C=None (CV-selected) if you regenerate with lower
STEALTH_FRACTION or more attacks per class, where they can help.
"""

import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.linear_model import LogisticRegression, LogisticRegressionCV
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import f1_score
from typing import List, Optional, Sequence


class LogisticRegressionModel:

    name = "Logistic Regression"

    def __init__(
        self,
        C:              Optional[float]      = 1.0,
        Cs:             Sequence[float]      = (0.01, 0.1, 1.0, 10.0, 100.0),
        max_iter:       int                  = 5000,
        class_weight:   Optional[str]        = None,
        cv:             int                  = 5,
        tune_threshold: bool                 = False,
        solver:         str                  = "liblinear",
        random_state:   int                  = 42,
        **kwargs,
    ):
        # If C is fixed, use a single LogisticRegression; otherwise let
        # LogisticRegressionCV choose C by cross-validation on the train set.
        self.C              = C
        self.Cs             = list(Cs)
        self.max_iter       = max_iter
        self.class_weight   = class_weight
        self.cv             = cv
        self.tune_threshold = tune_threshold
        self.solver         = solver
        self.random_state   = random_state
        self._kwargs        = kwargs

        self.model          = None                 # fitted sklearn estimator
        self.threshold_:    Optional[float] = None # tuned operating threshold
        self._binary        = False
        self._pos_idx       = 1
        self._pos_label     = 1
        self._neg_label     = 0

    # ── Fit ────────────────────────────────────────────────────────────────────
    def fit(self, X: np.ndarray, y: np.ndarray) -> "LogisticRegressionModel":
        classes      = np.unique(y)
        self._binary = len(classes) == 2

        if self.C is not None:
            est = LogisticRegression(
                C=self.C, class_weight=self.class_weight, max_iter=self.max_iter,
                solver=self.solver, random_state=self.random_state, **self._kwargs,
            )
        else:
            scoring = "f1" if self._binary else "f1_weighted"
            est = LogisticRegressionCV(
                Cs=self.Cs,
                cv=StratifiedKFold(self.cv, shuffle=True, random_state=self.random_state),
                scoring=scoring, class_weight=self.class_weight, max_iter=self.max_iter,
                solver=self.solver, random_state=self.random_state, **self._kwargs,
            )
        est.fit(X, y)
        self.model = est

        # Positive class = the anomaly label (1) for the binary target.
        if self._binary:
            self._pos_label = classes[-1]          # 1 for is_anomaly
            self._neg_label = classes[0]
            self._pos_idx   = int(np.where(est.classes_ == self._pos_label)[0][0])
            if self.tune_threshold:
                self._tune_threshold(X, y)

        return self

    def _tune_threshold(self, X: np.ndarray, y: np.ndarray) -> None:
        """Pick the threshold that maximises positive-class F1 using out-of-fold
        predictions on the TRAINING set (no test leakage). Falls back to 0.5."""
        C_sel = float(np.ravel(self.model.C_)[0]) if hasattr(self.model, "C_") else (self.C or 1.0)
        base = LogisticRegression(
            C=C_sel, class_weight=self.class_weight, max_iter=self.max_iter,
            solver=self.solver, random_state=self.random_state, **self._kwargs,
        )
        try:
            oof = cross_val_predict(
                clone(base), X, y,
                cv=StratifiedKFold(self.cv, shuffle=True, random_state=self.random_state),
                method="predict_proba",
            )[:, self._pos_idx]
        except Exception:
            self.threshold_ = 0.5
            return

        y_pos = (np.asarray(y) == self._pos_label).astype(int)
        grid  = np.linspace(0.05, 0.95, 91)
        f1s   = [f1_score(y_pos, (oof >= t).astype(int), zero_division=0) for t in grid]
        self.threshold_ = float(grid[int(np.argmax(f1s))])

    # ── Predict ────────────────────────────────────────────────────────────────
    def predict(self, X: np.ndarray) -> np.ndarray:
        if self._binary and self.threshold_ is not None:
            proba = self.model.predict_proba(X)[:, self._pos_idx]
            return np.where(proba >= self.threshold_, self._pos_label, self._neg_label)
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    def classes_(self) -> np.ndarray:
        return self.model.classes_

    def feature_importances(self, feature_names: List[str]) -> pd.Series:
        """
        Feature importance as absolute coefficient magnitude.
        For multiclass: mean of abs(coef) across all classes.
        """
        coef = np.abs(self.model.coef_)
        importance = coef.mean(axis=0) if coef.ndim > 1 else coef[0]
        return (
            pd.Series(importance, index=feature_names)
            .sort_values(ascending=False)
        )
