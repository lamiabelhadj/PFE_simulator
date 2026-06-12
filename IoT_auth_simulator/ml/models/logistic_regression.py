"""
ml/models/logistic_regression.py
──────────────────────────────────
Thin sklearn wrapper — Logistic Regression.
"""

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from typing import List, Optional


class LogisticRegressionModel:

    name = "Logistic Regression"

    def __init__(
        self,
        max_iter:     int   = 1000,
        C:            float = 1.0,
        random_state: int   = 42,
        **kwargs,
    ):
        self.model = LogisticRegression(
            max_iter=max_iter,
            C=C,
            random_state=random_state,
            **kwargs,
        )

    def fit(self, X: np.ndarray, y: np.ndarray) -> "LogisticRegressionModel":
        self.model.fit(X, y)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
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
