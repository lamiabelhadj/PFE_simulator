"""
ml/models/random_forest.py
───────────────────────────
Thin sklearn wrapper — Random Forest.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from typing import List


class RandomForestModel:

    name = "Random Forest"

    def __init__(
        self,
        n_estimators: int = 100,
        max_depth:    int = None,
        random_state: int = 42,
        n_jobs:       int = -1,
        **kwargs,
    ):
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=n_jobs,
            **kwargs,
        )

    def fit(self, X: np.ndarray, y: np.ndarray) -> "RandomForestModel":
        self.model.fit(X, y)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    def classes_(self) -> np.ndarray:
        return self.model.classes_

    def feature_importances(self, feature_names: List[str]) -> pd.Series:
        return (
            pd.Series(self.model.feature_importances_, index=feature_names)
            .sort_values(ascending=False)
        )
