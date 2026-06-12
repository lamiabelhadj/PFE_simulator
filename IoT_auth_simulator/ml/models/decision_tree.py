"""
ml/models/decision_tree.py
───────────────────────────
Thin sklearn wrapper — Decision Tree.
"""

import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from typing import List


class DecisionTreeModel:

    name = "Decision Tree"

    def __init__(
        self,
        max_depth:    int = 10,
        random_state: int = 42,
        **kwargs,
    ):
        self.model = DecisionTreeClassifier(
            max_depth=max_depth,
            random_state=random_state,
            **kwargs,
        )

    def fit(self, X: np.ndarray, y: np.ndarray) -> "DecisionTreeModel":
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
