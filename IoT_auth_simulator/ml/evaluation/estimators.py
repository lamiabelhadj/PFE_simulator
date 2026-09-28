"""
ml/evaluation/estimators.py
────────────────────────────
Shared preprocessor and the reference model set.

A *model factory* is any callable `factory(data) -> estimator` where `data` is a
Dataset or Split (anything with .num_cols / .cat_cols). Factories — rather than
ready-built estimators — are what let leakage_check() rebuild the same model on
a reduced column set, and let a benchmark swap in a tuned GridSearchCV.

Usage
─────
    from ml.evaluation.estimators import make_preprocessor, default_models

    def my_rf(d):
        return Pipeline([("pre", make_preprocessor(d)),
                         ("rf",  RandomForestClassifier(n_estimators=500))])
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Tuple

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier

ModelFactory = Callable[[Any], Any]


def make_preprocessor(data, scale: bool = False) -> ColumnTransformer:
    """
    Numeric passthrough (or StandardScaler when `scale`) + one-hot categoricals.

    Trees need no scaling; linear / distance-based models should use scale=True.
    """
    return ColumnTransformer([
        ("num", StandardScaler() if scale else "passthrough", list(data.num_cols)),
        ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), list(data.cat_cols)),
    ])


def default_models(seed: int = 42) -> Dict[str, Tuple[str, ModelFactory]]:
    """
    Untuned reference versions of the three notebook models.

    Returns {key: (display name, factory)}. These are baselines for a quick,
    consistent comparison — the notebooks' grid-searched versions will score
    differently. Pass your own factories to benchmark() for tuned models.
    """
    def logistic_regression(d):
        return Pipeline([
            ("pre", make_preprocessor(d, scale=True)),
            ("lr",  LogisticRegression(max_iter=3000, class_weight="balanced", random_state=seed)),
        ])

    def decision_tree(d):
        return Pipeline([
            ("pre", make_preprocessor(d)),
            ("dt",  DecisionTreeClassifier(min_samples_leaf=5, random_state=seed)),
        ])

    def random_forest(d):
        return Pipeline([
            ("pre", make_preprocessor(d)),
            ("rf",  RandomForestClassifier(n_estimators=300, random_state=seed, n_jobs=-1)),
        ])

    return {
        "lr": ("Logistic Regression", logistic_regression),
        "dt": ("Decision Tree",       decision_tree),
        "rf": ("Random Forest",       random_forest),
    }
