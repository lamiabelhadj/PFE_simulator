"""
ml/evaluation/data.py
──────────────────────
Load the per-session feature table and turn it into a model-ready (X, y).

This is the "Data Loading → Data Cleaning → Train/Test Split" part that the
three model notebooks used to copy verbatim. Keeping it in one place means the
three models are guaranteed to see the same rows, the same columns and the same
split, so their scores are directly comparable.

Usage
─────
    from ml.evaluation.data import load_features, prepare

    df    = load_features()                       # finds *_features.csv
    data  = prepare(df, target="is_anomaly")      # Dataset: X, y, column roles
    split = data.split(test_size=0.20, seed=42)   # stratified hold-out
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Union

import numpy as np
import pandas as pd
from pandas.api.types import is_numeric_dtype
from sklearn.model_selection import train_test_split


TARGETS = ("is_anomaly", "attack_type")
NORMAL_LABEL = "normal"

# ── Columns that are never predictive features ────────────────────────────────

# Identifiers and high-cardinality strings (one value per session / device).
ID_COLS: List[str] = [
    "scenario_id", "session_id", "device_id", "gateway_id",
    "claimed_device_id", "source_ip", "requested_topic",
    "payload_hash", "message_id",
]

# Every label column and its aliases. Whichever one is the target, the rest are
# dropped from X — any of them would hand the model the answer.
LABEL_COLS: List[str] = [
    "is_anomaly", "attack_type", "attack_phase", "severity",
    "attacker_class", "anomaly_type", "anomaly_phase",
]

# Structural features that separate the classes because injected attacks cut
# the session short, not because they carry an attack signature. Dropping them
# gives the "structure-free" robustness score (see leakage_check()).
STRUCTURAL_LEAK: List[str] = [
    "n_events", "session_duration_s", "mean_delay_s", "max_delay_s", "min_delay_s",
    "visited_states", "reached_session_open", "reached_access_granted",
    "reached_authenticated", "n_state_jumps", "connection_duration",
]
# Event counters (n_*) are structural too, except these genuine attack signals.
SIGNAL_COUNTS: Sequence[str] = (
    "n_failures", "n_retries", "n_nonce_reuses", "n_token_reuses", "n_renewal_request",
)

# ── Feature-table discovery ───────────────────────────────────────────────────

# Canonical ML extract first; older export names stay as fallbacks.
FEATURE_FILENAMES: Sequence[str] = (
    "iot_auth_ml_experiments_features.csv",
    "iot_auth_ml_features.csv",
    "iot_auth_dataset_features.csv",
)
_SEARCH_SUBDIRS = ("simulator/data/output", "IoT_auth_simulator/simulator/data/output")


def structural_leak_columns(columns: Iterable[str]) -> List[str]:
    """Return the structural-leak features present in `columns`."""
    columns = list(columns)
    counters = [c for c in columns if c.startswith("n_") and c not in SIGNAL_COUNTS]
    return [c for c in dict.fromkeys(STRUCTURAL_LEAK + counters) if c in columns]


def find_features_csv(start: Optional[Union[str, Path]] = None) -> Path:
    """Walk up from `start` (default: cwd) looking for a *_features.csv export."""
    here = Path(start) if start else Path.cwd()
    for base in [here, *here.parents]:
        for sub in _SEARCH_SUBDIRS:
            for name in FEATURE_FILENAMES:
                p = base / sub / name
                if p.exists():
                    return p
    raise FileNotFoundError("Could not locate a *_features.csv under simulator/data/output/")


def load_features(path: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """Read the feature CSV at `path`, or the first one find_features_csv() finds."""
    path = Path(path) if path else find_features_csv()
    df = pd.read_csv(path)
    df.attrs["source"] = str(path)
    return df


# ══════════════════════════════════════════════════════════════════════════════
# Containers
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Split:
    """A stratified train/test hold-out of a Dataset."""
    X_train:  pd.DataFrame
    X_test:   pd.DataFrame
    y_train:  pd.Series
    y_test:   pd.Series
    num_cols: List[str]
    cat_cols: List[str]
    target:   str
    # attack_type of every test row — lets a binary model be scored per attack.
    attack_type_test: Optional[pd.Series] = None

    @property
    def task(self) -> str:
        return "binary" if self.target == "is_anomaly" else "multiclass"


@dataclass
class Dataset:
    """Cleaned features plus the column bookkeeping every model needs."""
    X:           pd.DataFrame
    y:           pd.Series
    target:      str
    num_cols:    List[str]
    cat_cols:    List[str]
    dropped:     List[str]
    attack_type: Optional[pd.Series] = None

    @property
    def task(self) -> str:
        return "binary" if self.target == "is_anomaly" else "multiclass"

    def without(self, columns: Iterable[str]) -> "Dataset":
        """Return a copy with `columns` removed from X (e.g. structural leakers)."""
        cols = [c for c in columns if c in self.X.columns]
        return replace(
            self,
            X        = self.X.drop(columns=cols),
            num_cols = [c for c in self.num_cols if c not in cols],
            cat_cols = [c for c in self.cat_cols if c not in cols],
            dropped  = self.dropped + cols,
        )

    def split(self, test_size: float = 0.20, seed: int = 42) -> Split:
        """Stratified hold-out. The same seed always yields the same test rows,
        so datasets that differ only in columns share an identical split."""
        X_train, X_test, y_train, y_test = train_test_split(
            self.X, self.y, test_size=test_size, stratify=self.y, random_state=seed,
        )
        at = self.attack_type.loc[X_test.index] if self.attack_type is not None else None
        return Split(X_train, X_test, y_train, y_test,
                     list(self.num_cols), list(self.cat_cols), self.target, at)


# ══════════════════════════════════════════════════════════════════════════════
# Cleaning
# ══════════════════════════════════════════════════════════════════════════════

def prepare(
    df:             pd.DataFrame,
    target:         str = "is_anomaly",
    drop:           Iterable[str] = (),
    drop_constant:  bool = True,
    structure_free: bool = False,
) -> Dataset:
    """
    Clean the feature table into (X, y).

    Parameters
    ----------
    df             : per-session feature DataFrame
    target         : "is_anomaly" (binary) or "attack_type" (multiclass)
    drop           : extra columns to exclude from X
    drop_constant  : drop columns with a single value across the whole table
    structure_free : also drop the structural-leak features (honest lower bound)

    Categorical columns get NaN → "missing", numeric columns NaN → 0, matching
    the notebooks. Scaling / encoding is left to the model's own preprocessor.
    """
    if target not in TARGETS:
        raise ValueError(f"target must be one of {TARGETS}")
    if target not in df.columns:
        raise KeyError(f"target column '{target}' not in DataFrame")

    const = [c for c in df.columns if df[c].nunique(dropna=False) <= 1] if drop_constant else []
    dropped = [c for c in dict.fromkeys(ID_COLS + LABEL_COLS + const + list(drop)) if c in df.columns]

    X = df.drop(columns=dropped)
    y = df[target].astype(int) if target == "is_anomaly" else df[target].astype(str)
    attack_type = df["attack_type"].astype(str) if "attack_type" in df.columns else None

    # is_numeric_dtype treats bools as numeric and behaves the same on pandas 2
    # (object strings) and pandas 3 (str dtype), unlike select_dtypes("object").
    num_cols = [c for c in X.columns if is_numeric_dtype(X[c])]
    cat_cols = [c for c in X.columns if c not in num_cols]
    X = X.copy()
    X[cat_cols] = X[cat_cols].fillna("missing").astype(str)
    X[num_cols] = X[num_cols].fillna(0)

    data = Dataset(X, y, target, num_cols, cat_cols, dropped, attack_type)
    if structure_free:
        data = data.without(structural_leak_columns(X.columns))
    return data


def class_balance(y: Union[pd.Series, np.ndarray]) -> pd.Series:
    """Value counts of a label array, sorted by label."""
    return pd.Series(y).value_counts().sort_index()
