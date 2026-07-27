"""
ml/preprocessing.py
────────────────────
Feature preprocessing for the IoT authentication dataset.

Responsibilities
────────────────
  1. Drop identifier and alias columns (no predictive value)
  2. Drop high-cardinality string columns that have numeric proxies
  3. Encode low-cardinality categoricals with OrdinalEncoder
  4. Scale all numeric columns with StandardScaler
  5. Stratified train / test split

Two target modes
────────────────
  binary     : target = is_anomaly  (0 / 1)
  multiclass : target = attack_type (normal / replay_token / impersonation / …)

Usage
─────
    from ml.preprocessing import Preprocessor

    pre = Preprocessor(target="is_anomaly")
    X_train, X_test, y_train, y_test = pre.fit_transform(df)
    feature_names = pre.feature_names_
"""

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OrdinalEncoder, StandardScaler
from typing import List, Optional, Tuple


# ── Columns that are never predictive features ────────────────────────────────

# Pure identifiers / sequence metadata
_DROP_ALWAYS: List[str] = [
    "scenario_id", "session_id", "device_id", "gateway_id",
    "message_id", "payload_hash",
    "anomaly_type", "anomaly_phase",   # aliases of attack_type / attack_phase
]

# High-cardinality strings whose information is captured by numeric proxies:
#   claimed_device_id  → identity_claim_mismatch
#   source_ip          → source_ip_change
#   requested_topic    → topic_length
_DROP_HIGH_CARDINALITY: List[str] = [
    "claimed_device_id", "source_ip", "requested_topic",
]

# Columns that would leak the label when target = is_anomaly
_LEAK_BINARY: List[str] = ["attack_type", "attack_phase", "severity"]

# Columns that would leak the label when target = attack_type
_LEAK_MULTICLASS: List[str] = ["is_anomaly", "attack_phase", "severity"]

# Features that were empirically found to separate normal vs anomaly at
# ROC-AUC >= ~0.75 in the *pre-fix* dataset (see feature_analysis_outputs/
# leakage_features_to_drop.csv). These are structural / timing / rate aggregates
# that leaked because the generator keyed them on the ground-truth label.
#
# Set drop_leakage=True to exclude them and report an HONEST lower-bound score
# that reflects only the genuine attack signatures. Use this to (a) show a
# defensible number before regenerating, and (b) as a regression check after the
# generator fixes — once the generator no longer keys these on the label they
# stop leaking and can safely be kept, so this list is expected to shrink.
_KNOWN_LEAKAGE_FEATURES: List[str] = [
    "pairing_result", "packet_rate", "inter_arrival_time", "visited_states",
    "session_present", "n_events", "s5_latency_ms", "authorization_result",
    "message_rate", "byte_rate", "keep_alive", "n_session_closed",
    "n_access_granted", "reached_access_granted", "n_token_reuses",
    "s4_latency_ms", "session_duration_s", "connection_duration",
    "max_delay_s", "mean_delay_s", "failure_rate", "pairing_latency_ms",
    "s2_latency_ms", "reached_session_open", "auth_latency_ms", "s3_latency_ms",
    "n_token_validated", "n_access_request", "n_token_issued", "n_token_presented",
    # additional strong timing leakers from the diagnostics not in the drop CSV
    "s1_latency_ms", "s6_latency_ms", "min_delay_s", "payload_length",
    "reached_authenticated", "n_authentication_success",
]

# Low-cardinality categoricals to OrdinalEncode
_CATEGORICAL: List[str] = [
    "tcp_flags", "connack_code", "gateway_decision",
    "mqtt_msg_type", "operation",
]


class Preprocessor:
    """
    Fit-transform pipeline for the IoT auth feature DataFrame.

    Parameters
    ----------
    target      : column name to use as the label ("is_anomaly" or "attack_type")
    test_size   : fraction of data held out for testing
    random_state: reproducibility seed
    drop_leakage: if True, also drop the empirically-leaking features listed in
                  _KNOWN_LEAKAGE_FEATURES, yielding an honest lower-bound score
                  that reflects only the genuine attack signatures
    """

    def __init__(
        self,
        target:        str   = "is_anomaly",
        test_size:     float = 0.20,
        random_state:  int   = 42,
        drop_leakage:  bool  = False,
    ):
        if target not in ("is_anomaly", "attack_type"):
            raise ValueError("target must be 'is_anomaly' or 'attack_type'")
        self.target       = target
        self.test_size    = test_size
        self.random_state = random_state
        self.drop_leakage = drop_leakage

        self._encoder = OrdinalEncoder(
            handle_unknown="use_encoded_value",
            unknown_value=-1,
            dtype=np.float64,
        )
        self._scaler       = StandardScaler()
        self.feature_names_: List[str] = []
        self._cat_cols:      List[str] = []
        self._num_cols:      List[str] = []
        self._fitted        = False

    # ══════════════════════════════════════════════════════════════════════════
    # Public API
    # ══════════════════════════════════════════════════════════════════════════

    def fit_transform(
        self,
        df: pd.DataFrame,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Fit preprocessing on df and return train/test splits.

        Returns
        -------
        X_train, X_test, y_train, y_test
        """
        X, y = self._prepare(df, fit=True)
        return train_test_split(
            X, y,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=y,
        )

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Apply fitted preprocessing to new data (no label extraction)."""
        if not self._fitted:
            raise RuntimeError("Call fit_transform() before transform().")
        X, _ = self._prepare(df, fit=False)
        return X

    # ══════════════════════════════════════════════════════════════════════════
    # Internal helpers
    # ══════════════════════════════════════════════════════════════════════════

    def _prepare(
        self,
        df:  pd.DataFrame,
        fit: bool,
    ) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        df = df.copy()

        # ── Extract label ────────────────────────────────────────────────────
        y = None
        if self.target in df.columns:
            y = np.asarray(df[self.target])

        # ── Drop columns ──────────────────────────────────────────────────────
        leak_cols = _LEAK_BINARY if self.target == "is_anomaly" else _LEAK_MULTICLASS
        drop      = set(_DROP_ALWAYS + _DROP_HIGH_CARDINALITY + leak_cols + [self.target])
        if self.drop_leakage:
            drop |= set(_KNOWN_LEAKAGE_FEATURES)
        df.drop(columns=[c for c in drop if c in df.columns], inplace=True)

        # ── Identify categorical and numeric columns ───────────────────────────
        if fit:
            self._cat_cols = [c for c in _CATEGORICAL if c in df.columns]
            self._num_cols = [c for c in df.columns if c not in self._cat_cols]
            self.feature_names_ = self._cat_cols + self._num_cols

        # ── Encode categoricals ───────────────────────────────────────────────
        if self._cat_cols:
            cat_df = df[self._cat_cols].astype(str).fillna("missing")
            if fit:
                cat_arr = self._encoder.fit_transform(cat_df)
            else:
                cat_arr = self._encoder.transform(cat_df)
        else:
            cat_arr = np.empty((len(df), 0))

        # ── Fill numeric NaNs and scale ────────────────────────────────────────
        num_df = df[self._num_cols].fillna(0).astype(np.float64)
        if fit:
            num_arr = self._scaler.fit_transform(num_df)
            self._fitted = True
        else:
            num_arr = self._scaler.transform(num_df)

        X = np.hstack([cat_arr, num_arr]) if cat_arr.shape[1] > 0 else num_arr
        return X, y

    # ══════════════════════════════════════════════════════════════════════════
    # Utility
    # ══════════════════════════════════════════════════════════════════════════

    def class_distribution(self, y: np.ndarray) -> pd.Series:
        """Return value counts for a label array."""
        labels, counts = np.unique(y, return_counts=True)
        return pd.Series(counts, index=labels).sort_index()
