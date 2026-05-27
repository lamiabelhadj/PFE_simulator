"""
data/exporter.py
─────────────────
Converts the list of session event dicts to a pandas DataFrame
and saves it as CSV (and optionally Parquet).
"""

from pathlib import Path
from typing import List, Dict, Any

import pandas as pd

from config.settings import DATA_DIR


def to_dataframe(events: List[Dict[str, Any]]) -> pd.DataFrame:
    """Convert a list of session event dicts to a DataFrame."""
    df = pd.DataFrame(events)

    # Cast label columns to correct dtypes
    if "is_anomaly" in df.columns:
        df["is_anomaly"] = df["is_anomaly"].astype(int)
    for col in ["message_rate", "byte_rate", "session_duration",
                "trust_score", "behavior_deviation_score", "packet_rate"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


def save(
    events:   List[Dict[str, Any]],
    filename: str  = "iot_auth_dataset.csv",
    parquet:  bool = False,
) -> Path:
    """
    Save events to CSV (and optionally Parquet) in the data/output directory.

    Returns the path to the saved CSV file.
    """
    df      = to_dataframe(events)
    csv_path = DATA_DIR / filename
    df.to_csv(csv_path, index=False)

    if parquet:
        pq_path = csv_path.with_suffix(".parquet")
        df.to_parquet(pq_path, index=False)
        print(f"Parquet saved → {pq_path}")

    print(f"CSV saved     → {csv_path}  ({len(df):,} rows × {len(df.columns)} cols)")
    return csv_path