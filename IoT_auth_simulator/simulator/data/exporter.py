"""
simulator/data/exporter.py
───────────────────────────
Thin save wrapper used by main.py and ui_app.py.
Delegates to OutputViews for the three output formats and returns the
path to the primary feature CSV.
"""

from pathlib import Path
from typing import List, Tuple

from simulator.config.settings import DATA_DIR
from simulator.data.output_views import OutputViews, to_feature_df
from simulator.engines.event_engine import SessionContext
from simulator.event_model import AuthEvent


def save(
    sequences: List[Tuple[List[AuthEvent], SessionContext]],
    filename:  str  = "iot_auth_dataset.csv",
    parquet:   bool = False,
) -> Path:
    """
    Save the simulation output to DATA_DIR.

    Always writes:
      <stem>_events.json     — full per-event JSON log
      <stem>_event_log.csv   — one row per AuthEvent
      <stem>_features.csv    — one row per session (feature table for ML)

    If parquet=True, also writes <stem>_features.parquet.

    Returns the path to the feature CSV.
    """
    stem  = Path(filename).stem
    views = OutputViews(output_dir=str(DATA_DIR))
    paths = views.save(sequences, stem=stem)

    if parquet:
        df = to_feature_df(sequences)
        p  = DATA_DIR / f"{stem}_features.parquet"
        df.to_parquet(p, index=False)
        print(f"  Parquet     -> {p}")

    return paths.get("feature_csv", DATA_DIR / filename)
