"""
simulator/data/exporter.py
───────────────────────────
Thin synchronized save wrapper used by main.py and ui_app.py.

Historical builders remain available from ``output_views`` for analysis, but
the default generation path writes separated C1.6 information surfaces.
"""

from pathlib import Path
from typing import List, Tuple

from simulator.config.settings import DATA_DIR
from simulator.data.synchronized_views import SynchronizedOutputViews
from simulator.engines.event_engine import SessionContext
from simulator.event_model import AuthEvent


def save(
    sequences: List[Tuple[List[AuthEvent], SessionContext]],
    filename:  str  = "iot_auth_dataset.csv",
    parquet:   bool = False,
) -> Path:
    """
    Save the simulation output to DATA_DIR.

    Writes detector observations, event/trace GT, provenance, debug, and
    machine-readable field/dataset manifests as separate artifacts.

    If parquet=True, also writes detector observations as Parquet.

    Returns the path to the detector-observation CSV.
    """
    stem  = Path(filename).stem
    views = SynchronizedOutputViews(output_dir=str(DATA_DIR))
    paths = views.save(sequences, stem=stem)

    if parquet:
        from simulator.data.synchronized_views import to_detector_observation_df

        df = to_detector_observation_df(sequences)
        p  = DATA_DIR / f"{stem}_observations.parquet"
        df.to_parquet(p, index=False)
        print(f"  Parquet     -> {p}")

    return paths.get("detector_observations", DATA_DIR / filename)
