"""Stage 1 — turn the nested JSON candidate into flat, tidy CSV tables.

The JSON holds 336 *samples* (authentication sessions). Each sample has
  * `detector_observations`: the ordered event log a detector would see, and
  * `privileged_metadata`: generator-side ground truth (labels, device profile,
    how the sample was constructed). A detector must NOT see this.

We produce two tidy tables that keep that separation explicit:
  * events.csv   — one row per observed event (long format, 5 145 rows)
  * samples.csv  — one row per sample with all privileged metadata flattened
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .config import Paths

EVENT_FIELDS = [
    "event_type", "result", "failure_reason", "retry_count",
    "observed_timestamp", "observed_delay_since_previous_event",
    "nonce", "token_id", "resource_id", "requested_action", "topic",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _flatten(obj, prefix: str = "") -> dict:
    """Flatten nested dicts with '.'; scalar lists become '|'-joined strings."""
    out = {}
    for key, value in obj.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            if value:
                out.update(_flatten(value, name + "."))
            else:
                out[name] = None
        elif isinstance(value, list):
            out[name] = "|".join(map(str, value))
            out[name + ".__len"] = len(value)
        else:
            out[name] = value
    return out


def build_events(raw: dict) -> pd.DataFrame:
    rows = []
    for i, sample in enumerate(raw["samples"]):
        meta = sample["privileged_metadata"]
        attempt = 0
        for j, ev in enumerate(sample["detector_observations"]):
            # Derived: an authentication *attempt* starts at each challenge_sent.
            if ev["event_type"] == "challenge_sent":
                attempt += 1
            rows.append({
                "sample_key": f"S{i:03d}",
                "event_index": j,
                **{f: ev.get(f) for f in EVENT_FIELDS},
                "attempt_index": attempt,
                # Convenience copies of the labels (privileged — never use as features).
                "label_detector_truth": meta["detector_truth"],
                "label_role": meta["role"]["key"],
            })
    df = pd.DataFrame(rows)
    df["retry_count"] = df["retry_count"].astype(int)
    return df


def build_samples(raw: dict) -> pd.DataFrame:
    rows = []
    for i, sample in enumerate(raw["samples"]):
        flat = _flatten(sample["privileged_metadata"])
        rows.append({
            "sample_key": f"S{i:03d}",
            "sample_id": sample["sample_id"],
            "n_events": len(sample["detector_observations"]),
            **flat,
        })
    df = pd.DataFrame(rows)
    id_cols = ["sample_key", "sample_id", "n_events"]
    rest = sorted(c for c in df.columns if c not in id_cols)
    df = df[id_cols + rest]
    # Short, readable aliases for the columns used throughout the analysis.
    df.insert(3, "detector_truth", df.pop("detector_truth"))
    df.insert(4, "role", df.pop("role.key"))
    df.insert(5, "role_kind", df.pop("role.kind"))
    df.insert(6, "semantic_family", df.pop("semantic_family"))
    df.insert(7, "device", df.pop("device.population_device_key"))
    return df


def write_csv(df: pd.DataFrame, path: Path) -> None:
    df.to_csv(path, index=False, lineterminator="\n")


def run(paths: Paths) -> dict:
    raw = load_json(paths.input_json)
    events = build_events(raw)
    samples = build_samples(raw)
    # Device key on events too (it is observable context: which device spoke).
    events.insert(1, "device", events["sample_key"].map(samples.set_index("sample_key")["device"]))

    write_csv(events, paths.data / "events.csv")
    write_csv(samples, paths.data / "samples.csv")

    header = {k: v for k, v in raw.items() if k != "samples"}
    return {
        "raw": raw,
        "header": header,
        "events": events,
        "samples": samples,
        "input_sha256": sha256_file(paths.input_json),
        "input_bytes": paths.input_json.stat().st_size,
    }


def reload(paths: Paths) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Read the CSVs back — downstream stages use these, proving the CSVs are self-sufficient."""
    events = pd.read_csv(paths.data / "events.csv", keep_default_na=True)
    samples = pd.read_csv(paths.data / "samples.csv", keep_default_na=True)
    events["retry_count"] = events["retry_count"].astype(np.int64)
    return events, samples
