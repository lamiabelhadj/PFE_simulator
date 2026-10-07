"""Central configuration: paths, seed and the fixed vocabularies of the dataset.

Every stage reads its paths from a `Paths` object so the whole pipeline can be
re-run into a different output directory (this is what the reproducibility
check does).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

SEED = 20261005

PIPELINE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = PIPELINE_DIR.parent / "scientific-candidate.json"
DEFAULT_OUTPUT = PIPELINE_DIR / "outputs"

# Fixed order used in every table and figure so colors/rows never move.
ROLE_ORDER = [
    "ordinary_normal",
    "hard_negative:small_positive_causal_margin",
    "hard_negative:fresh_nonce_cross_attempt",
    "hard_negative:legitimate_same_attempt_nonce_recurrence",
    "anomaly:timestamp_inconsistency",
    "anomaly:nonce_reuse",
]
ROLE_SHORT = {
    "ordinary_normal": "ordinary normal",
    "hard_negative:small_positive_causal_margin": "HN small +margin",
    "hard_negative:fresh_nonce_cross_attempt": "HN fresh nonce x-attempt",
    "hard_negative:legitimate_same_attempt_nonce_recurrence": "HN same-attempt nonce",
    "anomaly:timestamp_inconsistency": "ANOM timestamp",
    "anomaly:nonce_reuse": "ANOM nonce reuse",
}
KIND_ORDER = ["ordinary_normal", "hard_negative", "anomaly"]
FAMILY_ORDER = ["ordinary_normal", "direct_timing", "nonce"]

# Canonical protocol order of event types (used for heatmaps / transition matrix).
EVENT_ORDER = [
    "discovery", "gateway_advertisement", "pairing_request", "pairing_response",
    "enrollment_request", "enrollment_confirmed",
    "authentication_request", "challenge_sent", "nonce_received", "response_sent",
    "authentication_failure", "retry", "authentication_success",
    "token_issued", "token_presented", "token_validated", "session_opened",
    "access_request", "access_granted", "renewal_request", "session_closed",
]

# Smallest delay the simulator emits for "back-to-back" events.
DELAY_FLOOR = 1e-6


@dataclass(frozen=True)
class Paths:
    input_json: Path
    out: Path

    @property
    def data(self) -> Path:
        return self.out / "data"

    @property
    def tables(self) -> Path:
        return self.out / "tables"

    @property
    def figures(self) -> Path:
        return self.out / "figures"

    def make(self) -> None:
        for p in (self.data, self.tables, self.figures):
            p.mkdir(parents=True, exist_ok=True)
